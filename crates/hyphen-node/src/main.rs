use clap::Parser;
use parking_lot::RwLock;
use prost::Message;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info, warn};

mod p2p;
mod peer_policy;

use p2p::{PeerSync, purge_block_transactions};

use hyphen_consensus::{
    Blockchain, ChainArchive, build_genesis_block, export_archive, replay_archive,
    verify_historical_archive,
};
use hyphen_core::config::{ChainConfig, GENESIS_TIMESTAMP_MS};
use hyphen_core::timestamp::{ntp_adjusted_timestamp_ms, start_ntp_sync_task};
use hyphen_mempool::{Mempool, MempoolConfig};
use hyphen_transport::{
    BlockTemplate, DeclareJobRequest, DeclareJobResult, POOL_PROTOCOL_VERSION, SignedEnvelope,
    SubmitBlockRequest, SubmitBlockResult, TP_DECLARE_JOB, TP_DECLARE_JOB_RESULT, TP_GET_TEMPLATE,
    TP_SUBMIT_BLOCK, TP_SUBMIT_RESULT, TP_SUBSCRIBE, TP_TEMPLATE, read_envelope, write_envelope,
};
use hyphen_wire::{DEFAULT_WIRE_BYTES, wire_config};

#[derive(Parser, Debug)]
#[command(name = "hyphen-node", about = "Hyphen blockchain full node")]
struct Cli {
    /// Defaults to hyphen_data/neural-v3 on neural-devnet and hyphen_data otherwise.
    #[arg(long)]
    data_dir: Option<String>,

    #[arg(
        long,
        value_parser = ["neural-devnet", "testnet", "mainnet"],
        default_value = "neural-devnet"
    )]
    network: String,

    #[arg(long)]
    identity_file: Option<PathBuf>,

    #[arg(long)]
    listen: Option<String>,

    #[arg(long, default_value = "")]
    boot_nodes: String,

    /// Upstream resolver for `/dns4`, `/dns6` and `/dns` boot nodes, repeatable.
    ///
    /// `recurse-x`'s spec format: `udp://1.1.1.1:53`, `tls://1.1.1.1:853#cloudflare-dns.com`,
    /// `https://dns.google/dns-query#dns.google`. Without any upstream the node
    /// resolves seed names itself, from the root servers, with DNSSEC
    /// validation. The `#name` fragment is the TLS identity of an encrypted
    /// upstream and is mandatory for `tls://` and `https://`.
    #[arg(long = "dns-upstream", value_name = "SPEC")]
    dns_upstreams: Vec<String>,

    /// Allow a mainnet seed node to start without boot peers.
    #[arg(long)]
    allow_isolated_mainnet: bool,

    /// Print the selected network's consensus and genesis identifiers, then exit.
    #[arg(long)]
    print_chain_identity: bool,

    /// Export post-genesis blocks to a chain-identity-bound replay archive.
    #[arg(long)]
    export_history: Option<PathBuf>,

    /// Replay a chain archive into a fresh data directory, then exit.
    #[arg(long)]
    replay_history: Option<PathBuf>,

    /// Verify all historical transitions in a disposable database, independent of the local clock.
    #[arg(long)]
    verify_history: Option<PathBuf>,

    #[arg(long, default_value = "127.0.0.1:3350")]
    template_bind: String,

    #[arg(long, default_value = "127.0.0.1:8080")]
    explorer_bind: String,

    /// Page cache for the sled database, in MiB.
    ///
    /// sled's own default is 1 GiB. On a 2 GiB host that is the difference
    /// between a node that survives and one the kernel kills under mining load.
    #[arg(long, default_value_t = 64)]
    db_cache_mb: u64,

    #[arg(long)]
    rpc_bind: Option<String>,
}

/// Fourteen days matches the outside bound a public mempool needs before an
/// unfunded transaction is treated as abandoned rather than pending.
const MEMPOOL_ENTRY_TTL_MS: u64 = 14 * 24 * 60 * 60 * 1_000;

fn node_mempool() -> Mempool {
    let config = MempoolConfig::default()
        .with_minimum_fee(
            hyphen_economics::MIN_RELAY_FEE,
            hyphen_economics::MIN_RELAY_FEE_PER_BYTE,
        )
        .with_max_entry_age(MEMPOOL_ENTRY_TTL_MS);
    Mempool::with_config(config)
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

// Bound runtime shutdown because the explorer serves on a blocking thread.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let outcome = runtime.block_on(run());
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    outcome
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    let (cfg, default_data_dir) = match cli.network.as_str() {
        "neural-devnet" => (ChainConfig::neural_devnet(), "hyphen_data/neural-v3"),
        "testnet" => (ChainConfig::testnet(), "hyphen_data"),
        "mainnet" => (ChainConfig::mainnet(), "hyphen_data"),
        _ => unreachable!("clap validates network"),
    };
    let data_dir = cli.data_dir.as_deref().unwrap_or(default_data_dir);
    if cli.print_chain_identity {
        println!("network={}", cfg.network_name);
        println!(
            "network_magic={}",
            hyphen_crypto::hex_encode(cfg.network_magic)
        );
        println!(
            "consensus_params_hash={}",
            hyphen_crypto::hex_encode(cfg.consensus_params_hash())
        );
        println!("genesis_hash={}", build_genesis_block(&cfg).hash());
        println!("genesis_timestamp_ms={}", GENESIS_TIMESTAMP_MS);
        println!(
            "genesis_instant={}",
            hyphen_core::timestamp::genesis_instant_iso8601()
        );
        return Ok(());
    }

    if cli.network == "mainnet"
        && cli.boot_nodes.trim().is_empty()
        && !cli.allow_isolated_mainnet
        && cli.export_history.is_none()
        && cli.replay_history.is_none()
        && cli.verify_history.is_none()
    {
        return Err("mainnet requires --boot-nodes; use --allow-isolated-mainnet only for the first seed node".into());
    }

    if let Some(path) = &cli.verify_history {
        let archive = ChainArchive::read(path)?;
        let report = verify_historical_archive(&cfg, &archive)?;
        println!(
            "verified_blocks={} final_height={} final_hash={}",
            report.blocks_applied, report.final_height, report.final_hash
        );
        return Ok(());
    }

    info!(
        "Starting Hyphen node on {} (block_time={}ms, chain_length={}, genesis_difficulty={}, genesis {})",
        cfg.network_name,
        cfg.block_time_ms(),
        cfg.pouw_chain_length,
        cfg.genesis_difficulty,
        hyphen_core::timestamp::genesis_instant_iso8601(),
    );

    let blockchain = Arc::new(
        Blockchain::open_with_cache(
            data_dir,
            cfg.clone(),
            cli.db_cache_mb.saturating_mul(1024 * 1024),
        )
        .map_err(|e| format!("Failed to open blockchain: {e}"))?,
    );

    if let Some(path) = &cli.export_history {
        let archive = export_archive(&blockchain)?;
        let encoded = wire_config(DEFAULT_WIRE_BYTES).serialize(&archive)?;
        std::fs::write(path, encoded)?;
        println!(
            "exported_blocks={} final_height={} path={}",
            archive.blocks.len(),
            blockchain.height()?,
            path.display()
        );
        return Ok(());
    }

    if let Some(path) = &cli.replay_history {
        let archive = ChainArchive::read(path)?;
        let replay_report = replay_archive(&blockchain, &archive)?;
        println!(
            "verified_blocks={} replayed_blocks={} final_height={} final_hash={} observation_ms={}",
            archive.blocks.len(),
            replay_report.blocks_applied,
            replay_report.final_height,
            replay_report.final_hash,
            replay_report.time_horizon_ms
        );
        return Ok(());
    }

    start_ntp_sync_task();

    let tip = blockchain.tip()?;
    info!(
        "Chain tip: height={}, hash={}, cum_diff={}",
        tip.height, tip.hash, tip.cumulative_difficulty
    );

    let mempool = Arc::new(RwLock::new(node_mempool()));

    {
        let prune_pool = Arc::clone(&mempool);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let removed = prune_pool.write().prune_expired(unix_time_ms());
                if removed > 0 {
                    info!(
                        target: "hyphen::metrics",
                        "Mempool expiry removed {removed} entries"
                    );
                }
            }
        });
    }

    let listen_addr_str = cli
        .listen
        .unwrap_or_else(|| format!("/ip4/0.0.0.0/tcp/{}", cfg.p2p_port));
    let listen_addr: libp2p::Multiaddr = listen_addr_str.parse()?;
    let boot_addresses = parse_boot_nodes(&cli.boot_nodes)?;
    let (mut boot_nodes, seed_resolver) = resolve_boot_nodes(&boot_addresses, &cli.dns_upstreams)?;
    let seed_resolver = seed_resolver.map(Arc::new);
    let mut seed_queries = tokio::task::JoinSet::new();
    let identity_path = cli
        .identity_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(data_dir).join("p2p_identity.key"));
    let p2p_identity = load_or_create_p2p_identity(&identity_path)?;

    let mut network = hyphen_network::HyphenNetwork::new(
        listen_addr,
        boot_nodes.clone(),
        p2p_identity,
        cfg.network_magic,
    )?;
    info!(
        "P2P network started, local peer ID: {}",
        network.swarm.local_peer_id()
    );

    let tp_addr: std::net::SocketAddr = cli.template_bind.parse()?;
    let bc_tp = Arc::clone(&blockchain);
    let mp_tp = Arc::clone(&mempool);
    let cfg_tp = cfg.clone();
    let (block_events, mut mined_block) = tokio::sync::watch::channel(None);
    tokio::spawn(async move {
        if let Err(e) = template_provider_server(tp_addr, bc_tp, mp_tp, cfg_tp, block_events).await
        {
            error!("Template Provider server error: {e}");
        }
    });
    info!("Template Provider listening on {}", cli.template_bind);

    let explorer_addr: std::net::SocketAddr = cli.explorer_bind.parse()?;
    let explorer_listener = std::net::TcpListener::bind(explorer_addr)
        .map_err(|error| format!("bind block explorer {explorer_addr}: {error}"))?;
    let bc_explorer = Arc::clone(&blockchain);
    let cfg_explorer = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) =
            hyphen_explorer::start_explorer_on(explorer_listener, bc_explorer, cfg_explorer).await
        {
            error!("Explorer server error: {e}");
        }
    });

    let rpc_bind_addr = cli
        .rpc_bind
        .unwrap_or_else(|| format!("127.0.0.1:{}", cfg.rpc_port));
    let rpc_handler =
        hyphen_rpc::handler::RpcHandler::new(Arc::clone(&blockchain), Arc::clone(&mempool));
    let rpc_server = hyphen_rpc::RpcServer::bind(&rpc_bind_addr, rpc_handler)
        .await
        .map_err(|e| format!("Failed to start RPC server: {e}"))?;
    info!("RPC server listening on {}", rpc_bind_addr);
    let (transaction_events, mut admitted_transactions) = tokio::sync::mpsc::channel(128);
    tokio::spawn(async move {
        rpc_server
            .with_transaction_events(transaction_events)
            .run()
            .await;
    });

    info!("Node running. Send SIGINT or SIGTERM to stop.");

    let mut bootstrap_interval = tokio::time::interval(std::time::Duration::from_secs(60));
    bootstrap_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut peers = PeerSync::default();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            Ok(()) = mined_block.changed() => {
                let hash = *mined_block.borrow_and_update();
                if let Some(hash) = hash {
                    p2p::publish_block(&blockchain, &mut network, hash);
                }
            }
            Some(hash) = admitted_transactions.recv() => {
                p2p::publish_transaction(&mempool, &mut network, hash);
            }
            event = network.next_event() => {
                if let Some(event) = event {
                    peers.handle_event(event, &blockchain, &mempool, &mut network);
                }
            }
            Some(result) = peers.validation.join_next(), if !peers.validation.is_empty() => {
                peers.on_validated(result, &blockchain, &mempool, &mut network);
            }
            Some(result) = peers.admissions.join_next(), if !peers.admissions.is_empty() => {
                match result {
                    Ok(admission) => peers.on_admission(admission, &mut network),
                    Err(error) => error!(%error, "Peer transaction validation task failed"),
                }
            }
            Some(result) = peers.responses.join_next(), if !peers.responses.is_empty() => {
                match result {
                    Ok((channel, response)) => { let _ = network.swarm.behaviour_mut().request_response.send_response(channel, response); }
                    Err(error) => error!(%error, "Peer response task failed"),
                }
            }
            _ = bootstrap_interval.tick() => {
                for peer in peers.policy.take_expired(Instant::now()) {
                    network.unblock_peer(peer);
                    info!("Peer {peer} ban expired; connections are allowed again");
                }
                network.dial_seeds(&boot_nodes);
                if let Some(resolver) = &seed_resolver && seed_queries.is_empty() {
                    let resolver = Arc::clone(resolver);
                    let addresses = boot_addresses.clone();
                    seed_queries.spawn_blocking(move || {
                        let mut resolved = Vec::new();
                        for address in &addresses {
                            match resolver.resolve(std::slice::from_ref(address)) {
                                Ok(seed) => resolved.extend(seed),
                                Err(error) => warn!(%address, %error, "Seed lookup failed"),
                            }
                        }
                        resolved
                    });
                }
                network.try_bootstrap();
                for peer in network.swarm.connected_peers().copied().collect::<Vec<_>>() {
                    network.send_sync_request(&peer, hyphen_network::SyncRequest::GetTip);
                }
            }
            Some(result) = seed_queries.join_next(), if !seed_queries.is_empty() => {
                match result {
                    Ok(addresses) => {
                        let refreshed = pair_with_peers(&addresses)?;
                        boot_nodes.retain(|(id, _)| !refreshed.iter().any(|(updated, _)| updated == id));
                        boot_nodes.extend(refreshed);
                        for (peer, addr) in &boot_nodes { network.add_peer(*peer, addr.clone()); }
                        network.dial_seeds(&boot_nodes);
                    }
                    Err(error) => warn!(%error, "Seed refresh task failed"),
                }
            }
            _ = &mut shutdown => {
                info!("Shutdown signal received, flushing state...");
                break;
            }
        }
    }

    while peers.validation.join_next().await.is_some() {}
    while peers.admissions.join_next().await.is_some() {}
    if let Err(error) = blockchain.db.flush() {
        error!("Failed to flush the database during shutdown: {error}");
    }

    info!("Shutdown complete.");
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(handler) => handler,
            Err(error) => {
                warn!("SIGTERM handler unavailable, waiting for SIGINT only: {error}");
                let _ = signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}

/// Parses `--boot-nodes` into validated multiaddrs.
///
/// Each address must parse and must carry `/p2p/<peer-id>`: a boot node without
/// a peer id cannot be authenticated, so accepting one would only defer the
/// failure to the dial.
fn parse_boot_nodes(s: &str) -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let nodes = s
        .split(',')
        .map(|addr_str| {
            let trimmed = addr_str.trim();
            let addr: libp2p::Multiaddr = trimmed
                .parse()
                .map_err(|e| format!("invalid boot node '{trimmed}': {e}"))?;
            boot_peer(&addr).map_err(|e| format!("invalid boot node '{trimmed}': {e}"))?;
            Ok(addr)
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(nodes)
}

/// Extracts the peer id a boot-node multiaddr commits to.
fn boot_peer(address: &libp2p::Multiaddr) -> Result<libp2p::PeerId, String> {
    use libp2p::multiaddr::Protocol::*;
    let mut parts = address.iter();
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (
            Some(Ip4(_) | Ip6(_) | Dns(_) | Dns4(_) | Dns6(_)),
            Some(Tcp(port)),
            Some(P2p(peer)),
            None,
        ) if port != 0 => Ok(peer),
        _ => Err("expected /<ip-or-dns>/<host>/tcp/<port>/p2p/<peer-id>".into()),
    }
}

/// Boot nodes keyed by the peer id their multiaddr commits to.
type BootNodes = Vec<(libp2p::PeerId, libp2p::Multiaddr)>;

/// Dialable boot nodes plus the resolver that produced them. The resolver is
/// kept alive so the bootstrap retry can pick up a rotated seed record.
type ResolvedBootNodes = (BootNodes, Option<hyphen_network::SeedResolver>);

/// Start with literal addresses while the maintenance task resolves DNS seeds.
fn resolve_boot_nodes(
    addresses: &[libp2p::Multiaddr],
    upstreams: &[String],
) -> Result<ResolvedBootNodes, Box<dyn std::error::Error>> {
    if !addresses.iter().any(hyphen_network::is_dns_seed) {
        return Ok((pair_with_peers(addresses)?, None));
    }

    let resolver = if upstreams.is_empty() {
        info!("Resolving DNS boot nodes iteratively with DNSSEC validation");
        hyphen_network::SeedResolver::recursive()?
    } else {
        info!(
            "Resolving DNS boot nodes through {} configured upstream(s)",
            upstreams.len()
        );
        hyphen_network::SeedResolver::with_upstreams(upstreams)?
    };

    let literals = addresses
        .iter()
        .filter(|addr| !hyphen_network::is_dns_seed(addr))
        .cloned()
        .collect::<Vec<_>>();
    Ok((pair_with_peers(&literals)?, Some(resolver)))
}

fn pair_with_peers(
    addresses: &[libp2p::Multiaddr],
) -> Result<BootNodes, Box<dyn std::error::Error>> {
    addresses
        .iter()
        .map(|address| {
            let peer = boot_peer(address)
                .map_err(|e| format!("boot node '{address}' is missing /p2p/<peer-id>: {e}"))?;
            Ok((peer, address.clone()))
        })
        .collect::<Result<Vec<_>, String>>()
        .map_err(Into::into)
}

fn load_or_create_p2p_identity(
    path: &Path,
) -> Result<libp2p::identity::Keypair, Box<dyn std::error::Error>> {
    let load = |file: std::fs::File| -> Result<_, Box<dyn std::error::Error>> {
        let mut encoded = zeroize::Zeroizing::new(Vec::new());
        if file.take(64 * 1024 + 1).read_to_end(&mut encoded)? > 64 * 1024 {
            return Err("oversized p2p identity".into());
        }
        Ok(libp2p::identity::Keypair::from_protobuf_encoding(&encoded)?)
    };
    match std::fs::File::open(path) {
        Ok(file) => return load(file),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let identity = libp2p::identity::Keypair::generate_ed25519();
    let encoded = zeroize::Zeroizing::new(identity.to_protobuf_encoding()?);
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(&encoded)?;
    staged.as_file().sync_all()?;
    match staged.persist_noclobber(path) {
        Ok(_) => {}
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {
            return load(std::fs::File::open(path)?);
        }
        Err(e) => return Err(e.into()),
    }
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    info!("Created persistent P2P identity at {}", path.display());
    Ok(identity)
}

async fn template_provider_server(
    addr: std::net::SocketAddr,
    blockchain: Arc<Blockchain>,
    mempool: Arc<RwLock<Mempool>>,
    cfg: ChainConfig,
    block_events: tokio::sync::watch::Sender<Option<hyphen_crypto::Hash256>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    info!("Template Provider server listening on {addr}");
    const MAX_TEMPLATE_CONNECTIONS: usize = 16;
    let mut sessions = tokio::task::JoinSet::new();

    loop {
        let (stream, peer_addr) = tokio::select! {
            Some(done) = sessions.join_next(), if !sessions.is_empty() => {
                if let Err(error) = done { warn!("TP session stopped: {error}"); }
                continue;
            }
            incoming = listener.accept(), if sessions.len() < MAX_TEMPLATE_CONNECTIONS => incoming?,
        };
        info!("TP client connected from {peer_addr}");
        let bc = Arc::clone(&blockchain);
        let mp = Arc::clone(&mempool);
        let cfg = cfg.clone();
        let events = block_events.clone();
        sessions.spawn(async move {
            if let Err(e) = handle_tp_client(stream, bc, mp, cfg, events).await {
                warn!("TP client {peer_addr} disconnected: {e}");
            }
        });
    }
}

async fn handle_tp_client(
    stream: tokio::net::TcpStream,
    blockchain: Arc<Blockchain>,
    mempool: Arc<RwLock<Mempool>>,
    cfg: ChainConfig,
    block_events: tokio::sync::watch::Sender<Option<hyphen_crypto::Hash256>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut reader, mut writer) = stream.into_split();

    let node_sk = hyphen_crypto::SecretKey::generate();

    loop {
        let env = tokio::time::timeout(
            std::time::Duration::from_secs(90),
            read_envelope(&mut reader),
        )
        .await??;
        if !env.verify() {
            return Err("invalid or stale TP envelope signature".into());
        }

        match env.msg_type {
            hyphen_transport::canonical::TP_CANONICAL_HASHES => {
                use hyphen_transport::canonical::*;
                if env.payload.len() > 2048 {
                    return Err("canonical hash request too large".into());
                }
                let request = CanonicalHashesRequest::decode(&env.payload[..])?;
                validate_template_request(
                    request.chain.as_ref().ok_or("missing chain identity")?,
                    &cfg,
                )?;
                if request.heights.len() > MAX_CANONICAL_HEIGHTS {
                    return Err("too many canonical heights".into());
                }
                let result = {
                    let _view = blockchain.canonical_view()?;
                    let tip = blockchain.tip()?;
                    let mut hashes = Vec::with_capacity(request.heights.len());
                    for height in request.heights {
                        hashes.push(if height > tip.height {
                            Vec::new()
                        } else {
                            blockchain
                                .blocks
                                .get_block_hash_at_height(height)?
                                .as_bytes()
                                .to_vec()
                        });
                    }
                    CanonicalHashesResult {
                        request_nonce: env.nonce,
                        tip_height: tip.height,
                        tip_hash: tip.hash.as_bytes().to_vec(),
                        hashes,
                    }
                };
                let reply = SignedEnvelope::sign(
                    TP_CANONICAL_HASHES_RESULT,
                    result.encode_to_vec(),
                    &node_sk,
                );
                write_envelope(&mut writer, &reply).await?;
            }
            TP_GET_TEMPLATE => {
                let req = hyphen_transport::TemplateRequest::decode(&env.payload[..])?;
                validate_template_request(&req, &cfg)?;
                let tpl = build_template(&blockchain, &mempool, &cfg)?;
                let resp = SignedEnvelope::sign(TP_TEMPLATE, tpl.encode_to_vec(), &node_sk);
                write_envelope(&mut writer, &resp).await?;
            }

            TP_SUBMIT_BLOCK => {
                let req = SubmitBlockRequest::decode(&env.payload[..])?;
                let result =
                    handle_block_submission(&req.block_data, &blockchain, &mempool, &block_events);
                let resp_env =
                    SignedEnvelope::sign(TP_SUBMIT_RESULT, result.encode_to_vec(), &node_sk);
                write_envelope(&mut writer, &resp_env).await?;
            }

            TP_SUBSCRIBE => {
                let req = hyphen_transport::TemplateRequest::decode(&env.payload[..])?;
                validate_template_request(&req, &cfg)?;
                let tpl = build_template(&blockchain, &mempool, &cfg)?;
                let resp = SignedEnvelope::sign(TP_TEMPLATE, tpl.encode_to_vec(), &node_sk);
                write_envelope(&mut writer, &resp).await?;
                info!("TP client subscribed for template updates");

                use tokio::io::AsyncBufReadExt;
                let mut reader = tokio::io::BufReader::new(reader);
                let mut interval = tokio::time::interval(cfg.block_time / 2);
                let mut last_parent = tpl.prev_hash;

                loop {
                    let mut read = std::pin::pin!(async {
                        reader.fill_buf().await?;
                        tokio::time::timeout(
                            std::time::Duration::from_secs(90),
                            read_envelope(&mut reader),
                        )
                        .await
                        .map_err(std::io::Error::from)?
                    });
                    let incoming = loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                if blockchain.tip().is_ok_and(|tip|tip.hash.as_bytes().as_slice() != last_parent) {
                                    match build_template(&blockchain, &mempool, &cfg) {
                                        Ok(tpl) => {
                                            last_parent.clone_from(&tpl.prev_hash);
                                            let env = SignedEnvelope::sign(
                                                TP_TEMPLATE,
                                                tpl.encode_to_vec(),
                                                &node_sk,
                                            );
                                            if write_envelope(&mut writer, &env)
                                                .await
                                                .is_err()
                                            {
                                                return Ok(());
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Failed to build template: {e}");
                                        }
                                    }
                                }
                            }

                            message = &mut read => break message?,
                        }
                    };
                    if !incoming.verify() {
                        return Err("invalid or stale subscribed TP envelope".into());
                    }
                    match incoming.msg_type {
                        TP_SUBMIT_BLOCK => {
                            let req = SubmitBlockRequest::decode(&incoming.payload[..])?;
                            let result = handle_block_submission(
                                &req.block_data,
                                &blockchain,
                                &mempool,
                                &block_events,
                            );
                            let resp_env = SignedEnvelope::sign(
                                TP_SUBMIT_RESULT,
                                result.encode_to_vec(),
                                &node_sk,
                            );
                            write_envelope(&mut writer, &resp_env).await?;

                            if result.accepted
                                && let Ok(tpl) = build_template(&blockchain, &mempool, &cfg)
                            {
                                last_parent.clone_from(&tpl.prev_hash);
                                let env = SignedEnvelope::sign(
                                    TP_TEMPLATE,
                                    tpl.encode_to_vec(),
                                    &node_sk,
                                );
                                write_envelope(&mut writer, &env).await?;
                            }
                        }

                        TP_DECLARE_JOB => {
                            let result = handle_job_declaration(
                                &incoming.payload,
                                &blockchain,
                                &mempool,
                                &cfg,
                            );
                            let resp_env = SignedEnvelope::sign(
                                TP_DECLARE_JOB_RESULT,
                                result.encode_to_vec(),
                                &node_sk,
                            );
                            write_envelope(&mut writer, &resp_env).await?;
                        }

                        TP_GET_TEMPLATE => {
                            let req =
                                hyphen_transport::TemplateRequest::decode(&incoming.payload[..])?;
                            validate_template_request(&req, &cfg)?;
                            let tpl = build_template(&blockchain, &mempool, &cfg)?;
                            let resp =
                                SignedEnvelope::sign(TP_TEMPLATE, tpl.encode_to_vec(), &node_sk);
                            write_envelope(&mut writer, &resp).await?;
                        }

                        other => {
                            warn!(
                                "Unknown TP msg during subscribe: \
                                             {other}"
                            );
                        }
                    }
                }
            }

            TP_DECLARE_JOB => {
                let result = handle_job_declaration(&env.payload, &blockchain, &mempool, &cfg);
                let resp_env =
                    SignedEnvelope::sign(TP_DECLARE_JOB_RESULT, result.encode_to_vec(), &node_sk);
                write_envelope(&mut writer, &resp_env).await?;
            }

            other => {
                warn!("Unknown TP message type: {other}");
            }
        }
    }
}

fn validate_template_request(
    request: &hyphen_transport::TemplateRequest,
    cfg: &ChainConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if request.protocol_version != POOL_PROTOCOL_VERSION {
        return Err(format!(
            "unsupported TP protocol version {}",
            request.protocol_version
        )
        .into());
    }
    if request.network_magic.as_slice() != cfg.network_magic {
        return Err("TP network mismatch".into());
    }
    if request.consensus_params_hash.as_slice() != cfg.consensus_params_hash()
        || request.genesis_hash.as_slice() != build_genesis_block(cfg).hash().as_bytes()
    {
        return Err("TP chain identity mismatch".into());
    }
    Ok(())
}

// The v5 header (fixed hashes/keys and at most nine bytes per integer),
// authorization (at most 256 bytes), and outer sequence lengths fit in 1 KiB.
// A miner may replace header fields and supply full-width witness values.
fn template_transaction_budget(cfg: &ChainConfig) -> usize {
    let witnesses = if cfg.feature_enabled(hyphen_core::config::FEATURE_NEURAL_MEMORY_WORK) {
        1
    } else if cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) {
        hyphen_neural::PROFILE_SPEC.input_dim as usize
    } else {
        hyphen_pow::MAX_WITNESSES_PER_BLOCK as usize
    };
    cfg.max_block_size.saturating_sub(1024 + 9 * witnesses)
}

fn framed_blob_size(len: usize) -> usize {
    // Vec<u8> uses a compact unsigned length followed by raw bytes.
    let prefix = wire_config(16)
        .serialized_size(&(len as u64))
        .expect("u64 fits in 9 bytes");
    len.saturating_add(prefix as usize)
}

fn build_template(
    blockchain: &Arc<Blockchain>,
    mempool: &Arc<RwLock<Mempool>>,
    cfg: &ChainConfig,
) -> Result<BlockTemplate, Box<dyn std::error::Error + Send + Sync>> {
    let mut tx_blobs: Vec<Vec<u8>> = {
        let pool = mempool.read();
        let budget = template_transaction_budget(cfg);
        pool.select_candidate_blobs(budget, budget / 4, framed_blob_size)
    };
    tx_blobs.sort_by_cached_key(|transaction| hyphen_crypto::blake3_hash(transaction));

    let hyphen_consensus::chain::CandidateTemplate {
        height: next_height,
        parent,
        difficulty,
        epoch_seed,
        commitment_root,
        nullifier_root,
        state_root,
        total_fee,
    } = blockchain.prepare_template(&mut tx_blobs)?;
    let parent_hash = parent.hash();

    let reward = hyphen_economics::emission::block_reward(next_height, cfg);

    let tx_root = hyphen_core::block::merkle_root_iter(
        tx_blobs.iter().map(|blob| hyphen_crypto::blake3_hash(blob)),
    );

    let header = hyphen_core::BlockHeader {
        version: hyphen_core::FROZEN_BLOCK_VERSION,
        height: next_height,
        timestamp: template_timestamp(&parent, ntp_adjusted_timestamp_ms(), cfg)?,
        prev_hash: parent_hash,
        tx_root,
        commitment_root,
        nullifier_root,
        state_root,
        receipt_root: hyphen_crypto::Hash256::ZERO,
        uncle_root: hyphen_crypto::Hash256::ZERO,
        pow_commitment: hyphen_crypto::Hash256::ZERO,
        epoch_seed,
        difficulty,
        nonce: 0,
        extra_nonce: [0u8; 32],
        miner_pubkey: [0u8; 32],
        total_fee,
        reward,
        view_tag: 0,
        block_size: 0,
    };

    let header_data = wire_config(DEFAULT_WIRE_BYTES).serialize(&header)?;
    let template_id = hyphen_crypto::blake3_hash_many(&[
        &next_height.to_le_bytes(),
        &difficulty.to_le_bytes(),
        parent_hash.as_bytes(),
    ]);

    Ok(BlockTemplate {
        template_id: template_id.as_bytes().to_vec(),
        header_data,
        transactions: tx_blobs,
        height: next_height,
        difficulty,
        reward,
        total_fee,
        epoch_seed: epoch_seed.as_bytes().to_vec(),
        prev_hash: parent_hash.as_bytes().to_vec(),
        pouw_chain_length: cfg.pouw_chain_length as u64,
        parent_work_commitment: parent.pow_commitment.as_bytes().to_vec(),
        clean: true,
        network_magic: cfg.network_magic.to_vec(),
        protocol_version: POOL_PROTOCOL_VERSION,
        consensus_params_hash: cfg.consensus_params_hash().to_vec(),
        genesis_hash: build_genesis_block(cfg).hash().as_bytes().to_vec(),
    })
}

fn template_timestamp(
    parent: &hyphen_core::BlockHeader,
    now: u64,
    cfg: &ChainConfig,
) -> Result<u64, hyphen_core::error::CoreError> {
    use hyphen_core::error::CoreError;
    if parent.height == 0 && !cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) {
        return Ok(now);
    }
    let timestamp = now.max(
        parent
            .timestamp
            .checked_add(1)
            .ok_or(CoreError::FutureTimestamp)?,
    );
    if timestamp > now.saturating_add(cfg.timestamp_future_limit_ms) {
        return Err(CoreError::FutureTimestamp);
    }
    Ok(timestamp)
}

fn handle_block_submission(
    block_data: &[u8],
    blockchain: &Arc<Blockchain>,
    mempool: &Arc<RwLock<Mempool>>,
    block_events: &tokio::sync::watch::Sender<Option<hyphen_crypto::Hash256>>,
) -> SubmitBlockResult {
    let block =
        match hyphen_core::Block::deserialise_limited(block_data, blockchain.cfg.max_block_size) {
            Ok(b) => b,
            Err(e) => {
                return SubmitBlockResult {
                    accepted: false,
                    error: format!("deserialise: {e}"),
                    block_hash: Vec::new(),
                };
            }
        };

    let block_hash = block.hash();
    info!(
        "TP: received block submission height={} hash={}",
        block.header.height, block_hash
    );

    match blockchain.accept_submitted_block(&block) {
        Ok(()) => {
            info!("TP: block {} accepted", block_hash);
            block_events.send_replace(Some(block_hash));

            purge_block_transactions(blockchain, mempool, &block);

            SubmitBlockResult {
                accepted: true,
                error: String::new(),
                block_hash: block_hash.as_bytes().to_vec(),
            }
        }
        Err(e) => {
            warn!("TP: block {} rejected: {e}", block_hash);
            SubmitBlockResult {
                accepted: false,
                error: format!("{e}"),
                block_hash: block_hash.as_bytes().to_vec(),
            }
        }
    }
}

fn handle_job_declaration(
    mut payload: &[u8],
    blockchain: &Arc<Blockchain>,
    mempool: &Arc<RwLock<Mempool>>,
    cfg: &ChainConfig,
) -> DeclareJobResult {
    let reject = |error: String| DeclareJobResult {
        accepted: false,
        job_id: Vec::new(),
        error,
        updated_header: Vec::new(),
    };
    const MAX_DECLARED_TXS: usize = 10_000;
    if payload.len() > cfg.max_block_size + 4096 + 128 + 6 * MAX_DECLARED_TXS {
        return reject("job declaration exceeds byte limit".into());
    }
    let mut req = DeclareJobRequest::default();
    while !payload.is_empty() {
        let (tag, ty) = match prost::encoding::decode_key(&mut payload) {
            Ok(key) => key,
            Err(e) => return reject(e.to_string()),
        };
        if tag == 2 && req.custom_transactions.len() == MAX_DECLARED_TXS {
            return reject("transaction count exceeds declaration limit".into());
        }
        if let Err(e) = req.merge_field(tag, ty, &mut payload, Default::default()) {
            return reject(e.to_string());
        }
    }
    if req.coinbase_script.len() > 4 * 1024 {
        return reject("coinbase script exceeds 4 KiB".into());
    }
    if req
        .custom_transactions
        .iter()
        .any(|tx| tx.len() > hyphen_wire::MAX_WIRE_COLLECTION_ITEMS)
    {
        return reject("transaction exceeds the block wire format's byte-vector limit".into());
    }
    if req
        .custom_transactions
        .iter()
        .map(|tx| framed_blob_size(tx.len()))
        .sum::<usize>()
        > template_transaction_budget(cfg)
    {
        return reject("transactions exceed block byte limit".into());
    }
    let base_template = match build_template(blockchain, mempool, cfg) {
        Ok(template) => template,
        Err(error) => return reject(format!("base template: {error}")),
    };
    if req.template_id != base_template.template_id {
        return reject("stale or unknown base template id".into());
    }
    if cfg.feature_enabled(hyphen_core::FEATURE_CANONICAL_TX_ORDER)
        && req.custom_transactions.windows(2).any(|pair| {
            hyphen_crypto::blake3_hash(&pair[0]) >= hyphen_crypto::blake3_hash(&pair[1])
        })
    {
        return reject("transactions must be in strict canonical hash order".into());
    }

    let mut header: hyphen_core::BlockHeader =
        match wire_config(4096).deserialize(&base_template.header_data) {
            Ok(header) => header,
            Err(error) => return reject(format!("base header: {error}")),
        };
    let (total_fee, state_root) = match blockchain.candidate_fee_and_root(
        &req.custom_transactions,
        header.height,
        header.prev_hash,
    ) {
        Ok(candidate) => candidate,
        Err(error) => return reject(format!("candidate validation: {error}")),
    };
    let custom_block = hyphen_core::Block {
        pow_witnesses: Vec::new(),
        header: header.clone(),
        transactions: req.custom_transactions,
        uncle_headers: Vec::new(),
        block_authorization: Vec::new(),
    };
    header.tx_root = custom_block.compute_tx_root();
    header.total_fee = total_fee;
    header.state_root = state_root;

    let job_id = hyphen_crypto::blake3_hash_many(&[
        b"Hyphen/TP/DeclaredJob/v1",
        &req.template_id,
        &req.coinbase_script,
        header.tx_root.as_bytes(),
        &total_fee.to_le_bytes(),
    ]);
    let header_data = match wire_config(DEFAULT_WIRE_BYTES).serialize(&header) {
        Ok(data) => data,
        Err(error) => return reject(format!("header serialisation: {error}")),
    };

    DeclareJobResult {
        accepted: true,
        job_id: job_id.as_bytes().to_vec(),
        error: String::new(),
        updated_header: header_data,
    }
}

#[cfg(test)]
mod payment_capacity;

#[cfg(test)]
mod template_tests {
    use super::*;

    #[test]
    fn submission_accepts_a_template_above_a_clock_ahead_parent() {
        use hyphen_core::{Block, BlockAuthorization, BlockHeader};
        use hyphen_crypto::{SecretKey, SpendKey, ViewKey};

        let dir = tempfile::tempdir().unwrap();
        let cfg = ChainConfig::archived_devnet_v2();
        let chain = Arc::new(Blockchain::open(dir.path().to_str().unwrap(), cfg.clone()).unwrap());
        let pool = Arc::new(RwLock::new(Mempool::new(16)));
        let (events, _) = tokio::sync::watch::channel(None);
        let miner = SecretKey([97; 32]);
        let view = ViewKey([98; 32]).public_point().compress().to_bytes();
        let spend = SpendKey([99; 32]).public_point().compress().to_bytes();
        let genesis = build_genesis_block(&cfg);
        let mut parent_work = genesis.header.pow_commitment;
        let ahead = ntp_adjusted_timestamp_ms() + cfg.timestamp_future_limit_ms / 2;
        let mut offset = 3;
        for height in 1..=2 {
            let template = build_template(&chain, &pool, &cfg).unwrap();
            let wire = wire_config(cfg.max_block_size);
            let mut header: BlockHeader = wire.deserialize(&template.header_data).unwrap();
            if height == 1 {
                header.timestamp = ahead;
            } else {
                assert_eq!(header.timestamp, ahead + 1);
            }
            let witnesses = hyphen_pow::search(&hyphen_pow::SearchParams {
                length: cfg.pouw_chain_length,
                offset,
                stride: 2,
                count: header.difficulty,
                max_candidates: 20_000_000,
                is_claimed: &|_| false,
            })
            .unwrap()
            .witnesses;
            assert_eq!(witnesses.len() as u64, header.difficulty);
            offset = witnesses.last().unwrap() + 2;
            header.pow_commitment =
                hyphen_pow::vms::witness_commitment(&parent_work, height, &witnesses);
            parent_work = header.pow_commitment;
            header.miner_pubkey = *miner.public_key().as_bytes();
            header.extra_nonce = hyphen_core::authorization::reward_commitment(&view, &spend);
            let authorization = BlockAuthorization::sign(
                &header,
                cfg.network_magic,
                cfg.consensus_params_hash(),
                genesis.hash(),
                view,
                spend,
                &miner,
            )
            .unwrap();
            let block = Block {
                header,
                pow_witnesses: witnesses,
                transactions: template.transactions,
                uncle_headers: vec![],
                block_authorization: wire.serialize(&authorization).unwrap(),
            };
            let result =
                handle_block_submission(&wire.serialize(&block).unwrap(), &chain, &pool, &events);
            assert!(result.accepted, "{}", result.error);
            assert_eq!(chain.tip().unwrap().hash, block.hash());
        }
    }

    #[test]
    fn timestamp_advances_within_the_arrival_window() {
        let cfg = ChainConfig::archived_devnet_v2();
        let mut parent = build_genesis_block(&cfg).header;
        let now = parent.timestamp - 1;
        assert_eq!(template_timestamp(&parent, now, &cfg).unwrap(), now);
        assert_eq!(
            template_timestamp(&parent, now, &ChainConfig::archived_neural_devnet_v1()).unwrap(),
            parent.timestamp + 1
        );
        parent.height = 1;
        parent.timestamp = now + cfg.timestamp_future_limit_ms - 1;
        assert_eq!(
            template_timestamp(&parent, now, &cfg).unwrap(),
            now + cfg.timestamp_future_limit_ms
        );
        parent.timestamp += 1;
        assert!(template_timestamp(&parent, now, &cfg).is_err());
        parent.timestamp = u64::MAX;
        assert!(template_timestamp(&parent, u64::MAX, &cfg).is_err());
    }
}
