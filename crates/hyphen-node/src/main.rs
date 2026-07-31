use libp2p::{gossipsub, identify, request_response};

use clap::Parser;
use parking_lot::RwLock;
use prost::Message;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info, warn};

use hyphen_consensus::{
    build_genesis_block, export_archive, replay_archive, verify_archive_envelopes, Blockchain,
    ChainArchive,
};
use hyphen_core::config::ChainConfig;
use hyphen_core::timestamp::{ntp_adjusted_timestamp_ms, start_ntp_sync_task};
use hyphen_mempool::Mempool;
use hyphen_transport::{
    read_envelope, write_envelope, BlockTemplate, DeclareJobRequest, DeclareJobResult,
    SignedEnvelope, SubmitBlockRequest, SubmitBlockResult, TP_DECLARE_JOB, TP_DECLARE_JOB_RESULT,
    TP_GET_TEMPLATE, TP_SUBMIT_BLOCK, TP_SUBMIT_RESULT, TP_SUBSCRIBE, TP_TEMPLATE,
};

#[derive(Parser, Debug)]
#[command(name = "hyphen-node", about = "Hyphen blockchain full node")]
struct Cli {
    #[arg(long, default_value = "hyphen_data")]
    data_dir: String,

    #[arg(long, value_parser = ["mainnet", "testnet", "devnet"], default_value = "devnet")]
    network: String,

    #[arg(long)]
    identity_file: Option<PathBuf>,

    #[arg(long)]
    listen: Option<String>,

    #[arg(long, default_value = "")]
    boot_nodes: String,

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

    /// Verify archive identity, linkage, roots and miner authorization without applying state.
    #[arg(long)]
    verify_history: Option<PathBuf>,

    #[arg(long, default_value = "127.0.0.1:3350")]
    template_bind: String,

    #[arg(long, default_value = "127.0.0.1:8080")]
    explorer_bind: String,

    #[arg(long)]
    rpc_bind: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    let cfg = match cli.network.as_str() {
        "mainnet" => ChainConfig::mainnet(),
        "testnet" => ChainConfig::testnet(),
        "devnet" => ChainConfig::devnet(),
        _ => unreachable!("clap validates network"),
    };
    if cli.print_chain_identity {
        println!("network={}", cfg.network_name);
        println!("network_magic={}", hex::encode(cfg.network_magic));
        println!(
            "consensus_params_hash={}",
            hex::encode(cfg.consensus_params_hash())
        );
        println!("genesis_hash={}", build_genesis_block(&cfg).hash());
        return Ok(());
    }
    if cli.network == "mainnet"
        && cli.boot_nodes.trim().is_empty()
        && !cli.allow_isolated_mainnet
        && cli.export_history.is_none()
        && cli.replay_history.is_none()
        && cli.verify_history.is_none()
    {
        return Err(
            "mainnet requires --boot-nodes; use --allow-isolated-mainnet only for the first seed node"
                .into(),
        );
    }

    if let Some(path) = &cli.verify_history {
        let archive = read_chain_archive(path)?;
        let report = verify_archive_envelopes(
            &cfg,
            &archive,
            hyphen_core::timestamp::ntp_adjusted_timestamp_ms(),
        )?;
        println!(
            "verified_blocks={} final_height={} final_hash={}",
            report.blocks_applied, report.final_height, report.final_hash
        );
        return Ok(());
    }

    info!(
        "Starting Hyphen node on {} (block_time={}ms, arena={}MiB)",
        cfg.network_name,
        cfg.block_time_ms(),
        cfg.arena_size / (1024 * 1024),
    );

    let blockchain = Arc::new(
        Blockchain::open(&cli.data_dir, cfg.clone())
            .map_err(|e| format!("Failed to open blockchain: {e}"))?,
    );

    if let Some(path) = &cli.export_history {
        let archive = export_archive(&blockchain)?;
        let encoded = hyphen_codec::serialize(&archive)?;
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
        let archive = read_chain_archive(path)?;
        let envelope_report = verify_archive_envelopes(
            &cfg,
            &archive,
            hyphen_core::timestamp::ntp_adjusted_timestamp_ms(),
        )?;
        let replay_report = replay_archive(&blockchain, &archive)?;
        println!(
            "verified_blocks={} replayed_blocks={} final_height={} final_hash={}",
            envelope_report.blocks_applied,
            replay_report.blocks_applied,
            replay_report.final_height,
            replay_report.final_hash
        );
        return Ok(());
    }

    start_ntp_sync_task();

    let tip = blockchain.tip()?;
    info!(
        "Chain tip: height={}, hash={}, cum_diff={}",
        tip.height, tip.hash, tip.cumulative_difficulty
    );

    let mempool = Arc::new(RwLock::new(Mempool::new(10_000)));

    let listen_addr_str = cli
        .listen
        .unwrap_or_else(|| format!("/ip4/0.0.0.0/tcp/{}", cfg.p2p_port));
    let listen_addr: libp2p::Multiaddr = listen_addr_str.parse()?;
    let boot_nodes = parse_boot_nodes(&cli.boot_nodes)?;
    let identity_path = cli
        .identity_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(&cli.data_dir).join("p2p_identity.key"));
    let p2p_identity = load_or_create_p2p_identity(&identity_path)?;

    let mut network = hyphen_network::HyphenNetwork::new(
        listen_addr,
        boot_nodes,
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
    tokio::spawn(async move {
        if let Err(e) = template_provider_server(tp_addr, bc_tp, mp_tp, cfg_tp).await {
            error!("Template Provider server error: {e}");
        }
    });
    info!("Template Provider listening on {}", cli.template_bind);

    let explorer_addr: std::net::SocketAddr = cli.explorer_bind.parse()?;
    let bc_explorer = Arc::clone(&blockchain);
    let cfg_explorer = cfg.clone();
    tokio::spawn(async move {
        if let Err(e) =
            hyphen_explorer::start_explorer(explorer_addr, bc_explorer, cfg_explorer).await
        {
            error!("Explorer server error: {e}");
        }
    });

    // ── RPC Server ───────────────────────────────────────────
    let rpc_bind_addr = cli
        .rpc_bind
        .unwrap_or_else(|| format!("127.0.0.1:{}", cfg.rpc_port));
    let rpc_handler =
        hyphen_rpc::handler::RpcHandler::new(Arc::clone(&blockchain), Arc::clone(&mempool));
    let rpc_server = hyphen_rpc::RpcServer::bind(&rpc_bind_addr, rpc_handler)
        .await
        .map_err(|e| format!("Failed to start RPC server: {e}"))?;
    info!("RPC server listening on {}", rpc_bind_addr);
    tokio::spawn(async move {
        rpc_server.run().await;
    });

    info!("Node running. Press Ctrl+C to stop.");

    let mut bootstrap_interval = tokio::time::interval(std::time::Duration::from_secs(60));
    // Don't delay the first tick.
    bootstrap_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            event = network.next_event() => {
                if let Some(event) = event {
                    handle_swarm_event(event, &blockchain, &mempool, &mut network);
                }
            }
            _ = bootstrap_interval.tick() => {
                // Periodically re-attempt Kademlia bootstrap so we discover
                // new peers even if the initial boot nodes were offline.
                let n = network.connected_peer_count();
                if n == 0 {
                    info!("No peers connected, retrying Kademlia bootstrap...");
                }
                network.try_bootstrap();
            }
            _ = signal::ctrl_c() => {
                info!("Shutting down...");
                break;
            }
        }
    }

    let _ = blockchain.db.flush();

    info!("Shutdown complete.");
    Ok(())
}

fn read_chain_archive(path: &Path) -> Result<ChainArchive, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > 512 * 1024 * 1024 {
        return Err("chain archive exceeds the 512 MiB CLI limit".into());
    }
    let encoded = std::fs::read(path)?;
    Ok(hyphen_codec::deserialize_with_limit(
        &encoded,
        512 * 1024 * 1024,
    )?)
}

fn parse_boot_nodes(
    s: &str,
) -> Result<Vec<(libp2p::PeerId, libp2p::Multiaddr)>, Box<dyn std::error::Error>> {
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
            let peer_id = addr
                .iter()
                .find_map(|proto| {
                    if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
                        Some(peer_id)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| format!("boot node '{trimmed}' is missing /p2p/<peer-id>"))?;
            Ok((peer_id, addr))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(nodes)
}

fn load_or_create_p2p_identity(
    path: &Path,
) -> Result<libp2p::identity::Keypair, Box<dyn std::error::Error>> {
    if path.exists() {
        let encoded = std::fs::read(path)?;
        return libp2p::identity::Keypair::from_protobuf_encoding(&encoded)
            .map_err(|e| format!("invalid p2p identity {}: {e}", path.display()).into());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let identity = libp2p::identity::Keypair::generate_ed25519();
    let encoded = identity.to_protobuf_encoding()?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("cannot create p2p identity {}: {e}", path.display()))?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    info!("Created persistent P2P identity at {}", path.display());
    Ok(identity)
}

fn handle_swarm_event(
    event: libp2p::swarm::SwarmEvent<hyphen_network::behaviour::HyphenBehaviourEvent>,
    _blockchain: &Arc<Blockchain>,
    _mempool: &Arc<RwLock<Mempool>>,
    network: &mut hyphen_network::HyphenNetwork,
) {
    use libp2p::swarm::SwarmEvent;
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            let local_peer = *network.swarm.local_peer_id();
            info!("Listening on {address}/p2p/{local_peer}");
        }
        SwarmEvent::ConnectionEstablished {
            peer_id,
            num_established,
            ..
        } => {
            info!("Connected to {peer_id} (total connections: {num_established})");
            network.send_sync_request(&peer_id, hyphen_network::SyncRequest::GetTip);
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            cause,
            ..
        } => {
            if num_established == 0 {
                info!(
                    "Disconnected from {peer_id} (cause: {})",
                    cause
                        .as_ref()
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "none".into())
                );
            }
        }
        SwarmEvent::Behaviour(behaviour_event) => {
            handle_behaviour_event(behaviour_event, _blockchain, _mempool, network);
        }
        _ => {}
    }
}

fn handle_behaviour_event(
    event: hyphen_network::behaviour::HyphenBehaviourEvent,
    blockchain: &Arc<Blockchain>,
    mempool: &Arc<RwLock<Mempool>>,
    network: &mut hyphen_network::HyphenNetwork,
) {
    use hyphen_network::behaviour::HyphenBehaviourEvent;
    match event {
        HyphenBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            message,
            propagation_source,
            ..
        }) => {
            if let Ok(msg) = hyphen_network::NetworkMessage::decode_proto(&message.data) {
                match msg {
                    hyphen_network::NetworkMessage::NewBlock(block_bytes) => {
                        if let Ok(block) = hyphen_core::Block::deserialise_limited(
                            &block_bytes,
                            blockchain.cfg.max_block_size,
                        ) {
                            info!(
                                "Received block {} from {}",
                                block.header.height, propagation_source
                            );
                            if let Err(e) = blockchain.accept_block(&block) {
                                warn!("Block rejected: {e}");
                            }
                        }
                    }
                    hyphen_network::NetworkMessage::NewTransaction(tx_bytes) => {
                        let tx = match hyphen_tx::Transaction::deserialise_limited(&tx_bytes) {
                            Ok(t) => t,
                            Err(e) => {
                                warn!(
                                    target: "hyphen::metrics",
                                    "P2P tx decode failed from {}: {e}", propagation_source
                                );
                                return;
                            }
                        };

                        // ── Full consensus validation (same as RPC path) ──
                        let tip = match blockchain.tip() {
                            Ok(t) => t,
                            Err(_) => return,
                        };
                        let next_height = tip.height + 1;

                        // Nullifier check
                        for inp in &tx.inputs {
                            if blockchain
                                .nullifiers
                                .contains(&inp.key_image)
                                .unwrap_or(false)
                            {
                                warn!(
                                    target: "hyphen::metrics",
                                    "P2P tx rejected (double-spend) from {}", propagation_source
                                );
                                return;
                            }
                        }

                        let valid_epoch_contexts =
                            match blockchain.build_valid_epoch_contexts(next_height) {
                                Ok(v) => v,
                                Err(_) => return,
                            };

                        let total_outputs = {
                            let ct = blockchain.commitment_tree.read();
                            ct.count()
                        };

                        let validator = hyphen_consensus::BlockValidator::new(&blockchain.cfg);
                        let store = blockchain.store();
                        let vre_quality = match validator.validate_transaction(
                            &tx,
                            |global_index| {
                                store.resolve_ring_member(global_index).map_err(|e| {
                                    hyphen_consensus::validator::ValidationError::Core(
                                        hyphen_core::error::CoreError::Storage(e.to_string()),
                                    )
                                })
                            },
                            &valid_epoch_contexts,
                            total_outputs,
                            next_height,
                        ) {
                            Ok(q) => q,
                            Err(e) => {
                                warn!(
                                    target: "hyphen::metrics",
                                    "P2P tx rejected from {}: {e}", propagation_source
                                );
                                return;
                            }
                        };

                        let tx_hash_hex = hex::encode(tx.hash().as_bytes());
                        let mut pool = mempool.write();
                        match pool.insert(tx, hyphen_mempool::Validated::new(vre_quality)) {
                            Ok(hash) => {
                                info!(
                                    target: "hyphen::metrics",
                                    "P2P tx {} accepted (vre_quality={}) from {}",
                                    hash, vre_quality, propagation_source
                                );
                            }
                            Err(e) => {
                                warn!(
                                    target: "hyphen::metrics",
                                    "P2P tx {} mempool-rejected from {}: {e}",
                                    tx_hash_hex, propagation_source
                                );
                            }
                        }
                    }
                    hyphen_network::NetworkMessage::InclusionReceiptVote(receipt) => {
                        warn!(
                            target: "hyphen::fairness",
                            "Ignoring structurally valid receipt vote for slot {} transaction {} from {} because no active finalized committee profile is configured",
                            receipt.statement.slot,
                            receipt.statement.transaction_id,
                            propagation_source
                        );
                    }
                    hyphen_network::NetworkMessage::QuorumInclusionReceipt(receipt) => {
                        warn!(
                            target: "hyphen::fairness",
                            "Ignoring structurally valid quorum receipt for slot {} transaction {} from {} because no active finalized committee profile is configured",
                            receipt.receipt.statement.slot,
                            receipt.receipt.statement.transaction_id,
                            propagation_source
                        );
                    }
                }
            }
        }
        HyphenBehaviourEvent::RequestResponse(request_response::Event::Message {
            peer,
            message,
            ..
        }) => match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                let response = handle_sync_request(&request, blockchain);
                let _ = network
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, response);
            }
            request_response::Message::Response { response, .. } => {
                handle_sync_response(response, blockchain, &peer, network);
            }
        },
        HyphenBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
            for addr in info.listen_addrs {
                network
                    .swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, addr);
            }
        }
        _ => {}
    }
}

fn handle_sync_request(
    request: &hyphen_network::SyncRequest,
    blockchain: &Arc<Blockchain>,
) -> hyphen_network::SyncResponse {
    use hyphen_network::{SyncRequest, SyncResponse};
    if let Err(error) = request.validate() {
        return SyncResponse::Error(error.to_string());
    }
    match request {
        SyncRequest::GetTip => match blockchain.tip() {
            Ok(tip) => SyncResponse::Tip {
                height: tip.height,
                hash: *tip.hash.as_bytes(),
                cumulative_difficulty: tip.cumulative_difficulty,
            },
            Err(e) => SyncResponse::Error(e.to_string()),
        },
        SyncRequest::GetBlocks {
            start_height,
            count,
        } => {
            let mut blocks = Vec::new();
            let Some(end_height) = start_height.checked_add(*count as u64) else {
                return SyncResponse::Error("requested height range overflows".into());
            };
            for h in *start_height..end_height {
                match blockchain.blocks.get_block_by_height(h) {
                    Ok(block) => {
                        if let Ok(data) = hyphen_codec::serialize(&block) {
                            blocks.push(data);
                        }
                    }
                    Err(_) => break,
                }
            }
            SyncResponse::Blocks(blocks)
        }
        SyncRequest::GetBlock { hash } => {
            let h = hyphen_crypto::Hash256::from_bytes(*hash);
            match blockchain.blocks.get_block_by_hash(&h) {
                Ok(block) => match hyphen_codec::serialize(&block) {
                    Ok(data) => SyncResponse::Block(data),
                    Err(e) => SyncResponse::Error(e.to_string()),
                },
                Err(e) => SyncResponse::Error(e.to_string()),
            }
        }
        SyncRequest::GetStateProof {
            namespace,
            root,
            key,
        } => {
            let namespace = hyphen_crypto::Hash256::from_bytes(*namespace);
            let root = hyphen_crypto::Hash256::from_bytes(*root);
            if namespace != blockchain.wes_latest.namespace() {
                return SyncResponse::Error("unknown state-proof namespace".into());
            }
            match blockchain
                .wes_latest
                .prove_at_root(hyphen_crypto::Hash256::from_bytes(*key), root)
            {
                Ok(proof) => SyncResponse::StateProof {
                    root: *root.as_bytes(),
                    proof,
                },
                Err(error) => SyncResponse::Error(error.to_string()),
            }
        }
        SyncRequest::GetBlobMetadata { object_hash } => {
            match blockchain
                .proof_blobs
                .metadata(hyphen_crypto::Hash256::from_bytes(*object_hash))
            {
                Ok(metadata) => SyncResponse::BlobMetadata(metadata),
                Err(error) => SyncResponse::Error(error.to_string()),
            }
        }
        SyncRequest::GetBlobChunk { object_hash, index } => {
            match blockchain
                .proof_blobs
                .chunk_proof(hyphen_crypto::Hash256::from_bytes(*object_hash), *index)
            {
                Ok(proof) => SyncResponse::BlobChunk(proof),
                Err(error) => SyncResponse::Error(error.to_string()),
            }
        }
    }
}

fn handle_sync_response(
    response: hyphen_network::SyncResponse,
    blockchain: &Arc<Blockchain>,
    peer: &libp2p::PeerId,
    network: &mut hyphen_network::HyphenNetwork,
) {
    use hyphen_network::SyncResponse;
    if let Err(error) = response.validate() {
        warn!("Invalid sync response from {peer}: {error}");
        return;
    }
    match response {
        SyncResponse::Blocks(blocks) => {
            let count = blocks.len();
            let mut accepted = 0u64;
            for block_data in blocks {
                if let Ok(block) = hyphen_core::Block::deserialise_limited(
                    &block_data,
                    blockchain.cfg.max_block_size,
                ) {
                    match blockchain.accept_block(&block) {
                        Ok(()) => accepted += 1,
                        Err(e) => {
                            warn!("Synced block rejected: {e}");
                            break;
                        }
                    }
                }
            }
            info!("Sync from {peer}: accepted {accepted}/{count} blocks");
        }
        SyncResponse::Block(data) => {
            if let Ok(block) =
                hyphen_core::Block::deserialise_limited(&data, blockchain.cfg.max_block_size)
            {
                if let Err(e) = blockchain.accept_block(&block) {
                    warn!("Synced block rejected: {e}");
                }
            }
        }
        SyncResponse::Tip {
            height,
            cumulative_difficulty,
            ..
        } => {
            let local_tip = match blockchain.tip() {
                Ok(t) => t,
                Err(_) => return,
            };
            if height > local_tip.height && cumulative_difficulty > local_tip.cumulative_difficulty
            {
                let gap = height - local_tip.height;
                info!(
                    "Remote peer {peer} at height {height} (local {}), syncing {gap} blocks",
                    local_tip.height
                );
                let batch = gap.min(500) as u32;
                network.send_sync_request(
                    peer,
                    hyphen_network::SyncRequest::GetBlocks {
                        start_height: local_tip.height + 1,
                        count: batch,
                    },
                );
            } else {
                info!(
                    "Remote {peer} at height {height}, local at {} – in sync",
                    local_tip.height
                );
            }
        }
        SyncResponse::StateProof { root, proof } => {
            info!(
                "State proof from {peer}: namespace={} root={} key={} present={}",
                proof.namespace,
                hyphen_crypto::Hash256::from_bytes(root),
                proof.key,
                proof.value.is_some()
            );
        }
        SyncResponse::BlobMetadata(metadata) => {
            info!(
                "Blob metadata from {peer}: object={} bytes={} chunks={} root={}",
                metadata.object_hash, metadata.byte_len, metadata.chunk_count, metadata.chunk_root
            );
        }
        SyncResponse::BlobChunk(proof) => {
            info!(
                "Blob chunk from {peer}: object={} index={}/{} bytes={}",
                proof.metadata.object_hash,
                proof.chunk_index,
                proof.metadata.chunk_count,
                proof.chunk.len()
            );
        }
        SyncResponse::Error(e) => {
            warn!("Sync error from {peer}: {e}");
        }
    }
}

async fn template_provider_server(
    addr: std::net::SocketAddr,
    blockchain: Arc<Blockchain>,
    mempool: Arc<RwLock<Mempool>>,
    cfg: ChainConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    info!("Template Provider server listening on {addr}");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        info!("TP client connected from {peer_addr}");
        let bc = Arc::clone(&blockchain);
        let mp = Arc::clone(&mempool);
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tp_client(stream, bc, mp, cfg).await {
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut reader, mut writer) = stream.into_split();

    let node_sk = hyphen_crypto::SecretKey::generate();

    loop {
        let env = read_envelope(&mut reader).await?;
        if !env.verify() {
            return Err("invalid or stale TP envelope signature".into());
        }

        match env.msg_type {
            TP_GET_TEMPLATE => {
                let req = hyphen_transport::TemplateRequest::decode(&env.payload[..])?;
                validate_template_request(&req, &cfg)?;
                let tpl = build_template(&blockchain, &mempool, &cfg)?;
                let resp = SignedEnvelope::sign(TP_TEMPLATE, tpl.encode_to_vec(), &node_sk);
                write_envelope(&mut writer, &resp).await?;
            }

            TP_SUBMIT_BLOCK => {
                let req = SubmitBlockRequest::decode(&env.payload[..])?;
                let result = handle_block_submission(&req.block_data, &blockchain, &mempool);
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

                let (msg_tx, mut msg_rx) = tokio::sync::mpsc::channel::<SignedEnvelope>(32);
                tokio::spawn(async move {
                    while let Ok(env) = read_envelope(&mut reader).await {
                        if msg_tx.send(env).await.is_err() {
                            break;
                        }
                    }
                });

                let mut interval = tokio::time::interval(cfg.block_time / 2);
                let mut last_tip_height = 0u64;

                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let current_height = blockchain
                                .tip()
                                .map(|t| t.height)
                                .unwrap_or(0);
                            if current_height != last_tip_height {
                                last_tip_height = current_height;
                                match build_template(&blockchain, &mempool, &cfg) {
                                    Ok(tpl) => {
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

                        msg = msg_rx.recv() => {
                            match msg {
                                Some(incoming) => {
                                    if !incoming.verify() {
                                        return Err("invalid or stale subscribed TP envelope".into());
                                    }
                                    match incoming.msg_type {
                                    TP_SUBMIT_BLOCK => {
                                        let req = SubmitBlockRequest::decode(
                                            &incoming.payload[..],
                                        )?;
                                        let result = handle_block_submission(
                                            &req.block_data,
                                            &blockchain,
                                            &mempool,
                                        );
                                        let resp_env = SignedEnvelope::sign(
                                            TP_SUBMIT_RESULT,
                                            result.encode_to_vec(),
                                            &node_sk,
                                        );
                                        write_envelope(&mut writer, &resp_env)
                                            .await?;

                                        if result.accepted {
                                            if let Ok(tpl) = build_template(
                                                &blockchain,
                                                &mempool,
                                                &cfg,
                                            ) {
                                                last_tip_height =
                                                    tpl.height.saturating_sub(1);
                                                let env = SignedEnvelope::sign(
                                                    TP_TEMPLATE,
                                                    tpl.encode_to_vec(),
                                                    &node_sk,
                                                );
                                                let _ = write_envelope(
                                                    &mut writer,
                                                    &env,
                                                )
                                                .await;
                                            }
                                        }
                                    }

                                    TP_DECLARE_JOB => {
                                        let req = DeclareJobRequest::decode(
                                            &incoming.payload[..],
                                        )?;
                                        let result = handle_job_declaration(
                                            &req,
                                            &blockchain,
                                            &mempool,
                                            &cfg,
                                        );
                                        let resp_env = SignedEnvelope::sign(
                                            TP_DECLARE_JOB_RESULT,
                                            result.encode_to_vec(),
                                            &node_sk,
                                        );
                                        write_envelope(&mut writer, &resp_env)
                                            .await?;
                                    }

                                    TP_GET_TEMPLATE => {
                                        let tpl = build_template(
                                            &blockchain,
                                            &mempool,
                                            &cfg,
                                        )?;
                                        let resp = SignedEnvelope::sign(
                                            TP_TEMPLATE,
                                            tpl.encode_to_vec(),
                                            &node_sk,
                                        );
                                        write_envelope(&mut writer, &resp).await?;
                                    }

                                    other => {
                                        warn!(
                                            "Unknown TP msg during subscribe: \
                                             {other}"
                                        );
                                    }
                                    }
                                },
                                None => return Ok(()),
                            }
                        }
                    }
                }
            }

            TP_DECLARE_JOB => {
                let req = DeclareJobRequest::decode(&env.payload[..])?;
                let result = handle_job_declaration(&req, &blockchain, &mempool, &cfg);
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
    if request.protocol_version != 2 {
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

fn build_template(
    blockchain: &Arc<Blockchain>,
    mempool: &Arc<RwLock<Mempool>>,
    cfg: &ChainConfig,
) -> Result<BlockTemplate, Box<dyn std::error::Error + Send + Sync>> {
    let tip = blockchain.tip()?;
    let next_height = tip.height + 1;
    let difficulty = blockchain.next_difficulty()?;
    let epoch_seed = blockchain.epoch_seed_for_height(next_height)?;

    let mut tx_blobs: Vec<Vec<u8>> = {
        let pool = mempool.read();
        pool.get_block_candidates(cfg.max_block_size)
            .iter()
            .filter_map(|tx| hyphen_codec::serialize(tx).ok())
            .collect()
    };
    tx_blobs.sort_unstable_by_key(|transaction| hyphen_crypto::blake3_hash(transaction));

    let commitment_root = blockchain.commitment_tree.read().root();
    let nullifier_root = blockchain.nullifiers.root_hash().unwrap_or_default();

    let reward = hyphen_economics::emission::block_reward(next_height, cfg);

    // Compute the total fee from all included transactions
    let total_fee: u64 = tx_blobs
        .iter()
        .filter_map(|blob| hyphen_tx::Transaction::deserialise_limited(blob).ok())
        .map(|tx| tx.fee)
        .sum();

    // Compute the tx_root from the transaction blobs (Merkle root of blake3 hashes)
    let tx_root = {
        let leaf_hashes: Vec<hyphen_crypto::Hash256> = tx_blobs
            .iter()
            .map(|blob| hyphen_crypto::blake3_hash(blob))
            .collect();
        hyphen_core::block::merkle_root(&leaf_hashes)
    };

    let header = hyphen_core::BlockHeader {
        version: hyphen_core::FROZEN_BLOCK_VERSION,
        height: next_height,
        timestamp: ntp_adjusted_timestamp_ms(),
        prev_hash: tip.hash,
        tx_root,
        commitment_root,
        nullifier_root,
        state_root: hyphen_crypto::Hash256::ZERO,
        receipt_root: hyphen_crypto::Hash256::ZERO,
        uncle_root: hyphen_crypto::Hash256::ZERO,
        pow_commitment: hyphen_crypto::blake3_hash(epoch_seed.as_bytes()),
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

    let header_data = hyphen_codec::serialize(&header)?;
    let template_id = hyphen_crypto::blake3_hash_many(&[
        &next_height.to_le_bytes(),
        &difficulty.to_le_bytes(),
        tip.hash.as_bytes(),
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
        prev_hash: tip.hash.as_bytes().to_vec(),
        arena_size: cfg.arena_size as u64,
        page_size: cfg.page_size as u64,
        clean: true,
        network_magic: cfg.network_magic.to_vec(),
        protocol_version: 2,
        consensus_params_hash: cfg.consensus_params_hash().to_vec(),
        genesis_hash: build_genesis_block(cfg).hash().as_bytes().to_vec(),
    })
}

fn handle_block_submission(
    block_data: &[u8],
    blockchain: &Arc<Blockchain>,
    mempool: &Arc<RwLock<Mempool>>,
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

    match blockchain.accept_block(&block) {
        Ok(()) => {
            info!("TP: block {} accepted", block_hash);

            let key_images: Vec<[u8; 32]> = block
                .transactions
                .iter()
                .filter_map(|blob| hyphen_tx::Transaction::deserialise_limited(blob).ok())
                .flat_map(|tx| tx.inputs.iter().map(|i| i.key_image).collect::<Vec<_>>())
                .collect();
            mempool.write().purge_confirmed(&key_images);

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
    req: &DeclareJobRequest,
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
    if req.coinbase_script.len() > 4 * 1024 {
        return reject("coinbase script exceeds 4 KiB".into());
    }
    if req.custom_transactions.len() > 10_000 {
        return reject("transaction count exceeds declaration limit".into());
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
        match hyphen_codec::deserialize_with_limit(&base_template.header_data, 4096) {
            Ok(header) => header,
            Err(error) => return reject(format!("base header: {error}")),
        };
    let total_fee = match blockchain
        .validate_transaction_blobs_for_height(&req.custom_transactions, header.height)
    {
        Ok(total_fee) => total_fee,
        Err(error) => return reject(format!("candidate validation: {error}")),
    };
    let custom_block = hyphen_core::Block {
        header: header.clone(),
        transactions: req.custom_transactions.clone(),
        uncle_headers: Vec::new(),
        block_authorization: Vec::new(),
    };
    header.tx_root = custom_block.compute_tx_root();
    header.total_fee = total_fee;

    let job_id = hyphen_crypto::blake3_hash_many(&[
        b"Hyphen/TP/DeclaredJob/v1",
        &req.template_id,
        &req.coinbase_script,
        header.tx_root.as_bytes(),
        &total_fee.to_le_bytes(),
    ]);
    let header_data = match hyphen_codec::serialize(&header) {
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
