use libp2p::{gossipsub, identify, request_response};

use clap::Parser;
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, warn};

use hyphen_consensus::Blockchain;
use hyphen_core::config::ChainConfig;
use hyphen_mempool::Mempool;

#[derive(Parser, Debug)]
#[command(name = "hyphen-node", about = "Hyphen blockchain full node")]
struct Cli {
    #[arg(long, default_value = "hyphen_data")]
    data_dir: String,

    #[arg(long, default_value = "testnet")]
    network: String,

    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/9734")]
    listen: String,

    #[arg(long, default_value = "")]
    boot_nodes: String,

    #[arg(long)]
    mine: bool,

    #[arg(long, default_value = "1")]
    mining_threads: usize,

    #[arg(long, default_value = "")]
    miner_address: String,
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
        _ => ChainConfig::testnet(),
    };

    info!(
        "Starting Hyphen node on {} (block_time={}s, arena={}MiB)",
        cfg.network_name,
        cfg.block_time.as_secs(),
        cfg.arena_size / (1024 * 1024),
    );

    let blockchain = Arc::new(
        Blockchain::open(&cli.data_dir, cfg.clone())
            .map_err(|e| format!("Failed to open blockchain: {e}"))?,
    );

    let tip = blockchain.tip()?;
    info!(
        "Chain tip: height={}, hash={}, cum_diff={}",
        tip.height, tip.hash, tip.cumulative_difficulty
    );

    let mempool = Arc::new(RwLock::new(Mempool::new(10_000)));

    let listen_addr: libp2p::Multiaddr = cli.listen.parse()?;
    let boot_nodes = parse_boot_nodes(&cli.boot_nodes);

    let mut network = hyphen_network::HyphenNetwork::new(listen_addr, boot_nodes)?;
    info!(
        "P2P network started, local peer ID: {}",
        network.swarm.local_peer_id()
    );

    if cli.mine {
        let bc = Arc::clone(&blockchain);
        let mp = Arc::clone(&mempool);
        let threads = if cli.mining_threads == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            cli.mining_threads
        };
        info!("Mining enabled with {threads} thread(s)");

        tokio::task::spawn_blocking(move || {
            mining_loop(bc, mp, threads);
        });
    }

    info!("Node running. Press Ctrl+C to stop.");

    loop {
        tokio::select! {
            event = network.next_event() => {
                if let Some(event) = event {
                    handle_swarm_event(event, &blockchain, &mempool, &mut network);
                }
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

fn parse_boot_nodes(s: &str) -> Vec<(libp2p::PeerId, libp2p::Multiaddr)> {
    if s.is_empty() {
        return Vec::new();
    }
    // Format: /ip4/.../tcp/.../p2p/<peer_id>
    s.split(',')
        .filter_map(|addr_str| {
            let addr: libp2p::Multiaddr = addr_str.trim().parse().ok()?;
            // Extract PeerId from the last component
            let peer_id = addr.iter().find_map(|proto| {
                if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
                    Some(peer_id)
                } else {
                    None
                }
            })?;
            Some((peer_id, addr))
        })
        .collect()
}

fn handle_swarm_event(
    event: libp2p::swarm::SwarmEvent<hyphen_network::behaviour::HyphenBehaviourEvent>,
    _blockchain: &Arc<Blockchain>,
    _mempool: &Arc<RwLock<Mempool>>,
    _network: &mut hyphen_network::HyphenNetwork,
) {
    use libp2p::swarm::SwarmEvent;
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            info!("Listening on {address}");
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            info!("Connected to {peer_id}");
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            info!("Disconnected from {peer_id}");
        }
        SwarmEvent::Behaviour(behaviour_event) => {
            handle_behaviour_event(behaviour_event, _blockchain, _mempool, _network);
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
            if let Ok(msg) = bincode::deserialize::<hyphen_network::NetworkMessage>(&message.data) {
                match msg {
                    hyphen_network::NetworkMessage::NewBlock(block_bytes) => {
                        if let Ok(block) = bincode::deserialize::<hyphen_core::Block>(&block_bytes)
                        {
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
                        if let Ok(tx) = bincode::deserialize::<hyphen_tx::Transaction>(&tx_bytes) {
                            let mut pool = mempool.write();
                            match pool.insert(tx) {
                                Ok(hash) => {
                                    info!("Added tx {hash} to mempool");
                                }
                                Err(e) => {
                                    warn!("Rejected tx: {e}");
                                }
                            }
                        }
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
                info!("Sync response from {peer}: received data");
                handle_sync_response(response, blockchain);
            }
        },
        HyphenBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
            // Add discovered addresses to Kademlia
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
            for h in *start_height..(*start_height + *count as u64) {
                match blockchain.blocks.get_block_by_height(h) {
                    Ok(block) => {
                        if let Ok(data) = bincode::serialize(&block) {
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
                Ok(block) => match bincode::serialize(&block) {
                    Ok(data) => SyncResponse::Block(data),
                    Err(e) => SyncResponse::Error(e.to_string()),
                },
                Err(e) => SyncResponse::Error(e.to_string()),
            }
        }
    }
}

fn handle_sync_response(response: hyphen_network::SyncResponse, blockchain: &Arc<Blockchain>) {
    use hyphen_network::SyncResponse;
    match response {
        SyncResponse::Blocks(blocks) => {
            for block_data in blocks {
                if let Ok(block) = bincode::deserialize::<hyphen_core::Block>(&block_data) {
                    if let Err(e) = blockchain.accept_block(&block) {
                        warn!("Synced block rejected: {e}");
                    }
                }
            }
        }
        SyncResponse::Block(data) => {
            if let Ok(block) = bincode::deserialize::<hyphen_core::Block>(&data) {
                if let Err(e) = blockchain.accept_block(&block) {
                    warn!("Synced block rejected: {e}");
                }
            }
        }
        SyncResponse::Tip { height, .. } => {
            info!("Remote tip at height {height}");
        }
        SyncResponse::Error(e) => {
            warn!("Sync error: {e}");
        }
    }
}

fn mining_loop(blockchain: Arc<Blockchain>, mempool: Arc<RwLock<Mempool>>, _threads: usize) {
    use hyphen_pow::solver::try_nonce;

    info!("Mining loop started");

    loop {
        let tip = match blockchain.tip() {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to get tip: {e}");
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        };

        let next_height = tip.height + 1;
        let difficulty = match blockchain.next_difficulty() {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to compute difficulty: {e}");
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        };

        let epoch_seed = match blockchain.epoch_seed_for_height(next_height) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to get epoch seed: {e}");
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        };

        let arena = blockchain.arena_for_epoch(epoch_seed);

        let tx_blobs: Vec<Vec<u8>> = {
            let pool = mempool.read();
            pool.get_block_candidates(blockchain.cfg.max_block_size)
                .iter()
                .filter_map(|tx| bincode::serialize(tx).ok())
                .collect()
        };

        let commitment_root = blockchain.commitment_tree.read().root();
        let nullifier_root = blockchain.nullifiers.root_hash().unwrap_or_default();

        let mut candidate = hyphen_core::BlockHeader {
            version: 1,
            height: next_height,
            timestamp: chrono::Utc::now().timestamp() as u64,
            prev_hash: tip.hash,
            tx_root: hyphen_crypto::Hash256::ZERO, // computed below
            commitment_root,
            nullifier_root,
            pow_commitment: hyphen_crypto::blake3_hash(arena.params.epoch_seed.as_bytes()),
            epoch_seed,
            difficulty,
            nonce: rand::random(),
            extra_nonce: rand::random(),
        };

        let block = hyphen_core::Block {
            header: candidate.clone(),
            transactions: tx_blobs.clone(),
        };
        candidate.tx_root = block.compute_tx_root();

        for nonce_attempt in 0..10_000u64 {
            let nonce_val = candidate.nonce.wrapping_add(nonce_attempt);
            if let Some(result) = try_nonce(
                &mut candidate,
                &arena,
                &blockchain.cfg,
                nonce_val,
            ) {
                info!(
                    "Mined block {} (nonce={}, hash={})",
                    next_height, result.nonce, result.hash
                );

                let mined_block = hyphen_core::Block {
                    header: candidate.clone(),
                    transactions: tx_blobs.clone(),
                };

                if let Err(e) = blockchain.accept_block(&mined_block) {
                    warn!("Self-mined block rejected: {e}");
                } else {
                    let key_images: Vec<[u8; 32]> = tx_blobs
                        .iter()
                        .filter_map(|blob| {
                            bincode::deserialize::<hyphen_tx::Transaction>(blob).ok()
                        })
                        .flat_map(|tx| tx.inputs.iter().map(|i| i.key_image).collect::<Vec<_>>())
                        .collect();
                    mempool.write().purge_confirmed(&key_images);
                }
                break;
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
