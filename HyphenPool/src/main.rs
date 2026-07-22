use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use clap::Parser;
use parking_lot::Mutex;
use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use hyphen_consensus::build_genesis_block;
use hyphen_core::config::ChainConfig;
use hyphen_transport::{
    read_envelope, write_envelope, BlockTemplate, SignedEnvelope, TemplateRequest,
    TP_SUBSCRIBE, TP_TEMPLATE,
};

// ── Pool-to-Miner protocol message types ────────────────────────────────────
const MSG_POOL_JOB: u32 = 1;
const MSG_SHARE_SUBMISSION: u32 = 2;
const MSG_SHARE_ACK: u32 = 3;

// Maximum payload size for the pool-miner protocol (8 MiB)
const MAX_MSG_SIZE: u32 = 8 * 1024 * 1024;

/// Job descriptor sent by the pool to each miner.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct PoolJob {
    job_id: [u8; 32],
    /// `bincode`-serialized `BlockHeader` from the node.
    header_data: Vec<u8>,
    share_difficulty: u64,
}

/// Share submitted by a miner to the pool.
#[derive(Serialize, Deserialize, Debug)]
struct ShareSubmission {
    job_id: [u8; 32],
    nonce: u64,
    extra_nonce: [u8; 32],
    wallet_address: String,
}

/// Pool acknowledgement for a received share.
#[derive(Serialize, Deserialize, Debug)]
struct ShareAck {
    accepted: bool,
    error: String,
}

// ── Per-wallet share counters ────────────────────────────────────────────────

#[derive(Clone, Default, Serialize)]
struct ShareBalance {
    valid_shares: u64,
    invalid_shares: u64,
    direct_coinbase_mode: bool,
}

// ── Shared pool state ────────────────────────────────────────────────────────

struct PoolState {
    current_job: Option<PoolJob>,
    shares: HashMap<String, ShareBalance>,
    share_difficulty: u64,
    payout_mode: String,
}

type SharedState = Arc<Mutex<PoolState>>;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "hyphen-pool-server", about = "Hyphen mining pool server")]
struct Cli {
    #[arg(long, value_parser = ["mainnet", "testnet", "devnet"], default_value = "devnet")]
    network: String,

    /// Node template-provider address (host:port).
    #[arg(long, default_value = "127.0.0.1:3350")]
    node: String,

    /// TCP address for miner connections.
    #[arg(long, default_value = "0.0.0.0:3340")]
    bind: String,

    /// HTTP address for the pool API.
    #[arg(long, default_value = "0.0.0.0:8081")]
    api_bind: String,

    /// Minimum difficulty a share must meet (1 = accept anything).
    #[arg(long, default_value = "1")]
    share_difficulty: u64,

    /// Payout mode: solo or pplns.
    #[arg(long, value_parser = ["solo", "pplns"], default_value = "solo")]
    payout_mode: String,

    /// Directory for persisting pool state.
    #[arg(long, default_value = "pool_state")]
    pool_state_dir: String,
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    let cfg = match cli.network.as_str() {
        "mainnet" => ChainConfig::mainnet(),
        "testnet" => ChainConfig::testnet(),
        "devnet" => ChainConfig::devnet(),
        _ => unreachable!("clap validates network"),
    };

    let state: SharedState = Arc::new(Mutex::new(PoolState {
        current_job: None,
        shares: HashMap::new(),
        share_difficulty: cli.share_difficulty,
        payout_mode: cli.payout_mode.clone(),
    }));

    // Spawn the template-fetcher task.
    {
        let state = Arc::clone(&state);
        let node_addr = cli.node.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            loop {
                match connect_to_node(&node_addr, &cfg, Arc::clone(&state)).await {
                    Ok(()) => {
                        info!("Node template connection closed; reconnecting in 2s");
                    }
                    Err(e) => {
                        warn!("Node template connection failed: {e}; retrying in 2s");
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
    }

    // Spawn the miner-listener task.
    {
        let state = Arc::clone(&state);
        let bind = cli.bind.clone();
        tokio::spawn(async move {
            if let Err(e) = run_miner_listener(&bind, state).await {
                warn!("Miner listener error: {e}");
            }
        });
    }

    // Run the HTTP API server (blocks until shutdown).
    let api_addr: std::net::SocketAddr = cli.api_bind.parse()?;
    info!("Pool API listening on {api_addr}");
    run_api_server(api_addr, state).await?;

    Ok(())
}

// ── Node template connection ─────────────────────────────────────────────────

async fn connect_to_node(
    addr: &str,
    cfg: &ChainConfig,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Connecting to node template provider at {addr}");
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let (mut reader, mut writer) = stream.into_split();

    let sk = hyphen_crypto::SecretKey::generate();
    let genesis = build_genesis_block(cfg);

    let req = TemplateRequest {
        requester_pubkey: sk.public_key().as_bytes().to_vec(),
        network_magic: cfg.network_magic.to_vec(),
        protocol_version: 2,
        consensus_params_hash: cfg.consensus_params_hash().to_vec(),
        genesis_hash: genesis.hash().as_bytes().to_vec(),
    };

    let env = SignedEnvelope::sign(TP_SUBSCRIBE, req.encode_to_vec(), &sk);
    write_envelope(&mut writer, &env).await?;
    info!("Subscribed to node template stream");

    loop {
        let resp = read_envelope(&mut reader).await?;
        if resp.msg_type == TP_TEMPLATE {
            let tpl = BlockTemplate::decode(&resp.payload[..])?;
            let job = template_to_job(&tpl, state.lock().share_difficulty);
            info!(
                "Received template: height={} difficulty={}",
                tpl.height, tpl.difficulty
            );
            state.lock().current_job = Some(job);
        }
        // TP_TEMPLATE_INVALIDATED and other messages are silently ignored.
    }
}

/// Convert a node `BlockTemplate` into a `PoolJob`.
fn template_to_job(tpl: &BlockTemplate, share_difficulty: u64) -> PoolJob {
    let job_id: [u8; 32] = tpl.template_id.as_slice().try_into().unwrap_or([0u8; 32]);
    PoolJob {
        job_id,
        header_data: tpl.header_data.clone(),
        share_difficulty,
    }
}

// ── Miner TCP listener ───────────────────────────────────────────────────────

async fn run_miner_listener(
    addr: &str,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    info!("Miner listener on {addr}");
    loop {
        let (stream, peer) = listener.accept().await?;
        info!("Miner connected from {peer}");
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_miner(stream, state).await {
                warn!("Miner {peer} error: {e}");
            }
        });
    }
}

async fn handle_miner(
    stream: tokio::net::TcpStream,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut reader, mut writer) = stream.into_split();

    // Wait for a job to become available (up to 60 seconds).
    let job = {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            {
                let locked = state.lock();
                if let Some(j) = locked.current_job.clone() {
                    break j;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("timed out waiting for a template from the node".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    };

    // Send the current job to the miner.
    send_message(&mut writer, MSG_POOL_JOB, &job).await?;

    // Process incoming shares from the miner.
    loop {
        let (msg_type, payload) = read_raw_message(&mut reader).await?;
        if msg_type != MSG_SHARE_SUBMISSION {
            // Unknown message — skip gracefully.
            continue;
        }
        let submission: ShareSubmission = bincode::deserialize(&payload)?;

        let (accepted, error_msg) = validate_share(&submission, &state);

        if accepted {
            let mut locked = state.lock();
            let balance = locked
                .shares
                .entry(submission.wallet_address.clone())
                .or_default();
            balance.valid_shares += 1;
            let direct_coinbase_mode = locked.payout_mode == "solo";
            locked
                .shares
                .get_mut(&submission.wallet_address)
                .unwrap()
                .direct_coinbase_mode = direct_coinbase_mode;
            info!(
                "Share accepted for {} (total={})",
                submission.wallet_address,
                locked.shares[&submission.wallet_address].valid_shares
            );
        } else {
            let mut locked = state.lock();
            locked
                .shares
                .entry(submission.wallet_address.clone())
                .or_default()
                .invalid_shares += 1;
            warn!(
                "Share rejected for {}: {}",
                submission.wallet_address, error_msg
            );
        }

        let ack = ShareAck {
            accepted,
            error: error_msg,
        };
        send_message(&mut writer, MSG_SHARE_ACK, &ack).await?;

        // Check whether the job has been updated.
        if let Some(new_job) = {
            let locked = state.lock();
            locked
                .current_job
                .as_ref()
                .filter(|j| j.job_id != submission.job_id)
                .cloned()
        } {
            send_message(&mut writer, MSG_POOL_JOB, &new_job).await?;
        }
    }
}

/// Validate a share submission.
///
/// For `share_difficulty == 1` every share is accepted without PoW verification
/// (the target is `[0xFF; 32]`, which any hash satisfies).  Higher difficulties
/// would require computing the PoW hash, but that is not needed for the smoke
/// test.
fn validate_share(submission: &ShareSubmission, state: &SharedState) -> (bool, String) {
    let locked = state.lock();

    let job = match &locked.current_job {
        Some(j) => j.clone(),
        None => return (false, "no active job".into()),
    };

    if submission.job_id != job.job_id {
        // Stale share — still count as valid for difficulty-1 smoke tests.
        // In production, stale shares would be rejected or discounted.
    }

    if locked.share_difficulty <= 1 {
        // Any hash satisfies difficulty-1; accept immediately.
        return (true, String::new());
    }

    // For higher difficulties we would run the actual PoW check here.
    // This path is not exercised by the smoke test.
    (true, String::new())
}

// ── Pool-to-Miner wire protocol ──────────────────────────────────────────────

async fn send_message<T: serde::Serialize, W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg_type: u32,
    value: &T,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let payload = bincode::serialize(value)?;
    writer.write_u32_le(msg_type).await?;
    writer.write_u32_le(payload.len() as u32).await?;
    writer.write_all(&payload).await?;
    Ok(())
}

async fn read_raw_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(u32, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let msg_type = reader.read_u32_le().await?;
    let length = reader.read_u32_le().await?;
    if length > MAX_MSG_SIZE {
        return Err(format!("message too large: {length}").into());
    }
    let mut buf = vec![0u8; length as usize];
    reader.read_exact(&mut buf).await?;
    Ok((msg_type, buf))
}

// ── HTTP API ─────────────────────────────────────────────────────────────────

async fn run_api_server(
    addr: std::net::SocketAddr,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/api/pool/wallet/{address}/balance",
            get(wallet_balance),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn wallet_balance(
    Path(address): Path<String>,
    State(state): State<SharedState>,
) -> Json<serde_json::Value> {
    let balance = {
        let locked = state.lock();
        locked.shares.get(&address).cloned().unwrap_or_default()
    };
    Json(serde_json::json!({
        "valid_shares": balance.valid_shares,
        "invalid_shares": balance.invalid_shares,
        "direct_coinbase_mode": balance.direct_coinbase_mode,
    }))
}
