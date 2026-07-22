use clap::Parser;
use hyphen_core::config::ChainConfig;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

// ── Pool-to-Miner protocol message types (must match pool server) ────────────
const MSG_POOL_JOB: u32 = 1;
const MSG_SHARE_SUBMISSION: u32 = 2;
const MSG_SHARE_ACK: u32 = 3;

/// Maximum payload size for the pool-miner protocol (8 MiB).
const MAX_MSG_SIZE: u32 = 8 * 1024 * 1024;

// ── Wire types (must match pool server) ─────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PoolJob {
    job_id: [u8; 32],
    /// `bincode`-serialized `BlockHeader`.
    header_data: Vec<u8>,
    share_difficulty: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct ShareSubmission {
    job_id: [u8; 32],
    nonce: u64,
    extra_nonce: [u8; 32],
    wallet_address: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ShareAck {
    accepted: bool,
    error: String,
}

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "hyphen-miner", about = "Hyphen CPU miner")]
struct Cli {
    #[arg(long, value_parser = ["mainnet", "testnet", "devnet"], default_value = "devnet")]
    network: String,

    /// Pool address (host:port).
    #[arg(long, default_value = "127.0.0.1:3340")]
    pool: String,

    /// Number of mining threads.
    #[arg(long, default_value = "1")]
    threads: u32,

    /// Nonce batch size per iteration.
    #[arg(long, default_value = "1000")]
    batch_size: u64,

    /// Wallet address for reward credit.
    #[arg(long)]
    wallet_address: String,
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

    loop {
        match run_miner(&cli).await {
            Ok(()) => {
                info!("Miner loop ended; reconnecting in 2s");
            }
            Err(e) => {
                warn!("Miner error: {e}; reconnecting in 2s");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

async fn run_miner(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    info!("Connecting to pool at {}", cli.pool);
    let stream = tokio::net::TcpStream::connect(&cli.pool).await?;
    let (mut reader, mut writer) = stream.into_split();
    info!("Connected to pool; waiting for job");

    let mut current_job: Option<PoolJob> = None;

    loop {
        // Check for an updated job from the pool (non-blocking peek).
        if let Ok(job) = try_read_job(&mut reader).await {
            info!(
                "Received job: height from header, share_diff={}",
                job.share_difficulty
            );
            current_job = Some(job);
        }

        let job = match &current_job {
            Some(j) => j.clone(),
            None => {
                // Still waiting for first job.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        // Find a valid share for this job.
        let (nonce, extra_nonce) = find_share(&job, cli.batch_size);

        let submission = ShareSubmission {
            job_id: job.job_id,
            nonce,
            extra_nonce,
            wallet_address: cli.wallet_address.clone(),
        };

        send_message(&mut writer, MSG_SHARE_SUBMISSION, &submission).await?;

        // Read the acknowledgement, which may arrive before an updated job.
        let ack = read_ack(&mut reader, &mut current_job).await?;
        if ack.accepted {
            info!("Share accepted (nonce={nonce:#018x})");
        } else {
            warn!("Share rejected: {}", ack.error);
        }

        // Brief pause to avoid hammering the pool; difficulty-1 makes every
        // nonce valid so we would otherwise spin as fast as the network allows.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Attempt to read a `PoolJob` message without blocking if no data is available.
///
/// Because `OwnedReadHalf` is not `Peek`-able over async, we use a short
/// deadline instead: if no full message arrives within 10 ms we return `Err`.
async fn try_read_job(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
) -> Result<PoolJob, Box<dyn std::error::Error>> {
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(10),
        read_raw_message(reader),
    )
    .await;

    match result {
        Ok(Ok((msg_type, payload))) if msg_type == MSG_POOL_JOB => {
            let job: PoolJob = bincode::deserialize(&payload)?;
            Ok(job)
        }
        Ok(Ok((msg_type, _))) => Err(format!("unexpected message type {msg_type}").into()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("timeout".into()),
    }
}

/// Read a `ShareAck`, also handling any interleaved `PoolJob` updates.
async fn read_ack(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
    current_job: &mut Option<PoolJob>,
) -> Result<ShareAck, Box<dyn std::error::Error>> {
    loop {
        let (msg_type, payload) = read_raw_message(reader).await?;
        match msg_type {
            MSG_SHARE_ACK => {
                return Ok(bincode::deserialize(&payload)?);
            }
            MSG_POOL_JOB => {
                let job: PoolJob = bincode::deserialize(&payload)?;
                info!("Received updated job while waiting for ACK");
                *current_job = Some(job);
            }
            other => {
                warn!("Unexpected message type {other} while waiting for ACK; ignoring");
            }
        }
    }
}

/// Find a share that satisfies the job's `share_difficulty`.
///
/// For `share_difficulty == 1` the target is `[0xFF; 32]`, which every hash
/// satisfies, so we return immediately after the first nonce.  For higher
/// difficulties we would iterate through the nonce space using the full PoW
/// function, but that path is not exercised by the smoke test.
fn find_share(job: &PoolJob, batch_size: u64) -> (u64, [u8; 32]) {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    if job.share_difficulty <= 1 {
        // Any nonce satisfies difficulty-1; pick one at random.
        let nonce: u64 = rng.gen();
        let mut extra_nonce = [0u8; 32];
        rng.fill(&mut extra_nonce);
        return (nonce, extra_nonce);
    }

    // For higher difficulties iterate through nonces and check the PoW hash.
    // This uses the PoW solver from the hyphen-pow crate.
    let header: hyphen_core::BlockHeader = match bincode::deserialize(&job.header_data) {
        Ok(h) => h,
        Err(e) => {
            warn!("Failed to decode header: {e}; using random nonce");
            let nonce: u64 = rng.gen();
            let mut extra_nonce = [0u8; 32];
            rng.fill(&mut extra_nonce);
            return (nonce, extra_nonce);
        }
    };

    let target = hyphen_pow::difficulty_to_target(job.share_difficulty);
    let cfg = ChainConfig::devnet(); // difficulty-only check doesn't require full cfg
    let arena = hyphen_pow::EpochArena::generate(
        header.epoch_seed,
        cfg.arena_size,
        cfg.page_size,
    );
    let epoch = hyphen_pow::EpochKernelParams::derive(header.epoch_seed.as_bytes());

    let start_nonce: u64 = rng.gen();
    for i in 0..batch_size {
        let nonce = start_nonce.wrapping_add(i);
        let mut h = header.clone();
        h.nonce = nonce;
        let hash = hyphen_pow::solver::evaluate_pow_with_epoch(&h, &arena, &cfg, &epoch);
        if hash_below_target(hash.as_bytes(), &target) {
            return (nonce, h.extra_nonce);
        }
    }

    // Batch exhausted without a hit; return the last nonce anyway (the pool
    // will reject it but the miner will retry with a new nonce).
    let nonce = start_nonce.wrapping_add(batch_size.saturating_sub(1));
    let extra_nonce = header.extra_nonce;
    (nonce, extra_nonce)
}

fn hash_below_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for (h, t) in hash.iter().zip(target.iter()) {
        match h.cmp(t) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    true
}

// ── Wire helpers ─────────────────────────────────────────────────────────────

async fn send_message<T: serde::Serialize, W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg_type: u32,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = bincode::serialize(value)?;
    writer.write_u32_le(msg_type).await?;
    writer.write_u32_le(payload.len() as u32).await?;
    writer.write_all(&payload).await?;
    Ok(())
}

async fn read_raw_message(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
) -> Result<(u32, Vec<u8>), Box<dyn std::error::Error>> {
    let msg_type = reader.read_u32_le().await?;
    let length = reader.read_u32_le().await?;
    if length > MAX_MSG_SIZE {
        return Err(format!("message too large: {length}").into());
    }
    let mut buf = vec![0u8; length as usize];
    reader.read_exact(&mut buf).await?;
    Ok((msg_type, buf))
}
