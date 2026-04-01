use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use hyphen_consensus::Blockchain;
use hyphen_core::block::{Block, BlockHeader};
use hyphen_core::config::ChainConfig;
use hyphen_crypto::Hash256;
use hyphen_economics::{block_reward, total_supply_at_height};

pub struct ExplorerState {
    pub blockchain: Arc<Blockchain>,
    pub cfg: ChainConfig,
    cache: RwLock<ExplorerCache>,
}

const INDEX_HTML: &str = include_str!("index.html");
const ATOMIC_UNITS: u64 = 1_000_000_000_000;

fn format_hpn(atomic: u64) -> String {
    let whole = atomic / ATOMIC_UNITS;
    let frac = atomic % ATOMIC_UNITS;
    if frac == 0 {
        format!("{whole}.000000000000")
    } else {
        format!("{whole}.{frac:012}")
    }
}

fn format_hpn_128(atomic: u128) -> String {
    let au = ATOMIC_UNITS as u128;
    let whole = atomic / au;
    let frac = atomic % au;
    if frac == 0 {
        format!("{whole}.000000000000")
    } else {
        format!("{whole}.{frac:012}")
    }
}

#[derive(Serialize)]
struct InfoResponse {
    height: u64,
    tip_hash: String,
    cumulative_difficulty: String,
    network: String,
    block_time_target_secs: u64,
    current_reward: String,
    current_reward_atomic: u64,
    total_supply: String,
    total_supply_atomic: String,
    difficulty: u64,
    epoch_length: u64,
    current_epoch: u64,
    total_outputs: u64,
}

#[derive(Serialize)]
struct BlockSummary {
    height: u64,
    hash: String,
    timestamp: u64,
    difficulty: u64,
    tx_count: usize,
    block_size: u32,
    reward: String,
    reward_atomic: u64,
    total_fee: String,
    total_fee_atomic: u64,
    miner_pubkey: String,
}

#[derive(Serialize)]
struct BlocksResponse {
    blocks: Vec<BlockSummary>,
    total_height: u64,
    page: u64,
    limit: u64,
}

#[derive(Serialize)]
struct HeaderDetail {
    version: u32,
    height: u64,
    timestamp: u64,
    prev_hash: String,
    tx_root: String,
    commitment_root: String,
    nullifier_root: String,
    state_root: String,
    receipt_root: String,
    uncle_root: String,
    pow_commitment: String,
    epoch_seed: String,
    difficulty: u64,
    nonce: u64,
    extra_nonce: String,
    miner_pubkey: String,
    total_fee: String,
    total_fee_atomic: u64,
    reward: String,
    reward_atomic: u64,
    view_tag: u8,
    block_size: u32,
}

#[derive(Serialize)]
struct BlockDetail {
    hash: String,
    header: HeaderDetail,
    tx_count: usize,
    tx_hashes: Vec<String>,
    uncle_count: usize,
    uncle_hashes: Vec<String>,
}

#[derive(Serialize)]
struct TxLocationResponse {
    tx_hash: String,
    block_hash: String,
    block_height: u64,
    index_in_block: u32,
}

#[derive(Serialize)]
struct SearchResponse {
    result_type: String,
    height: Option<u64>,
    hash: Option<String>,
}

#[derive(Serialize)]
struct MinerRewardsResponse {
    miner_pubkey: String,
    blocks_found: u64,
    total_reward: String,
    total_reward_atomic: String,
    latest_height: Option<u64>,
}

#[derive(Clone, Serialize)]
struct MinerBlockEvent {
    height: u64,
    hash: String,
    timestamp: u64,
    difficulty: u64,
    reward: String,
    reward_atomic: u64,
    total_fee: String,
    total_fee_atomic: u64,
    miner_pubkey: String,
}

#[derive(Serialize)]
struct MinerBlocksResponse {
    miner_pubkey: String,
    blocks: Vec<MinerBlockEvent>,
}

#[derive(Deserialize)]
struct MinerBlocksQuery {
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct UpdatesQuery {
    since: Option<u64>,
}

#[derive(Serialize)]
struct ExplorerUpdatesResponse {
    changed: bool,
    info: InfoResponse,
    latest_block: Option<BlockSummary>,
}

#[derive(Default)]
struct ExplorerCache {
    indexed_tip_height: Option<u64>,
    indexed_tip_hash: Option<String>,
    miner_blocks: HashMap<String, Vec<MinerBlockEvent>>,
}

impl ExplorerState {
    fn refresh_cache(&self) -> Result<(), String> {
        let tip = self.blockchain.tip().map_err(|e| e.to_string())?;
        let tip_hash = tip.hash.to_string();
        let mut cache = self.cache.write();

        let should_rebuild = match (cache.indexed_tip_height, cache.indexed_tip_hash.as_ref()) {
            (Some(indexed_height), Some(indexed_hash)) => {
                if indexed_height > tip.height {
                    true
                } else {
                    self.blockchain
                        .blocks
                        .get_block_hash_at_height(indexed_height)
                        .map(|hash| hash.to_string() != *indexed_hash)
                        .unwrap_or(true)
                }
            }
            _ => false,
        };

        if should_rebuild {
            cache.indexed_tip_height = None;
            cache.indexed_tip_hash = None;
            cache.miner_blocks.clear();
        }

        let start_height = cache
            .indexed_tip_height
            .map(|height| height + 1)
            .unwrap_or(0);
        if start_height > tip.height {
            cache.indexed_tip_height = Some(tip.height);
            cache.indexed_tip_hash = Some(tip_hash);
            return Ok(());
        }

        for height in start_height..=tip.height {
            let block = self
                .blockchain
                .blocks
                .get_block_by_height(height)
                .map_err(|e| e.to_string())?;
            let event = MinerBlockEvent {
                height,
                hash: block.hash().to_string(),
                timestamp: block.header.timestamp,
                difficulty: block.header.difficulty,
                reward: format_hpn(block.header.reward),
                reward_atomic: block.header.reward,
                total_fee: format_hpn(block.header.total_fee),
                total_fee_atomic: block.header.total_fee,
                miner_pubkey: hex::encode(block.header.miner_pubkey),
            };
            let events = cache
                .miner_blocks
                .entry(event.miner_pubkey.clone())
                .or_default();
            events.push(event);
            if events.len() > 512 {
                let overflow = events.len() - 512;
                events.drain(..overflow);
            }
        }

        cache.indexed_tip_height = Some(tip.height);
        cache.indexed_tip_hash = Some(tip_hash);
        Ok(())
    }
}

fn build_info_response(
    state: &ExplorerState,
    tip: hyphen_state::chain_state::ChainTip,
) -> InfoResponse {
    let reward = block_reward(tip.height, &state.cfg);
    let supply = total_supply_at_height(tip.height, &state.cfg);

    let difficulty = state
        .blockchain
        .blocks
        .get_block_by_height(tip.height)
        .map(|block| block.header.difficulty)
        .unwrap_or(0);

    InfoResponse {
        height: tip.height,
        tip_hash: tip.hash.to_string(),
        cumulative_difficulty: tip.cumulative_difficulty.to_string(),
        network: state.cfg.network_name.clone(),
        block_time_target_secs: state.cfg.block_time.as_secs(),
        current_reward: format_hpn(reward),
        current_reward_atomic: reward,
        total_supply: format_hpn_128(supply),
        total_supply_atomic: supply.to_string(),
        difficulty,
        epoch_length: state.cfg.epoch_length,
        current_epoch: tip.height / state.cfg.epoch_length,
        total_outputs: tip.total_outputs,
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn header_detail(h: &BlockHeader) -> HeaderDetail {
    HeaderDetail {
        version: h.version,
        height: h.height,
        timestamp: h.timestamp,
        prev_hash: h.prev_hash.to_string(),
        tx_root: h.tx_root.to_string(),
        commitment_root: h.commitment_root.to_string(),
        nullifier_root: h.nullifier_root.to_string(),
        state_root: h.state_root.to_string(),
        receipt_root: h.receipt_root.to_string(),
        uncle_root: h.uncle_root.to_string(),
        pow_commitment: h.pow_commitment.to_string(),
        epoch_seed: h.epoch_seed.to_string(),
        difficulty: h.difficulty,
        nonce: h.nonce,
        extra_nonce: hex::encode(h.extra_nonce),
        miner_pubkey: hex::encode(h.miner_pubkey),
        total_fee: format_hpn(h.total_fee),
        total_fee_atomic: h.total_fee,
        reward: format_hpn(h.reward),
        reward_atomic: h.reward,
        view_tag: h.view_tag,
        block_size: h.block_size,
    }
}

fn block_summary(block: &Block) -> BlockSummary {
    let header = &block.header;
    BlockSummary {
        height: header.height,
        hash: block.hash().to_string(),
        timestamp: header.timestamp,
        difficulty: header.difficulty,
        tx_count: block.transactions.len(),
        block_size: header.block_size,
        reward: format_hpn(header.reward),
        reward_atomic: header.reward,
        total_fee: format_hpn(header.total_fee),
        total_fee_atomic: header.total_fee,
        miner_pubkey: hex::encode(header.miner_pubkey),
    }
}

fn parse_hash(s: &str) -> Option<Hash256> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Hash256::from_bytes(arr))
}

fn error_json(status: StatusCode, msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
    )
}

async fn serve_frontend() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn get_info(State(state): State<Arc<ExplorerState>>) -> impl IntoResponse {
    let tip = match state.blockchain.tip() {
        Ok(t) => t,
        Err(e) => {
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()).into_response()
        }
    };

    (StatusCode::OK, Json(build_info_response(&state, tip))).into_response()
}

#[derive(Deserialize)]
struct BlocksQuery {
    page: Option<u64>,
    limit: Option<u64>,
}

async fn get_blocks(
    State(state): State<Arc<ExplorerState>>,
    Query(params): Query<BlocksQuery>,
) -> impl IntoResponse {
    let tip = match state.blockchain.tip() {
        Ok(t) => t,
        Err(e) => {
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()).into_response()
        }
    };

    let page = params.page.unwrap_or(0);
    let limit = params.limit.unwrap_or(20).min(100);
    let skip = page * limit;
    let mut blocks = Vec::new();

    if tip.height >= skip {
        let start_height = tip.height - skip;
        let count = limit.min(start_height + 1);

        for offset in 0..count {
            let height = start_height - offset;
            match state.blockchain.blocks.get_block_by_height(height) {
                Ok(block) => blocks.push(block_summary(&block)),
                Err(_) => break,
            }
        }
    }

    (
        StatusCode::OK,
        Json(BlocksResponse {
            blocks,
            total_height: tip.height,
            page,
            limit,
        }),
    )
        .into_response()
}

async fn get_block_handler(
    State(state): State<Arc<ExplorerState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let block = if let Ok(height) = id.parse::<u64>() {
        state.blockchain.blocks.get_block_by_height(height).ok()
    } else if let Some(hash) = parse_hash(&id) {
        state.blockchain.blocks.get_block_by_hash(&hash).ok()
    } else {
        None
    };

    let block = match block {
        Some(block) => block,
        None => {
            return error_json(StatusCode::NOT_FOUND, &format!("Block not found: {id}"))
                .into_response()
        }
    };

    let tx_hashes = block
        .transactions
        .iter()
        .map(|tx_blob| hyphen_crypto::blake3_hash(tx_blob).to_string())
        .collect();

    let uncle_hashes = block
        .uncle_headers
        .iter()
        .map(|uncle| uncle.hash().to_string())
        .collect();

    (
        StatusCode::OK,
        Json(BlockDetail {
            hash: block.hash().to_string(),
            header: header_detail(&block.header),
            tx_count: block.transactions.len(),
            tx_hashes,
            uncle_count: block.uncle_headers.len(),
            uncle_hashes,
        }),
    )
        .into_response()
}

async fn get_tx(
    State(state): State<Arc<ExplorerState>>,
    Path(hash_str): Path<String>,
) -> impl IntoResponse {
    let tx_hash = match parse_hash(&hash_str) {
        Some(hash) => hash,
        None => {
            return error_json(StatusCode::BAD_REQUEST, "Invalid transaction hash").into_response()
        }
    };

    let (block_hash, idx) = match state.blockchain.blocks.get_tx_location(&tx_hash) {
        Ok(location) => location,
        Err(_) => {
            return error_json(
                StatusCode::NOT_FOUND,
                &format!("Transaction not found: {hash_str}"),
            )
            .into_response()
        }
    };

    let block_height = match state.blockchain.blocks.get_block_by_hash(&block_hash) {
        Ok(block) => block.header.height,
        Err(_) => 0,
    };

    (
        StatusCode::OK,
        Json(TxLocationResponse {
            tx_hash: tx_hash.to_string(),
            block_hash: block_hash.to_string(),
            block_height,
            index_in_block: idx,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

async fn search_handler(
    State(state): State<Arc<ExplorerState>>,
    Query(params): Query<SearchQuery>,
) -> impl IntoResponse {
    let query = params.q.trim();

    if let Ok(height) = query.parse::<u64>() {
        if state.blockchain.blocks.get_block_by_height(height).is_ok() {
            return (
                StatusCode::OK,
                Json(SearchResponse {
                    result_type: "block".into(),
                    height: Some(height),
                    hash: None,
                }),
            )
                .into_response();
        }
    }

    if let Some(hash) = parse_hash(query) {
        if let Ok(block) = state.blockchain.blocks.get_block_by_hash(&hash) {
            return (
                StatusCode::OK,
                Json(SearchResponse {
                    result_type: "block".into(),
                    height: Some(block.header.height),
                    hash: Some(hash.to_string()),
                }),
            )
                .into_response();
        }

        if let Ok((block_hash, _)) = state.blockchain.blocks.get_tx_location(&hash) {
            return (
                StatusCode::OK,
                Json(SearchResponse {
                    result_type: "tx".into(),
                    height: None,
                    hash: Some(block_hash.to_string()),
                }),
            )
                .into_response();
        }
    }

    (
        StatusCode::OK,
        Json(SearchResponse {
            result_type: "none".into(),
            height: None,
            hash: None,
        }),
    )
        .into_response()
}

async fn get_miner_rewards(
    State(state): State<Arc<ExplorerState>>,
    Path(pubkey): Path<String>,
) -> impl IntoResponse {
    let normalized = pubkey.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return error_json(StatusCode::BAD_REQUEST, "miner pubkey must be 64 hex chars")
            .into_response();
    }

    if let Err(error) = state.refresh_cache() {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, &error).into_response();
    }

    let cache = state.cache.read();
    let events = cache.miner_blocks.get(&normalized);
    let blocks_found = events.map(|items| items.len() as u64).unwrap_or(0);
    let total_reward_atomic = events
        .map(|items| items.iter().map(|event| event.reward_atomic as u128).sum())
        .unwrap_or(0);
    let latest_height = events.and_then(|items| items.last().map(|event| event.height));

    (
        StatusCode::OK,
        Json(MinerRewardsResponse {
            miner_pubkey: normalized,
            blocks_found,
            total_reward: format_hpn_128(total_reward_atomic),
            total_reward_atomic: total_reward_atomic.to_string(),
            latest_height,
        }),
    )
        .into_response()
}

async fn get_miner_blocks(
    State(state): State<Arc<ExplorerState>>,
    Path(pubkey): Path<String>,
    Query(params): Query<MinerBlocksQuery>,
) -> impl IntoResponse {
    let normalized = pubkey.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return error_json(StatusCode::BAD_REQUEST, "miner pubkey must be 64 hex chars")
            .into_response();
    }

    if let Err(error) = state.refresh_cache() {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, &error).into_response();
    }

    let limit = params.limit.unwrap_or(16).clamp(1, 128);
    let cache = state.cache.read();
    let blocks = cache
        .miner_blocks
        .get(&normalized)
        .map(|items| items.iter().rev().take(limit).cloned().collect())
        .unwrap_or_default();

    (
        StatusCode::OK,
        Json(MinerBlocksResponse {
            miner_pubkey: normalized,
            blocks,
        }),
    )
        .into_response()
}

async fn get_updates(
    State(state): State<Arc<ExplorerState>>,
    Query(params): Query<UpdatesQuery>,
) -> impl IntoResponse {
    let tip = match state.blockchain.tip() {
        Ok(t) => t,
        Err(e) => {
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()).into_response()
        }
    };

    let latest_block = state
        .blockchain
        .blocks
        .get_block_by_height(tip.height)
        .ok()
        .map(|block| block_summary(&block));
    let changed = params.since.map(|since| since < tip.height).unwrap_or(true);

    (
        StatusCode::OK,
        Json(ExplorerUpdatesResponse {
            changed,
            info: build_info_response(&state, tip),
            latest_block,
        }),
    )
        .into_response()
}

pub fn explorer_router(blockchain: Arc<Blockchain>, cfg: ChainConfig) -> Router {
    let state = Arc::new(ExplorerState {
        blockchain,
        cfg,
        cache: RwLock::new(ExplorerCache::default()),
    });
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/", get(serve_frontend))
        .route("/api/info", get(get_info))
        .route("/api/updates", get(get_updates))
        .route("/api/blocks", get(get_blocks))
        .route("/api/block/{id}", get(get_block_handler))
        .route("/api/tx/{hash}", get(get_tx))
        .route("/api/miner/{pubkey}/rewards", get(get_miner_rewards))
        .route("/api/miner/{pubkey}/blocks", get(get_miner_blocks))
        .route("/api/search", get(search_handler))
        .layer(cors)
        .with_state(state)
}

pub async fn start_explorer(
    bind_addr: std::net::SocketAddr,
    blockchain: Arc<Blockchain>,
    cfg: ChainConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!("Block explorer listening on http://{}", bind_addr);
    axum::serve(listener, explorer_router(blockchain, cfg)).await?;
    Ok(())
}
