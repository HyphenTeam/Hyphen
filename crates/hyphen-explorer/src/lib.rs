use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use courierust::courierust_body::Body;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_http::{Method, StatusCode};
use courierust::courierust_server::{Server, ServerConfig};
use parking_lot::RwLock;
use serde::Serialize;
use tracing::{info, warn};

use hyphen_compute::{ArithmeticProfile, ScientificDomain, TaskRecord, TaskStatus};
use hyphen_consensus::Blockchain;
use hyphen_core::block::Block;
use hyphen_core::config::ChainConfig;
use hyphen_crypto::Hash256;
use hyphen_economics::{block_reward, total_supply_at_height};
use hyphen_vm::{application_manifest, AppManifest, Contract, ContractAddress};

pub struct ExplorerState {
    pub blockchain: Arc<Blockchain>,
    pub cfg: ChainConfig,
    cache: RwLock<ExplorerCache>,
}

const INDEX_HTML: &str = include_str!("index.html");
const APP_JS: &str = include_str!("app.js");
const EXPLORER_WASM: &[u8] = include_bytes!("hyphen_explorer_web.wasm");
const ATOMIC_UNITS: u64 = 1_000_000_000_000;

/// Largest request accepted. Every route is a `GET` with no body.
const MAX_REQUEST_BYTES: usize = 4 * 1024;

/// Largest header list accepted.
const MAX_HEADER_LIST: usize = 32 * 1024;

/// Absolute deadline for a complete request head.
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-connection read budget; queries never take this long, and a stalled
/// client must not hold a worker.
const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Close a parked connection after this long.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Concurrent connections kept open.
const MAX_CONNECTIONS: usize = 512;

/// Page size bounds, so a single request cannot ask the state for an unbounded
/// slice.
const PAGE_LIMIT_DEFAULT: usize = 20;
const PAGE_LIMIT_MAX: usize = 100;

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

#[derive(Serialize)]
struct ExplorerUpdatesResponse {
    changed: bool,
    info: InfoResponse,
    latest_block: Option<BlockSummary>,
}

#[derive(Serialize)]
struct ScientificTaskResponse {
    task_id: String,
    status: &'static str,
    domain: &'static str,
    arithmetic: &'static str,
    scientist: String,
    published_height: u64,
    publish_deadline: u64,
    challenge_deadline: Option<u64>,
    finalized_height: Option<u64>,
    retain_until_height: Option<u64>,
    rejected_height: Option<u64>,
    reward: String,
    reward_atomic: u64,
    max_operations: u64,
    program_hash: String,
    circuit_id: String,
    input_object_hash: String,
    input_bytes: u64,
    input_chunk_root: String,
    input_available: bool,
    output_object_hash: Option<String>,
    output_bytes: Option<u64>,
    output_chunk_root: Option<String>,
    output_available: Option<bool>,
    worker: Option<String>,
    proof_system: Option<u16>,
    trace_root: Option<String>,
    checkpoint_root: Option<String>,
    retention_providers: usize,
}

#[derive(Serialize)]
struct ScientificTasksResponse {
    tasks: Vec<ScientificTaskResponse>,
    total: usize,
    offset: usize,
    limit: usize,
}

#[derive(Serialize)]
struct ContractResponse {
    address: String,
    code_hash: String,
    deployer: String,
    deployed_height: u64,
    code_bytes: usize,
    application: Option<AppManifest>,
}

#[derive(Serialize)]
struct ContractsResponse {
    contracts: Vec<ContractResponse>,
    total: usize,
    offset: usize,
    limit: usize,
}

fn contract_response(contract: Contract) -> ContractResponse {
    let application = application_manifest(&contract.code).ok().flatten();
    ContractResponse {
        address: contract.address.to_string(),
        code_hash: contract.code_hash.to_string(),
        deployer: hyphen_crypto::hex_encode(contract.deployer),
        deployed_height: contract.deployed_height,
        code_bytes: contract.code.len(),
        application,
    }
}

fn get_contracts(state: &ExplorerState, params: &QueryParams) -> Result<Response<Body>, Rejection> {
    let offset = params.number::<usize>("offset")?.unwrap_or(0);
    let limit = params
        .number::<usize>("limit")?
        .unwrap_or(PAGE_LIMIT_DEFAULT)
        .clamp(1, PAGE_LIMIT_MAX);
    let (contracts, total) = state.blockchain.vm_contracts(offset, limit);
    Ok(json_response(
        StatusCode::OK,
        &ContractsResponse {
            contracts: contracts.into_iter().map(contract_response).collect(),
            total,
            offset,
            limit,
        },
    ))
}

fn get_contract(state: &ExplorerState, address: &str) -> Result<Response<Body>, Rejection> {
    let Some(hash) = parse_hash(address) else {
        return Err(Rejection::bad_request(
            "contract address must be 64 hex characters",
        ));
    };
    let address = ContractAddress(*hash.as_bytes());
    let Some(contract) = state.blockchain.vm_contract(address) else {
        return Ok(error_json(StatusCode::NOT_FOUND, "WASM contract not found"));
    };
    Ok(json_response(StatusCode::OK, &contract_response(contract)))
}

#[derive(Default)]
struct ExplorerCache {
    indexed_tip_height: Option<u64>,
    indexed_hash_at_tip: Option<String>,
    miner_blocks: HashMap<String, Vec<MinerBlockEvent>>,
    /// Insertion order of `miner_blocks` keys, so the oldest derived history
    /// can be dropped instead of letting a public endpoint grow this map
    /// without bound.
    miner_order: VecDeque<String>,
}

/// Distinct reward keys the explorer keeps history for.
///
/// This is derived data; a host with 2 GiB must not let a public route decide
/// how much memory the node holds, so the oldest key is evicted at the limit.
const MINER_KEY_LIMIT: usize = 4_096;

/// Blocks indexed per refresh.
///
/// A refresh reads blocks from sled, and an uncached request must never pin a
/// worker for the whole chain: on a long chain the first request would take
/// minutes and every concurrent reader would queue behind it. The index moves
/// forward in bounded batches instead and converges over a few requests.
const INDEX_BATCH_BLOCKS: u64 = 256;

/// Miner history kept per reward key.
const MINER_HISTORY_LIMIT: usize = 512;

/// Batches one request may index.
///
/// A page view must stay fast; eight batches catch up 2048 blocks per request,
/// which is enough for any chain that has been running for less than a day at
/// the devnet block time, while never pinning a worker for the whole history.
const INDEX_BATCHES_PER_REQUEST: usize = 8;

impl ExplorerState {
    /// Advances the derived index, and reports whether it is caught up.
    fn refresh_cache(&self) -> Result<(), String> {
        for _ in 0..INDEX_BATCHES_PER_REQUEST {
            if !self.refresh_cache_once()? {
                break;
            }
        }
        Ok(())
    }

    /// Indexes at most one batch. Returns `true` while blocks remain.
    fn refresh_cache_once(&self) -> Result<bool, String> {
        let tip = self.blockchain.tip().map_err(|e| e.to_string())?;
        let (start_height, stale) = {
            let cache = self.cache.read();
            match (cache.indexed_tip_height, cache.indexed_hash_at_tip.as_ref()) {
                (Some(indexed_height), Some(indexed_hash)) => {
                    let stale = indexed_height > tip.height
                        || self
                            .blockchain
                            .blocks
                            .get_block_hash_at_height(indexed_height)
                            .map(|hash| hash.to_string() != *indexed_hash)
                            .unwrap_or(true);
                    (if stale { 0 } else { indexed_height + 1 }, stale)
                }
                _ => (0, false),
            }
        };

        if stale {
            let mut cache = self.cache.write();
            cache.miner_blocks.clear();
            cache.miner_order.clear();
            cache.indexed_tip_height = None;
            cache.indexed_hash_at_tip = None;
        } else if start_height > tip.height {
            return Ok(false);
        }
        let start_height = if stale { 0 } else { start_height };

        let end_height = start_height
            .saturating_add(INDEX_BATCH_BLOCKS - 1)
            .min(tip.height);
        let mut batch = Vec::with_capacity((end_height - start_height + 1) as usize);
        for height in start_height..=end_height {
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
                miner_pubkey: hyphen_crypto::hex_encode(block.header.miner_pubkey),
            };
            let reward_key = block
                .decode_authorization()
                .map(|authorization| hyphen_crypto::hex_encode(authorization.reward_spend_public))
                .unwrap_or_else(|_| event.miner_pubkey.clone());
            batch.push((reward_key, event));
        }

        let indexed_hash = if end_height == tip.height {
            tip.hash.to_string()
        } else {
            self.blockchain
                .blocks
                .get_block_hash_at_height(end_height)
                .map(|hash| hash.to_string())
                .map_err(|e| e.to_string())?
        };

        let mut cache = self.cache.write();
        let current = cache
            .indexed_tip_height
            .map(|height| height + 1)
            .unwrap_or(0);
        if current != start_height {
            return Ok(true);
        }
        for (reward_key, event) in batch {
            if !cache.miner_blocks.contains_key(&reward_key) {
                cache.miner_order.push_back(reward_key.clone());
                while cache.miner_order.len() > MINER_KEY_LIMIT {
                    if let Some(evicted) = cache.miner_order.pop_front() {
                        cache.miner_blocks.remove(&evicted);
                    }
                }
            }
            let events = cache.miner_blocks.entry(reward_key).or_default();
            events.push(event);
            if events.len() > MINER_HISTORY_LIMIT {
                let overflow = events.len() - MINER_HISTORY_LIMIT;
                events.drain(..overflow);
            }
        }

        cache.indexed_tip_height = Some(end_height);
        cache.indexed_hash_at_tip = Some(indexed_hash);
        Ok(end_height < tip.height)
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

fn header_detail(block: &Block) -> HeaderDetail {
    let h = &block.header;
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
        extra_nonce: hyphen_crypto::hex_encode(h.extra_nonce),
        miner_pubkey: hyphen_crypto::hex_encode(h.miner_pubkey),
        total_fee: format_hpn(h.total_fee),
        total_fee_atomic: h.total_fee,
        reward: format_hpn(h.reward),
        reward_atomic: h.reward,
        view_tag: h.view_tag,
        block_size: encoded_block_size(block),
    }
}

/// Actual wire size of the block.
///
/// The header's `block_size` field is not filled in by the pool that builds
/// blocks, so reading it reported `0 bytes` for every block.
fn encoded_block_size(block: &Block) -> u32 {
    hyphen_core::wire_config(hyphen_core::DEFAULT_WIRE_BYTES)
        .serialize(block)
        .map(|bytes| bytes.len().min(u32::MAX as usize) as u32)
        .unwrap_or(block.header.block_size)
}

fn block_summary(block: &Block) -> BlockSummary {
    let header = &block.header;
    BlockSummary {
        height: header.height,
        hash: block.hash().to_string(),
        timestamp: header.timestamp,
        difficulty: header.difficulty,
        tx_count: block.transactions.len(),
        block_size: encoded_block_size(block),
        reward: format_hpn(header.reward),
        reward_atomic: header.reward,
        total_fee: format_hpn(header.total_fee),
        total_fee_atomic: header.total_fee,
        miner_pubkey: hyphen_crypto::hex_encode(header.miner_pubkey),
    }
}

fn scientific_task(task_id: Hash256, record: TaskRecord) -> ScientificTaskResponse {
    let spec = &record.task.spec;
    let domain = match spec.domain {
        ScientificDomain::QuantumChromodynamics => "QCD",
        ScientificDomain::ManifoldDynamics => "Manifold",
        ScientificDomain::Connectomics => "Connectomics",
    };
    let arithmetic = match spec.arithmetic {
        ArithmeticProfile::DeterministicFixedPointV1 => "fixed-point-v1",
    };
    let (
        status,
        result,
        challenge_deadline,
        finalized_height,
        retain_until_height,
        rejected_height,
    ) = match &record.status {
        TaskStatus::Open => ("open", None, None, None, None, None),
        TaskStatus::Submitted {
            result,
            challenge_deadline,
            ..
        } => (
            "submitted",
            Some(result),
            Some(*challenge_deadline),
            None,
            None,
            None,
        ),
        TaskStatus::Rejected {
            rejected_height, ..
        } => ("rejected", None, None, None, None, Some(*rejected_height)),
        TaskStatus::Finalized {
            result,
            finalized_height,
            retain_until_height,
        } => (
            "finalized",
            Some(result),
            None,
            Some(*finalized_height),
            Some(*retain_until_height),
            None,
        ),
    };
    let output = result.map(|signed| &signed.claim.output);

    ScientificTaskResponse {
        task_id: task_id.to_string(),
        status,
        domain,
        arithmetic,
        scientist: spec.scientist.to_string(),
        published_height: record.published_height,
        publish_deadline: spec.publish_deadline,
        challenge_deadline,
        finalized_height,
        retain_until_height,
        rejected_height,
        reward: format_hpn(spec.reward),
        reward_atomic: spec.reward,
        max_operations: spec.max_operations,
        program_hash: spec.program_hash.to_string(),
        circuit_id: spec.circuit_id.to_string(),
        input_object_hash: spec.input.object_hash.to_string(),
        input_bytes: spec.input.byte_len,
        input_chunk_root: spec.input.chunk_root.to_string(),
        input_available: !spec.input.locator.trim().is_empty(),
        output_object_hash: output.map(|value| value.object_hash.to_string()),
        output_bytes: output.map(|value| value.byte_len),
        output_chunk_root: output.map(|value| value.chunk_root.to_string()),
        output_available: output.map(|value| !value.locator.trim().is_empty()),
        worker: result.map(|signed| signed.claim.worker.to_string()),
        proof_system: result.map(|signed| signed.claim.proof_system),
        trace_root: result.map(|signed| signed.claim.trace_root.to_string()),
        checkpoint_root: result.map(|signed| signed.claim.checkpoint_root.to_string()),
        retention_providers: record.retention.len(),
    }
}

fn get_scientific_tasks(
    state: &ExplorerState,
    params: &QueryParams,
) -> Result<Response<Body>, Rejection> {
    let offset = params.number::<usize>("offset")?.unwrap_or(0);
    let limit = params
        .number::<usize>("limit")?
        .unwrap_or(PAGE_LIMIT_DEFAULT)
        .clamp(1, PAGE_LIMIT_MAX);
    let (records, total) = state.blockchain.compute_tasks(offset, limit);
    let tasks = records
        .into_iter()
        .map(|(task_id, record)| scientific_task(task_id, record))
        .collect();
    Ok(json_response(
        StatusCode::OK,
        &ScientificTasksResponse {
            tasks,
            total,
            offset,
            limit,
        },
    ))
}

fn get_scientific_task(state: &ExplorerState, task_id: &str) -> Result<Response<Body>, Rejection> {
    let Some(task_id) = parse_hash(task_id) else {
        return Err(Rejection::bad_request("task ID must be 64 hex characters"));
    };
    let Some(record) = state.blockchain.compute_task(task_id) else {
        return Ok(error_json(
            StatusCode::NOT_FOUND,
            "scientific task not found",
        ));
    };
    Ok(json_response(
        StatusCode::OK,
        &scientific_task(task_id, record),
    ))
}

fn parse_hash(s: &str) -> Option<Hash256> {
    let bytes = hyphen_crypto::hex_decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Hash256::from_bytes(arr))
}

/// A request the explorer will not serve, with what the caller should be told.
#[derive(Debug)]
struct Rejection {
    status: StatusCode,
    message: String,
}

impl Rejection {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

/// Decoded query-string parameters.
///
/// Values are percent-decoded once, on the way in, so a handler never sees an
/// escape sequence. Unknown parameters are ignored: the explorer's links carry
/// things like `#/block/7` fragments and cache-busting values, and refusing a
/// request because a client added one would be pedantry, not safety.
#[derive(Debug)]
struct QueryParams {
    pairs: Vec<(String, String)>,
}

impl QueryParams {
    fn parse(query: Option<&str>) -> Result<Self, Rejection> {
        let mut pairs = Vec::new();
        if let Some(query) = query {
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (name, value) = match pair.split_once('=') {
                    Some((name, value)) => (name, value),
                    None => (pair, ""),
                };
                pairs.push((percent_decode(name)?, percent_decode(value)?));
            }
        }
        Ok(Self { pairs })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// A required parameter, or `400`.
    fn require(&self, name: &str) -> Result<&str, Rejection> {
        self.get(name)
            .ok_or_else(|| Rejection::bad_request(format!("missing query parameter '{name}'")))
    }

    /// A numeric parameter, or `400` when it is present and not a number.
    fn number<T: std::str::FromStr>(&self, name: &str) -> Result<Option<T>, Rejection> {
        match self.get(name) {
            None => Ok(None),
            Some(value) => match value.trim().parse::<T>() {
                Ok(parsed) => Ok(Some(parsed)),
                Err(_) => Err(Rejection::bad_request(format!(
                    "query parameter '{name}' is not a number: '{value}'"
                ))),
            },
        }
    }
}

/// Decodes `%XX` escapes in a path segment or query parameter.
fn percent_decode(input: &str) -> Result<String, Rejection> {
    if !input.contains('%') {
        return Ok(input.to_string());
    }
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let escape = bytes.get(index + 1..index + 3).ok_or_else(|| {
            Rejection::bad_request("percent-encoding is truncated in the request target")
        })?;
        let text = std::str::from_utf8(escape).map_err(|_| {
            Rejection::bad_request("percent-encoding is not valid ASCII in the request target")
        })?;
        decoded.push(u8::from_str_radix(text, 16).map_err(|_| {
            Rejection::bad_request(format!("'%{text}' is not a valid percent-encoding"))
        })?);
        index += 3;
    }
    String::from_utf8(decoded)
        .map_err(|_| Rejection::bad_request("request target is not valid UTF-8 once decoded"))
}

/// Response headers every route carries.
///
/// The page, its script and its WebAssembly module are all served from this
/// origin, so the policy can stay as tight as it was: no remote scripts, no
/// framing, no referrer, and a media type that cannot be sniffed into anything
/// else. `'wasm-unsafe-eval'` is required to compile the module and permits
/// WebAssembly only, not JavaScript `eval`.
fn secure_response(
    status: StatusCode,
    content_type: &'static str,
    body: impl Into<Body>,
) -> Response<Body> {
    Response::<Body>::with_status(status)
        .header("content-type", content_type)
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .header(
            "content-security-policy",
            "default-src 'self'; connect-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        .with_body(body.into())
}

fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> Response<Body> {
    match serde_json::to_vec(payload) {
        Ok(bytes) => secure_response(status, "application/json", Body::from(bytes)),
        Err(error) => {
            warn!("Encoding an explorer payload failed: {error}");
            secure_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                Body::from(&b"{\"error\":\"internal error\"}"[..]),
            )
        }
    }
}

fn error_json(status: StatusCode, msg: &str) -> Response<Body> {
    json_response(
        status,
        &ErrorResponse {
            error: msg.to_string(),
        },
    )
}

fn serve_frontend() -> Response<Body> {
    secure_response(StatusCode::OK, "text/html; charset=utf-8", INDEX_HTML)
}

fn serve_app_js() -> Response<Body> {
    secure_response(StatusCode::OK, "text/javascript; charset=utf-8", APP_JS)
}

fn serve_wasm() -> Response<Body> {
    secure_response(StatusCode::OK, "application/wasm", EXPLORER_WASM)
}

/// Liveness only: no chain lock, no disk read. A supervisor or Cloudflare
/// health check must be able to distinguish a live HTTP stack from a stuck
/// chain without waiting on consensus state.
fn serve_health() -> Response<Body> {
    secure_response(StatusCode::OK, "text/plain; charset=utf-8", "ok\n")
}

fn get_info(state: &ExplorerState) -> Response<Body> {
    let tip = match state.blockchain.tip() {
        Ok(t) => t,
        Err(e) => {
            return error_json(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
    };
    json_response(StatusCode::OK, &build_info_response(state, tip))
}

fn get_blocks(state: &ExplorerState, params: &QueryParams) -> Result<Response<Body>, Rejection> {
    let tip = state.blockchain.tip().map_err(|error| Rejection {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: error.to_string(),
    })?;

    let page = params.number::<u64>("page")?.unwrap_or(0);
    let limit = params
        .number::<u64>("limit")?
        .unwrap_or(PAGE_LIMIT_DEFAULT as u64)
        .min(PAGE_LIMIT_MAX as u64);
    let skip = page.saturating_mul(limit);
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

    Ok(json_response(
        StatusCode::OK,
        &BlocksResponse {
            blocks,
            total_height: tip.height,
            page,
            limit,
        },
    ))
}

fn get_block_handler(state: &ExplorerState, id: &str) -> Response<Body> {
    let block = if let Ok(height) = id.parse::<u64>() {
        state.blockchain.blocks.get_block_by_height(height).ok()
    } else if let Some(hash) = parse_hash(id) {
        state.blockchain.blocks.get_block_by_hash(&hash).ok()
    } else {
        None
    };

    let block = match block {
        Some(block) => block,
        None => {
            return error_json(StatusCode::NOT_FOUND, &format!("Block not found: {id}"));
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

    json_response(
        StatusCode::OK,
        &BlockDetail {
            hash: block.hash().to_string(),
            header: header_detail(&block),
            tx_count: block.transactions.len(),
            tx_hashes,
            uncle_count: block.uncle_headers.len(),
            uncle_hashes,
        },
    )
}

fn get_tx(state: &ExplorerState, hash_str: &str) -> Response<Body> {
    let tx_hash = match parse_hash(hash_str) {
        Some(hash) => hash,
        None => {
            return error_json(StatusCode::BAD_REQUEST, "Invalid transaction hash");
        }
    };

    let (block_hash, idx) = match state.blockchain.blocks.get_tx_location(&tx_hash) {
        Ok(location) => location,
        Err(_) => {
            return error_json(
                StatusCode::NOT_FOUND,
                &format!("Transaction not found: {hash_str}"),
            );
        }
    };

    let block_height = match state.blockchain.blocks.get_block_by_hash(&block_hash) {
        Ok(block) => block.header.height,
        Err(_) => 0,
    };

    json_response(
        StatusCode::OK,
        &TxLocationResponse {
            tx_hash: tx_hash.to_string(),
            block_hash: block_hash.to_string(),
            block_height,
            index_in_block: idx,
        },
    )
}

fn search_handler(
    state: &ExplorerState,
    params: &QueryParams,
) -> Result<Response<Body>, Rejection> {
    let query = params.require("q")?.trim();

    let hit = |result_type: &'static str, height: Option<u64>, hash: Option<String>| {
        json_response(
            StatusCode::OK,
            &SearchResponse {
                result_type: result_type.to_string(),
                height,
                hash,
            },
        )
    };

    if let Ok(height) = query.parse::<u64>() {
        if state.blockchain.blocks.get_block_by_height(height).is_ok() {
            return Ok(hit("block", Some(height), None));
        }
    }

    if let Some(hash) = parse_hash(query) {
        if let Ok(block) = state.blockchain.blocks.get_block_by_hash(&hash) {
            return Ok(hit(
                "block",
                Some(block.header.height),
                Some(hash.to_string()),
            ));
        }

        if state.blockchain.blocks.get_tx_location(&hash).is_ok() {
            return Ok(hit("tx", None, Some(hash.to_string())));
        }

        if state.blockchain.compute_task(hash).is_some() {
            return Ok(hit("science_task", None, Some(hash.to_string())));
        }

        if state
            .blockchain
            .vm_contract(ContractAddress(*hash.as_bytes()))
            .is_some()
        {
            return Ok(hit("app", None, Some(hash.to_string())));
        }
    }

    Ok(hit("none", None, None))
}

fn get_miner_rewards(state: &ExplorerState, pubkey: &str) -> Result<Response<Body>, Rejection> {
    let normalized = normalized_pubkey(pubkey)?;
    state.refresh_cache().map_err(|error| Rejection {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: error,
    })?;

    let cache = state.cache.read();
    let events = cache.miner_blocks.get(&normalized);
    let blocks_found = events.map(|items| items.len() as u64).unwrap_or(0);
    let total_reward_atomic = events
        .map(|items| items.iter().map(|event| event.reward_atomic as u128).sum())
        .unwrap_or(0);
    let latest_height = events.and_then(|items| items.last().map(|event| event.height));

    Ok(json_response(
        StatusCode::OK,
        &MinerRewardsResponse {
            miner_pubkey: normalized,
            blocks_found,
            total_reward: format_hpn_128(total_reward_atomic),
            total_reward_atomic: total_reward_atomic.to_string(),
            latest_height,
        },
    ))
}

fn get_miner_blocks(
    state: &ExplorerState,
    pubkey: &str,
    params: &QueryParams,
) -> Result<Response<Body>, Rejection> {
    let normalized = normalized_pubkey(pubkey)?;
    state.refresh_cache().map_err(|error| Rejection {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: error,
    })?;

    let limit = params.number::<usize>("limit")?.unwrap_or(16).clamp(1, 128);
    let cache = state.cache.read();
    let blocks = cache
        .miner_blocks
        .get(&normalized)
        .map(|items| items.iter().rev().take(limit).cloned().collect())
        .unwrap_or_default();

    Ok(json_response(
        StatusCode::OK,
        &MinerBlocksResponse {
            miner_pubkey: normalized,
            blocks,
        },
    ))
}

/// A miner pubkey must be exactly 32 bytes of hex, in lowercase for the cache.
fn normalized_pubkey(pubkey: &str) -> Result<String, Rejection> {
    let normalized = pubkey.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Rejection::bad_request("miner pubkey must be 64 hex chars"));
    }
    Ok(normalized)
}

fn get_updates(state: &ExplorerState, params: &QueryParams) -> Result<Response<Body>, Rejection> {
    let tip = state.blockchain.tip().map_err(|error| Rejection {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: error.to_string(),
    })?;

    let latest_block = state
        .blockchain
        .blocks
        .get_block_by_height(tip.height)
        .ok()
        .map(|block| block_summary(&block));
    let changed = params
        .number::<u64>("since")?
        .map(|since| since < tip.height)
        .unwrap_or(true);

    Ok(json_response(
        StatusCode::OK,
        &ExplorerUpdatesResponse {
            changed,
            info: build_info_response(state, tip),
            latest_block,
        },
    ))
}

/// The routes the explorer serves.
#[derive(Debug)]
enum Route {
    Index,
    AppJs,
    Wasm,
    Health,
    Info,
    Updates,
    Blocks,
    Block(String),
    Tx(String),
    ScienceTasks,
    ScienceTask(String),
    Apps,
    App(String),
    MinerRewards(String),
    MinerBlocks(String),
    Search,
}

impl Route {
    /// Resolves a request target, or `None` when no route matches.
    ///
    /// Path parameters are percent-decoded here and nowhere else: a handler
    /// receives the value a client meant, and a malformed escape is `400`
    /// rather than a silently different address.
    fn resolve(path: &str) -> Result<Option<Self>, Rejection> {
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let route = match segments.as_slice() {
            [""] => Route::Index,
            ["app.js"] => Route::AppJs,
            ["hyphen_explorer_web.wasm"] => Route::Wasm,
            ["healthz"] => Route::Health,
            ["api", "info"] => Route::Info,
            ["api", "updates"] => Route::Updates,
            ["api", "blocks"] => Route::Blocks,
            ["api", "search"] => Route::Search,
            ["api", "apps"] => Route::Apps,
            ["api", "science", "tasks"] => Route::ScienceTasks,
            ["api", "block", id] => Route::Block(percent_decode(id)?),
            ["api", "tx", hash] => Route::Tx(percent_decode(hash)?),
            ["api", "app", address] => Route::App(percent_decode(address)?),
            ["api", "science", "task", id] => Route::ScienceTask(percent_decode(id)?),
            ["api", "miner", pubkey, "rewards"] => Route::MinerRewards(percent_decode(pubkey)?),
            ["api", "miner", pubkey, "blocks"] => Route::MinerBlocks(percent_decode(pubkey)?),
            _ => return Ok(None),
        };
        Ok(Some(route))
    }
}

/// Serves one request; the whole explorer surface lives here.
struct ExplorerService {
    state: Arc<ExplorerState>,
}

impl ExplorerService {
    fn respond(&self, request: Request<Body>) -> Response<Body> {
        let route = match Route::resolve(request.uri.path()) {
            Ok(Some(route)) => route,
            Ok(None) => return error_json(StatusCode::NOT_FOUND, "no such endpoint"),
            Err(rejection) => return error_json(rejection.status, &rejection.message),
        };

        // `HEAD` is served like `GET`; the server suppresses the body.
        if request.method != Method::GET && request.method != Method::HEAD {
            let mut response = error_json(
                StatusCode::METHOD_NOT_ALLOWED,
                "the explorer serves GET and HEAD",
            );
            response.headers.insert("allow".into(), "GET, HEAD".into());
            return response;
        }

        let params = match QueryParams::parse(request.uri.query()) {
            Ok(params) => params,
            Err(rejection) => return error_json(rejection.status, &rejection.message),
        };

        let state = &self.state;
        let outcome = match route {
            Route::Index => Ok(serve_frontend()),
            Route::AppJs => Ok(serve_app_js()),
            Route::Wasm => Ok(serve_wasm()),
            Route::Health => Ok(serve_health()),
            Route::Info => Ok(get_info(state)),
            Route::Updates => get_updates(state, &params),
            Route::Blocks => get_blocks(state, &params),
            Route::Block(id) => Ok(get_block_handler(state, &id)),
            Route::Tx(hash) => Ok(get_tx(state, &hash)),
            Route::ScienceTasks => get_scientific_tasks(state, &params),
            Route::ScienceTask(id) => get_scientific_task(state, &id),
            Route::Apps => get_contracts(state, &params),
            Route::App(address) => get_contract(state, &address),
            Route::MinerRewards(pubkey) => get_miner_rewards(state, &pubkey),
            Route::MinerBlocks(pubkey) => get_miner_blocks(state, &pubkey, &params),
            Route::Search => search_handler(state, &params),
        };

        match outcome {
            Ok(response) => response,
            Err(rejection) => error_json(rejection.status, &rejection.message),
        }
    }
}

/// Serves the explorer until the process stops.
///
/// Courierust owns the listener and its workers; the chain state is shared
/// read-mostly behind its own lock, so handlers stay synchronous and the page,
/// its script, its WebAssembly module and every JSON route come from one HTTP
/// stack.
pub fn serve_explorer(
    bind_addr: SocketAddr,
    blockchain: Arc<Blockchain>,
    cfg: ChainConfig,
) -> Result<(), String> {
    let listener =
        TcpListener::bind(bind_addr).map_err(|error| format!("bind block explorer: {error}"))?;
    serve_explorer_on(listener, blockchain, cfg)
}

/// Serve the explorer on a listener the caller already bound.
///
/// Binding before this call lets a supervisor treat "the explorer port is
/// taken" as a startup failure instead of running a node whose public surface
/// is silently absent.
pub fn serve_explorer_on(
    listener: TcpListener,
    blockchain: Arc<Blockchain>,
    cfg: ChainConfig,
) -> Result<(), String> {
    let state = Arc::new(ExplorerState {
        blockchain,
        cfg,
        cache: RwLock::new(ExplorerCache::default()),
    });
    let config = ServerConfig {
        http2: true,
        max_body: MAX_REQUEST_BYTES,
        max_header_list: MAX_HEADER_LIST,
        request_header_timeout: Some(REQUEST_HEAD_TIMEOUT),
        read_timeout: Some(READ_TIMEOUT),
        idle_timeout: Some(IDLE_TIMEOUT),
        max_connections: MAX_CONNECTIONS,
        ..ServerConfig::default()
    };
    let server = Server::from_listener(listener, config)
        .map_err(|error| format!("configure block explorer: {error}"))?;
    let local_addr = server
        .local_addr()
        .map_err(|error| format!("block explorer address: {error}"))?;
    info!("Block explorer listening on http://{local_addr}");

    let service = ExplorerService { state };
    server
        .serve(move |request: Request<Body>| service.respond(request))
        .map_err(|error| format!("serve block explorer: {error}"))
}

pub async fn start_explorer(
    bind_addr: SocketAddr,
    blockchain: Arc<Blockchain>,
    cfg: ChainConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(bind_addr)?;
    start_explorer_on(listener, blockchain, cfg).await
}

/// Run the explorer on a caller-bound listener. The bind stays in the caller
/// so an occupied port fails startup rather than only the explorer task.
pub async fn start_explorer_on(
    listener: TcpListener,
    blockchain: Arc<Blockchain>,
    cfg: ChainConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::task::spawn_blocking(move || serve_explorer_on(listener, blockchain, cfg)).await??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_route_resolves_and_nothing_else_does() {
        let cases = [
            ("/", Some(Route::Index)),
            ("/app.js", Some(Route::AppJs)),
            ("/hyphen_explorer_web.wasm", Some(Route::Wasm)),
            ("/healthz", Some(Route::Health)),
            ("/api/info", Some(Route::Info)),
            ("/api/updates", Some(Route::Updates)),
            ("/api/blocks", Some(Route::Blocks)),
            ("/api/search", Some(Route::Search)),
            ("/api/apps", Some(Route::Apps)),
            ("/api/science/tasks", Some(Route::ScienceTasks)),
        ];
        for (path, expected) in cases {
            let resolved = Route::resolve(path).expect("well-formed target");
            assert_eq!(
                resolved.is_some(),
                expected.is_some(),
                "unexpected route for {path}"
            );
            assert_eq!(
                resolved.map(|route| std::mem::discriminant(&route)),
                expected.map(|route| std::mem::discriminant(&route)),
                "unexpected route for {path}"
            );
        }

        // Parameters are carried, not dropped.
        match Route::resolve("/api/block/7").unwrap() {
            Some(Route::Block(id)) => assert_eq!(id, "7"),
            _ => panic!("block height must resolve to a block route"),
        }
        match Route::resolve("/api/tx/ab%63d").unwrap() {
            Some(Route::Tx(hash)) => assert_eq!(hash, "abcd"),
            _ => panic!("a percent-encoded hash must decode"),
        }
        match Route::resolve("/api/miner/aa/rewards").unwrap() {
            Some(Route::MinerRewards(pubkey)) => assert_eq!(pubkey, "aa"),
            _ => panic!("miner rewards must resolve"),
        }
        match Route::resolve("/api/science/task/ab").unwrap() {
            Some(Route::ScienceTask(id)) => assert_eq!(id, "ab"),
            _ => panic!("scientific task must resolve"),
        }
        match Route::resolve("/api/app/ab").unwrap() {
            Some(Route::App(address)) => assert_eq!(address, "ab"),
            _ => panic!("contract must resolve"),
        }

        for path in [
            "/favicon.ico",
            "/api",
            "/api/info/",
            "/api/block",
            "/api/block/a/b",
            "/api/miner/aa",
            "/index.html",
        ] {
            assert!(
                Route::resolve(path).expect("well-formed target").is_none(),
                "{path} must not match a route"
            );
        }

        let rejection = Route::resolve("/api/block/%zz").unwrap_err();
        assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn query_parameters_are_decoded_and_validated() {
        let params = QueryParams::parse(Some("page=2&limit=50&q=hello%20world")).unwrap();
        assert_eq!(params.number::<u64>("page").unwrap(), Some(2));
        assert_eq!(params.number::<u64>("limit").unwrap(), Some(50));
        assert_eq!(params.require("q").unwrap(), "hello world");
        assert_eq!(params.get("absent"), None);

        let params = QueryParams::parse(Some("since=9&cachebuster=1")).unwrap();
        assert_eq!(params.number::<u64>("since").unwrap(), Some(9));

        let params = QueryParams::parse(Some("")).unwrap();
        assert_eq!(
            params.require("q").unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
        let params = QueryParams::parse(Some("page=abc")).unwrap();
        assert_eq!(
            params.number::<u64>("page").unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            QueryParams::parse(Some("q=%zz")).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn every_answer_carries_the_security_headers() {
        let response = serve_frontend();
        let header = |name: &str| {
            response
                .headers
                .get(name)
                .map(|value| value.as_bytes().to_vec())
        };
        assert_eq!(
            header("content-type"),
            Some(b"text/html; charset=utf-8".to_vec())
        );
        assert_eq!(header("x-content-type-options"), Some(b"nosniff".to_vec()));
        assert_eq!(header("referrer-policy"), Some(b"no-referrer".to_vec()));
        let policy = header("content-security-policy").expect("the CSP is set");
        let policy = String::from_utf8(policy).unwrap();
        assert!(policy.contains("default-src 'self'"));
        assert!(policy.contains("script-src 'self' 'wasm-unsafe-eval'"));
        assert!(policy.contains("frame-ancestors 'none'"));
        assert!(policy.contains("object-src 'none'"));

        let json = error_json(StatusCode::NOT_FOUND, "no such endpoint");
        assert_eq!(
            json.headers.get("content-type").map(|v| v.as_bytes()),
            Some(&b"application/json"[..])
        );
        assert_eq!(json.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn static_assets_are_served_with_their_own_media_types() {
        assert!(!INDEX_HTML.is_empty());
        assert!(!APP_JS.is_empty());
        assert!(!EXPLORER_WASM.is_empty());
        assert!(
            EXPLORER_WASM.starts_with(b"\0asm"),
            "the WASM module is real"
        );

        let script = serve_app_js();
        assert_eq!(
            script.headers.get("content-type").map(|v| v.as_bytes()),
            Some(&b"text/javascript; charset=utf-8"[..])
        );
        let wasm = serve_wasm();
        assert_eq!(
            wasm.headers.get("content-type").map(|v| v.as_bytes()),
            Some(&b"application/wasm"[..])
        );
    }
}
