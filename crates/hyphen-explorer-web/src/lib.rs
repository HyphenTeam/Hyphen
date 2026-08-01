use serde::Deserialize;
use std::fmt::Write;

#[derive(Deserialize)]
struct Info {
    height: u64,
    tip_hash: String,
    cumulative_difficulty: String,
    network: String,
    block_time_target_secs: u64,
    current_reward: String,
    total_supply: String,
    difficulty: u64,
    current_epoch: u64,
    total_outputs: u64,
}

#[derive(Deserialize)]
struct BlockSummary {
    height: u64,
    hash: String,
    timestamp: u64,
    difficulty: u64,
    tx_count: usize,
    block_size: u32,
    reward: String,
    total_fee: String,
    miner_pubkey: String,
}

#[derive(Deserialize)]
struct Blocks {
    blocks: Vec<BlockSummary>,
    total_height: u64,
    page: u64,
    limit: u64,
}

#[derive(Deserialize)]
struct HomePayload {
    info: Info,
    blocks: Blocks,
}

#[derive(Deserialize)]
struct ScientificTask {
    task_id: String,
    status: String,
    domain: String,
    arithmetic: String,
    scientist: String,
    published_height: u64,
    publish_deadline: u64,
    challenge_deadline: Option<u64>,
    finalized_height: Option<u64>,
    retain_until_height: Option<u64>,
    rejected_height: Option<u64>,
    reward: String,
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

#[derive(Deserialize)]
struct ScientificTasks {
    tasks: Vec<ScientificTask>,
    total: usize,
    offset: usize,
    limit: usize,
}

#[derive(Deserialize)]
struct Header {
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
    miner_pubkey: String,
    total_fee: String,
    reward: String,
    view_tag: u8,
    block_size: u32,
}

#[derive(Deserialize)]
struct BlockDetail {
    hash: String,
    header: Header,
    tx_count: usize,
    tx_hashes: Vec<String>,
    uncle_count: usize,
    uncle_hashes: Vec<String>,
}

#[derive(Deserialize)]
struct TransactionLocation {
    tx_hash: String,
    block_hash: String,
    block_height: u64,
    index_in_block: u32,
}

#[derive(Deserialize)]
struct ApplicationManifest {
    abi: u16,
    category: String,
    name: String,
    version: String,
}

#[derive(Deserialize)]
struct ContractApplication {
    address: String,
    code_hash: String,
    deployer: String,
    deployed_height: u64,
    code_bytes: usize,
    application: Option<ApplicationManifest>,
}

#[derive(Deserialize)]
struct ContractApplications {
    contracts: Vec<ContractApplication>,
    total: usize,
    offset: usize,
    limit: usize,
}

fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(character);
    }
    output
}

fn short(value: &str) -> String {
    if value.len() <= 18 {
        escape(value)
    } else {
        format!(
            "{}..{}",
            escape(&value[..10]),
            escape(&value[value.len() - 6..])
        )
    }
}

fn age(timestamp: u64, now_ms: u64) -> String {
    let timestamp_ms = if timestamp < 1_000_000_000_000 {
        timestamp.saturating_mul(1_000)
    } else {
        timestamp
    };
    let seconds = now_ms.saturating_sub(timestamp_ms) / 1_000;
    match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3_599 => format!("{}m", seconds / 60),
        3_600..=86_399 => format!("{}h", seconds / 3_600),
        _ => format!("{}d", seconds / 86_400),
    }
}

fn metric(output: &mut String, label: &str, value: &str, tone: &str) {
    let _ = write!(
        output,
        "<div class=\"metric\"><span>{}</span><strong class=\"{}\">{}</strong></div>",
        escape(label),
        tone,
        escape(value)
    );
}

fn render_home(payload: &str, now_ms: u64) -> Result<String, String> {
    let data: HomePayload = serde_json::from_str(payload).map_err(|error| error.to_string())?;
    let mut output = String::with_capacity(16_384);
    output.push_str("<section class=\"metrics\">");
    metric(
        &mut output,
        "CHAIN HEIGHT",
        &grouped(data.info.height),
        "cyan",
    );
    metric(
        &mut output,
        "DIFFICULTY",
        &grouped(data.info.difficulty),
        "amber",
    );
    metric(
        &mut output,
        "AETHER REWARD",
        &format!("{} HPN", data.info.current_reward),
        "green",
    );
    metric(
        &mut output,
        "PRIVATE OUTPUTS",
        &grouped(data.info.total_outputs),
        "coral",
    );
    output.push_str("</section><section class=\"chain-strip\">");
    let _ = write!(
        output,
        "<div><span>NETWORK</span><b>{}</b></div>",
        escape(&data.info.network)
    );
    let _ = write!(
        output,
        "<div><span>TIP</span><b title=\"{}\">{}</b></div>",
        escape(&data.info.tip_hash),
        short(&data.info.tip_hash)
    );
    let _ = write!(
        output,
        "<div><span>CUMULATIVE WORK</span><b>{}</b></div>",
        escape(&data.info.cumulative_difficulty)
    );
    let _ = write!(
        output,
        "<div><span>EPOCH</span><b>{}</b></div>",
        grouped(data.info.current_epoch)
    );
    let _ = write!(
        output,
        "<div><span>TARGET</span><b>{}s</b></div>",
        data.info.block_time_target_secs
    );
    let _ = write!(
        output,
        "<div><span>ISSUED</span><b>{} HPN</b></div>",
        escape(&data.info.total_supply)
    );
    output.push_str("</section><div class=\"section-head\"><div><span class=\"kicker\">CANONICAL LEDGER</span><h1>Recent blocks</h1></div><span class=\"live\">LIVE</span></div>");
    output.push_str("<div class=\"data-table\"><table><thead><tr><th>Height</th><th>Age</th><th>Block</th><th>Transactions</th><th>Bytes</th><th>Work units</th><th>Reward</th><th>Producer</th></tr></thead><tbody>");
    for block in &data.blocks.blocks {
        let _ = write!(output, "<tr><td><a href=\"#/block/{}\">#{}</a></td><td>{}</td><td><a class=\"hash\" title=\"{}\" href=\"#/block/{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td><span class=\"amount\">{} HPN</span><small>fee {}</small></td><td class=\"hash\" title=\"{}\">{}</td></tr>", block.height, grouped(block.height), age(block.timestamp, now_ms), escape(&block.hash), escape(&block.hash), short(&block.hash), grouped(block.tx_count as u64), grouped(block.block_size as u64), grouped(block.difficulty), escape(&block.reward), escape(&block.total_fee), escape(&block.miner_pubkey), short(&block.miner_pubkey));
    }
    output.push_str("</tbody></table></div>");
    let page_count = (data.blocks.total_height + 1)
        .div_ceil(data.blocks.limit)
        .max(1);
    let _ = write!(output, "<nav class=\"pager\"><button data-action=\"newer\" {}>NEWER</button><span>{} / {}</span><button data-action=\"older\" {}>OLDER</button></nav>", if data.blocks.page == 0 { "disabled" } else { "" }, data.blocks.page + 1, page_count, if data.blocks.page + 1 >= page_count { "disabled" } else { "" });
    Ok(output)
}

fn status_class(status: &str) -> &'static str {
    match status {
        "finalized" => "ok",
        "submitted" => "pending",
        "rejected" => "bad",
        _ => "open",
    }
}

fn render_science(payload: &str) -> Result<String, String> {
    let data: ScientificTasks = serde_json::from_str(payload).map_err(|error| error.to_string())?;
    let mut output = String::with_capacity(12_000);
    output.push_str("<div class=\"section-head\"><div><span class=\"kicker\">AETHERCOMPUTE</span><h1>Verifiable scientific work</h1></div><span class=\"privacy-mark\">COMMITMENTS ONLY</span></div>");
    output.push_str("<div class=\"domain-band\"><b>QCD</b><b>MANIFOLD DYNAMICS</b><b>CONNECTOMICS</b><span>fixed-point deterministic kernels</span></div>");
    output.push_str("<div class=\"data-table\"><table><thead><tr><th>Task</th><th>State</th><th>Domain</th><th>Budget</th><th>Reward</th><th>Published</th><th>Retention</th></tr></thead><tbody>");
    for task in &data.tasks {
        let _ = write!(output, "<tr><td><a class=\"hash\" title=\"{}\" href=\"#/science/task/{}\">{}</a></td><td><span class=\"status {}\">{}</span></td><td>{}<small>{}</small></td><td>{} ops</td><td class=\"amount\">{} HPN</td><td><a href=\"#/block/{}\">#{}</a></td><td>{} peers</td></tr>", escape(&task.task_id), escape(&task.task_id), short(&task.task_id), status_class(&task.status), escape(&task.status), escape(&task.domain), escape(&task.arithmetic), grouped(task.max_operations), escape(&task.reward), task.published_height, grouped(task.published_height), task.retention_providers);
    }
    output.push_str("</tbody></table></div>");
    let page = data.offset / data.limit;
    let pages = data.total.div_ceil(data.limit).max(1);
    let _ = write!(output, "<nav class=\"pager\"><button data-action=\"science-newer\" {}>PREVIOUS</button><span>{} / {} &middot; {} TASKS</span><button data-action=\"science-older\" {}>NEXT</button></nav>", if page == 0 { "disabled" } else { "" }, page + 1, pages, data.total, if page + 1 >= pages { "disabled" } else { "" });
    Ok(output)
}

fn detail_row(output: &mut String, label: &str, value: &str) {
    let _ = write!(
        output,
        "<dt>{}</dt><dd>{}</dd>",
        escape(label),
        escape(value)
    );
}

fn hash_row(output: &mut String, label: &str, value: &str) {
    let _ = write!(
        output,
        "<dt>{}</dt><dd class=\"full-hash\">{}</dd>",
        escape(label),
        escape(value)
    );
}

fn render_task(payload: &str) -> Result<String, String> {
    let task: ScientificTask = serde_json::from_str(payload).map_err(|error| error.to_string())?;
    let mut output = String::with_capacity(10_000);
    let _ = write!(output, "<div class=\"section-head\"><div><span class=\"kicker\">AETHERCOMPUTE / TASK</span><h1>{}</h1></div><span class=\"status {}\">{}</span></div>", short(&task.task_id), status_class(&task.status), escape(&task.status));
    output.push_str("<section class=\"detail-grid\"><article><h2>Execution statement</h2><dl>");
    hash_row(&mut output, "Task ID", &task.task_id);
    detail_row(&mut output, "Domain", &task.domain);
    detail_row(&mut output, "Arithmetic", &task.arithmetic);
    detail_row(
        &mut output,
        "Operation ceiling",
        &grouped(task.max_operations),
    );
    detail_row(&mut output, "Reward", &format!("{} HPN", task.reward));
    detail_row(
        &mut output,
        "Published",
        &format!("#{}", task.published_height),
    );
    detail_row(
        &mut output,
        "Publish deadline",
        &format!("#{}", task.publish_deadline),
    );
    if let Some(height) = task.challenge_deadline {
        detail_row(&mut output, "Challenge deadline", &format!("#{height}"));
    }
    if let Some(height) = task.finalized_height {
        detail_row(&mut output, "Finalized", &format!("#{height}"));
    }
    if let Some(height) = task.retain_until_height {
        detail_row(&mut output, "Retain through", &format!("#{height}"));
    }
    if let Some(height) = task.rejected_height {
        detail_row(&mut output, "Rejected", &format!("#{height}"));
    }
    hash_row(&mut output, "Scientist", &task.scientist);
    output.push_str("</dl></article><article><h2>Committed input</h2><dl>");
    hash_row(&mut output, "Program", &task.program_hash);
    hash_row(&mut output, "Circuit", &task.circuit_id);
    hash_row(&mut output, "Object", &task.input_object_hash);
    hash_row(&mut output, "Chunk root", &task.input_chunk_root);
    detail_row(
        &mut output,
        "Size",
        &format!("{} bytes", grouped(task.input_bytes)),
    );
    detail_row(
        &mut output,
        "Availability",
        if task.input_available {
            "committed"
        } else {
            "unavailable"
        },
    );
    output.push_str("</dl></article>");
    if let Some(object_hash) = &task.output_object_hash {
        output.push_str("<article><h2>Verified output</h2><dl>");
        hash_row(&mut output, "Object", object_hash);
        if let Some(root) = &task.output_chunk_root {
            hash_row(&mut output, "Chunk root", root);
        }
        if let Some(bytes) = task.output_bytes {
            detail_row(&mut output, "Size", &format!("{} bytes", grouped(bytes)));
        }
        if let Some(available) = task.output_available {
            detail_row(
                &mut output,
                "Availability",
                if available {
                    "committed"
                } else {
                    "unavailable"
                },
            );
        }
        if let Some(worker) = &task.worker {
            hash_row(&mut output, "Worker", worker);
        }
        if let Some(system) = task.proof_system {
            detail_row(&mut output, "Proof system", &system.to_string());
        }
        if let Some(root) = &task.trace_root {
            hash_row(&mut output, "Trace root", root);
        }
        if let Some(root) = &task.checkpoint_root {
            hash_row(&mut output, "Checkpoint root", root);
        }
        output.push_str("</dl></article>");
    }
    let _ = write!(output, "<article><h2>Privacy boundary</h2><dl><dt>Published</dt><dd>content hashes, Merkle roots, byte lengths</dd><dt>Withheld</dt><dd>object locators, credentials, private transaction payloads</dd><dt>Retention</dt><dd>{} independent attestations</dd></dl></article></section>", task.retention_providers);
    Ok(output)
}

fn render_block(payload: &str, now_ms: u64) -> Result<String, String> {
    let block: BlockDetail = serde_json::from_str(payload).map_err(|error| error.to_string())?;
    let h = &block.header;
    let mut output = String::with_capacity(12_000);
    let _ = write!(output, "<div class=\"section-head\"><div><span class=\"kicker\">CANONICAL BLOCK</span><h1>Height #{}</h1></div><span class=\"age-badge\">{} AGO</span></div><section class=\"detail-grid\"><article><h2>Header</h2><dl>", grouped(h.height), age(h.timestamp, now_ms));
    hash_row(&mut output, "Block hash", &block.hash);
    hash_row(&mut output, "Previous", &h.prev_hash);
    detail_row(&mut output, "Version", &h.version.to_string());
    detail_row(&mut output, "Difficulty", &grouped(h.difficulty));
    detail_row(&mut output, "Nonce", &h.nonce.to_string());
    detail_row(&mut output, "View tag", &h.view_tag.to_string());
    detail_row(
        &mut output,
        "Serialized size",
        &format!("{} bytes", grouped(h.block_size as u64)),
    );
    detail_row(&mut output, "Reward", &format!("{} HPN", h.reward));
    detail_row(&mut output, "Fees", &format!("{} HPN", h.total_fee));
    hash_row(&mut output, "Producer", &h.miner_pubkey);
    output.push_str("</dl></article><article><h2>Consensus commitments</h2><dl>");
    for (label, value) in [
        ("Transaction root", &h.tx_root),
        ("Commitment root", &h.commitment_root),
        ("Nullifier root", &h.nullifier_root),
        ("Unified state root", &h.state_root),
        ("Receipt root", &h.receipt_root),
        ("Uncle root", &h.uncle_root),
        ("Work commitment", &h.pow_commitment),
        ("Epoch seed", &h.epoch_seed),
    ] {
        hash_row(&mut output, label, value);
    }
    output
        .push_str("</dl></article></section><section class=\"object-list\"><h2>Transactions</h2>");
    if block.tx_hashes.is_empty() {
        output.push_str("<p class=\"empty\">No private transactions in this block.</p>");
    }
    for hash in &block.tx_hashes {
        let _ = write!(
            output,
            "<a href=\"#/tx/{}\"><span>{}</span><b>{}</b></a>",
            escape(hash),
            short(hash),
            escape(hash)
        );
    }
    let _ = write!(
        output,
        "<p class=\"list-meta\">{} transactions &middot; {} uncle headers</p></section>",
        block.tx_count, block.uncle_count
    );
    if !block.uncle_hashes.is_empty() {
        output.push_str("<section class=\"object-list\"><h2>Uncle headers</h2>");
        for hash in &block.uncle_hashes {
            let _ = write!(
                output,
                "<a href=\"#/block/{}\"><span>{}</span><b>{}</b></a>",
                escape(hash),
                short(hash),
                escape(hash)
            );
        }
        output.push_str("</section>");
    }
    Ok(output)
}

fn render_transaction(payload: &str) -> Result<String, String> {
    let tx: TransactionLocation =
        serde_json::from_str(payload).map_err(|error| error.to_string())?;
    let mut output = String::with_capacity(2_000);
    output.push_str("<div class=\"section-head\"><div><span class=\"kicker\">PRIVATE TRANSACTION</span><h1>Inclusion record</h1></div><span class=\"privacy-mark\">PAYLOAD WITHHELD</span></div><section class=\"detail-grid single\"><article><h2>Public commitments</h2><dl>");
    hash_row(&mut output, "Transaction hash", &tx.tx_hash);
    let _ = write!(
        output,
        "<dt>Block</dt><dd><a href=\"#/block/{}\">#{}</a></dd>",
        escape(&tx.block_hash),
        grouped(tx.block_height)
    );
    hash_row(&mut output, "Block hash", &tx.block_hash);
    detail_row(&mut output, "Position", &tx.index_in_block.to_string());
    output.push_str("</dl></article></section>");
    Ok(output)
}

fn render_applications(payload: &str) -> Result<String, String> {
    let data: ContractApplications =
        serde_json::from_str(payload).map_err(|error| error.to_string())?;
    let mut output = String::with_capacity(10_000);
    output.push_str("<div class=\"section-head\"><div><span class=\"kicker\">HYPHEN WASM ABI V1</span><h1>On-chain applications</h1></div><span class=\"privacy-mark\">STATE ROOT COMMITTED</span></div>");
    output.push_str("<div class=\"domain-band\"><b>DEFI</b><b>GAME</b><b>UTILITY</b><span>deterministic wasm32 &middot; metered host calls &middot; atomic rollback</span></div>");
    output.push_str("<div class=\"data-table\"><table><thead><tr><th>Application</th><th>Category</th><th>Contract</th><th>ABI</th><th>Code</th><th>Deployed</th></tr></thead><tbody>");
    for contract in &data.contracts {
        let (name, category, version, abi) = match &contract.application {
            Some(app) => (
                app.name.as_str(),
                app.category.as_str(),
                app.version.as_str(),
                app.abi.to_string(),
            ),
            None => ("Unclassified contract", "raw wasm", "-", "-".into()),
        };
        let _ = write!(output, "<tr><td><a href=\"#/app/{}\">{}</a><small>v{}</small></td><td><span class=\"status open\">{}</span></td><td class=\"hash\" title=\"{}\">{}</td><td>{}</td><td>{} bytes</td><td><a href=\"#/block/{}\">#{}</a></td></tr>", escape(&contract.address), escape(name), escape(version), escape(category), escape(&contract.address), short(&contract.address), escape(&abi), grouped(contract.code_bytes as u64), contract.deployed_height, grouped(contract.deployed_height));
    }
    output.push_str("</tbody></table></div>");
    let page = data.offset / data.limit;
    let pages = data.total.div_ceil(data.limit).max(1);
    let _ = write!(output, "<nav class=\"pager\"><button data-action=\"apps-newer\" {}>PREVIOUS</button><span>{} / {} &middot; {} CONTRACTS</span><button data-action=\"apps-older\" {}>NEXT</button></nav>", if page == 0 { "disabled" } else { "" }, page + 1, pages, data.total, if page + 1 >= pages { "disabled" } else { "" });
    Ok(output)
}

fn render_application(payload: &str) -> Result<String, String> {
    let contract: ContractApplication =
        serde_json::from_str(payload).map_err(|error| error.to_string())?;
    let mut output = String::with_capacity(4_000);
    let (name, category) = contract
        .application
        .as_ref()
        .map(|app| (app.name.as_str(), app.category.as_str()))
        .unwrap_or(("Unclassified contract", "raw wasm"));
    let _ = write!(output, "<div class=\"section-head\"><div><span class=\"kicker\">WASM APPLICATION</span><h1>{}</h1></div><span class=\"status open\">{}</span></div><section class=\"detail-grid single\"><article><h2>Immutable deployment</h2><dl>", escape(name), escape(category));
    hash_row(&mut output, "Contract", &contract.address);
    hash_row(&mut output, "Code hash", &contract.code_hash);
    hash_row(&mut output, "Deployer", &contract.deployer);
    detail_row(
        &mut output,
        "Deployed",
        &format!("#{}", contract.deployed_height),
    );
    detail_row(
        &mut output,
        "Code size",
        &format!("{} bytes", grouped(contract.code_bytes as u64)),
    );
    if let Some(app) = &contract.application {
        detail_row(&mut output, "ABI", &app.abi.to_string());
        detail_row(&mut output, "Version", &app.version);
        detail_row(&mut output, "Query export", "hyphen_query");
        detail_row(&mut output, "Execute export", "hyphen_execute");
    }
    output.push_str("</dl></article></section>");
    Ok(output)
}

pub fn render(view: u32, payload: &str, now_ms: u64) -> Result<String, String> {
    match view {
        0 => render_home(payload, now_ms),
        1 => render_science(payload),
        2 => render_task(payload),
        3 => render_block(payload, now_ms),
        4 => render_transaction(payload),
        5 => render_applications(payload),
        6 => render_application(payload),
        _ => Err("unknown explorer view".into()),
    }
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn hyphen_alloc(length: u32) -> u32 {
    let allocation = vec![0_u8; length as usize].into_boxed_slice();
    Box::into_raw(allocation) as *mut u8 as u32
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn hyphen_free(pointer: u32, length: u32) {
    let slice = std::ptr::slice_from_raw_parts_mut(pointer as *mut u8, length as usize);
    drop(unsafe { Box::from_raw(slice) });
}

#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn hyphen_render(view: u32, pointer: u32, length: u32, now_ms: f64) -> u64 {
    let bytes = unsafe { std::slice::from_raw_parts(pointer as *const u8, length as usize) };
    let payload = std::str::from_utf8(bytes).unwrap_or("");
    let rendered = render(view, payload, now_ms.max(0.0) as u64).unwrap_or_else(|error| {
        format!(
            "<div class=\"error\">WASM render error: {}</div>",
            escape(&error)
        )
    });
    let output = rendered.into_bytes().into_boxed_slice();
    let output_length = output.len() as u32;
    let output_pointer = Box::into_raw(output) as *mut u8 as u32;
    ((output_length as u64) << 32) | output_pointer as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_escapes_untrusted_chain_strings() {
        let payload = r#"{
            "info":{"height":1,"tip_hash":"<script>","cumulative_difficulty":"2","network":"devnet","block_time_target_secs":60,"current_reward":"1","total_supply":"2","difficulty":3,"current_epoch":0,"total_outputs":0},
            "blocks":{"blocks":[],"total_height":1,"page":0,"limit":20}
        }"#;
        let html = render(0, payload, 0).unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn task_renderer_has_no_locator_surface() {
        let payload = r#"{"task_id":"01","status":"open","domain":"QCD","arithmetic":"fixed-point-v1","scientist":"02","published_height":1,"publish_deadline":2,"challenge_deadline":null,"finalized_height":null,"retain_until_height":null,"rejected_height":null,"reward":"1","max_operations":10,"program_hash":"03","circuit_id":"04","input_object_hash":"05","input_bytes":8,"input_chunk_root":"06","input_available":true,"input_locator":"s3://private-bucket/credential","output_object_hash":null,"output_bytes":null,"output_chunk_root":null,"output_available":null,"worker":null,"proof_system":null,"trace_root":null,"checkpoint_root":null,"retention_providers":0}"#;
        let html = render(2, payload, 0).unwrap();
        assert!(!html.contains("s3://private-bucket/credential"));
        assert!(html.contains("Privacy boundary"));
    }
}
