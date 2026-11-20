use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use hyphen_consensus::Blockchain;
use hyphen_core::ChainConfig;
use hyphen_crypto::{Hash256, PublicKey, hex_decode};
use hyphen_wallet::{AuditVerificationContext, SelectiveDisclosure, verify_disclosure};

#[derive(Parser)]
#[command(
    about = "Verify a scoped single-output disclosure against a local synchronized node database"
)]
struct Cli {
    #[arg(long, value_parser = ["mainnet", "testnet", "devnet", "contract-devnet", "neural-devnet", "compute-devnet"])]
    network: String,
    #[arg(long)]
    data_dir: String,
    #[arg(long, required_unless_present = "export_output")]
    disclosure: Option<PathBuf>,
    /// Export one canonical transaction and output location for the owner's offline wallet.
    #[arg(long, conflicts_with_all = ["auditor", "scope", "disclosure"])]
    export_output: Option<u64>,
    /// Expected auditor's Ed25519 public key in hex.
    #[arg(long, value_parser = hex32, required_unless_present = "export_output")]
    auditor: Option<[u8; 32]>,
    /// Expected scope digest in hex.
    #[arg(long, value_parser = hex32, required_unless_present = "export_output")]
    scope: Option<[u8; 32]>,
}

fn hex32(text: &str) -> Result<[u8; 32], String> {
    hex_decode(text)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 32 bytes".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let cfg = match cli.network.as_str() {
        "mainnet" => ChainConfig::mainnet(),
        "testnet" => ChainConfig::testnet(),
        "devnet" => ChainConfig::devnet(),
        "neural-devnet" => ChainConfig::neural_devnet(),
        "contract-devnet" => ChainConfig::contract_devnet(),
        "compute-devnet" => ChainConfig::compute_devnet(),
        _ => unreachable!("clap validates network"),
    };
    if !std::path::Path::new(&cli.data_dir).join("conf").is_file() {
        return Err("expected an existing node database".into());
    }
    let network = cfg.network_name.clone();
    let chain = Blockchain::open(&cli.data_dir, cfg)?;
    if let Some(index) = cli.export_output {
        let entry = chain.canonical_output(index)?;
        let export = serde_json::json!({
            "schema": "hyphen-canonical-output-v1", "network": network, "chain_id": chain.chain_id().to_string(),
            "transaction_hex": hyphen_crypto::hex_encode(entry.transaction.serialise()), "txid": entry.transaction.hash().to_string(),
            "output_index": entry.output_index, "global_index": index,
            "block_height": entry.block_height, "block_hash": entry.block_hash.to_string(),
            "tip_height": entry.tip.height, "tip_hash": entry.tip.hash.to_string(),
        });
        println!("{export}");
        return Ok(());
    }
    let mut bytes = Vec::new();
    File::open(cli.disclosure.ok_or("missing disclosure file")?)?
        .take(16385)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err("disclosure exceeds 16 KiB".into());
    }
    let proof: SelectiveDisclosure = serde_json::from_slice(&bytes)?;
    let entry = chain.canonical_output(proof.global_index)?;
    if entry.output_index != proof.output_index {
        return Err("canonical transaction output ordinal differs".into());
    }
    let context = AuditVerificationContext {
        chain_id: chain.chain_id(),
        auditor: PublicKey(cli.auditor.ok_or("missing auditor")?),
        scope_hash: Hash256::from_bytes(cli.scope.ok_or("missing scope")?),
        now: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    verify_disclosure(&proof, &entry.transaction, context)?;
    println!(
        "capability={} transaction={} output_index={} global_index={} amount_atomic={} block_height={} block_hash={} tip_height={} tip_hash={}",
        proof.capability_id(),
        proof.txid,
        proof.output_index,
        proof.global_index,
        proof.value,
        entry.block_height,
        entry.block_hash,
        entry.tip.height,
        entry.tip.hash
    );
    Ok(())
}
