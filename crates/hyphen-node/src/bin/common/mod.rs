use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

use hyphen_core::{ChainConfig, ChainIdentity, FROZEN_BLOCK_VERSION};
use hyphen_crypto::Hash256;
use hyphen_rpc::{messages::*, server::MAX_FRAME_SIZE};
use prost::Message;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[allow(dead_code)] // Shared by the compute and contract readers.
pub fn parse_hash(text: &str) -> std::result::Result<Hash256, String> {
    let bytes = hyphen_crypto::hex_decode(text).map_err(|e| e.to_string())?;
    Ok(Hash256::from_bytes(
        bytes.try_into().map_err(|_| "expected a 32-byte hash")?,
    ))
}

#[allow(dead_code)]
pub fn checked_local_state(
    path: &Path,
    expected: Option<Hash256>,
) -> Result<hyphen_consensus::Blockchain> {
    if !path.join("conf").is_file() {
        return Err("expected an existing stopped HYN3 node database".into());
    }
    let db = hyphen_consensus::Blockchain::open(
        path.to_str().ok_or("invalid database path")?,
        ChainConfig::neural_devnet(),
    )?;
    let tip = db.tip()?;
    if expected.is_some_and(|hash| hash != tip.hash) {
        return Err("local tip differs from the expected block hash".into());
    }
    let state_root = db.state_root()?;
    let block = db.store().get_block_by_hash(&tip.hash)?;
    if block.hash() != tip.hash
        || block.header.height != tip.height
        || block.header.state_root != state_root
    {
        return Err("local protocol state differs from the canonical header".into());
    }
    eprintln!(
        "tip_height={} tip_hash={} state_root={}",
        tip.height, tip.hash, state_root
    );
    Ok(db)
}

#[allow(dead_code)] // Some binaries use only the bounded file and RPC readers.
pub fn read_key(path: &Path) -> Result<hyphen_crypto::SecretKey> {
    let mut key = hyphen_crypto::SecretKey([0; 32]);
    let mut file = File::open(path)?;
    file.read_exact(&mut key.0)?;
    if file.read(&mut [0])? != 0 {
        return Err("expected a raw 32-byte signing seed".into());
    }
    Ok(key)
}

pub fn read_bytes(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(format!("{} exceeds {limit} bytes", path.display()).into());
    }
    Ok(bytes)
}

pub fn request<R: Message + Default>(
    stream: &mut TcpStream,
    method: u32,
    message: impl Message,
) -> Result<R> {
    let payload = RpcRequest {
        id: method,
        method,
        payload: message.encode_to_vec(),
    }
    .encode_to_vec();
    stream.write_all(&u32::try_from(payload.len())?.to_be_bytes())?;
    stream.write_all(&payload)?;
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length);
    if length > MAX_FRAME_SIZE {
        return Err("RPC response exceeds the frame limit".into());
    }
    let mut bytes = vec![0; length as usize];
    stream.read_exact(&mut bytes)?;
    let response = RpcResponse::decode(bytes.as_slice())?;
    if response.id != method {
        return Err("unexpected RPC response ID".into());
    }
    if !response.success {
        return Err(response.error.into());
    }
    Ok(R::decode(response.payload.as_slice())?)
}

pub fn check_identity(stream: &mut TcpStream, cfg: &ChainConfig) -> Result<Hash256> {
    let identity = ChainIdentity::of(cfg);
    let info: ChainInfoResponse = request(stream, METHOD_GET_CHAIN_INFO, GetChainInfoRequest {})?;
    if info.network != cfg.network_name
        || info.consensus_params_hash != identity.consensus_params_hash
        || info.genesis_hash != identity.genesis_hash.as_bytes()
        || info.network_magic != identity.network_magic
        || info.block_version != FROZEN_BLOCK_VERSION
        || info.pouw_protocol_version != u32::from(hyphen_pow::POUW_PROTOCOL_VERSION)
    {
        return Err(format!("node identity differs from {}", cfg.network_name).into());
    }
    Ok(identity.genesis_hash)
}
