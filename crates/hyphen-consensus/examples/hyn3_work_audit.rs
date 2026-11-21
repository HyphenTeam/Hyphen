//! Offline reference for the HYN3 work transcript. Only the archive decoder,
//! header field types, BLAKE3 and standard ChaCha primitive are shared libraries.
use std::{error::Error, path::Path, time::Instant};

use hyphen_consensus::ChainArchive;
use hyphen_core::{Block, BlockHeader};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::{Value, json};

type Digest = [u8; 32];
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const CELLS: usize = 32_768;
const ONE: i64 = 1 << 32;
const INITIAL: u64 = 1 << 60;
const GENESIS: &str = "710ad7eb105d56901495cf9c31f07f749cb812ddf3848f978e2bd133b7ebc926";
const PARAMS: &str = "4f3b68f56eb14d9d022d2f6b970811b3d8d53f5a3f6db07f70763cd7e5c17d49";

fn hash(parts: &[&[u8]]) -> Digest {
    let mut h = blake3::Hasher::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn low(bytes: &Digest) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

struct Network {
    seed: Digest,
    tensor: [i64; 2128],
}

impl Network {
    fn new(parent: &Digest, height: u64, miner: &Digest) -> Self {
        let seed = hash(&[
            b"Hyphen/neural-work-seed/v1",
            parent,
            &height.to_le_bytes(),
            miner,
        ]);
        let mut rng = ChaCha20Rng::from_seed(seed);
        // rand_chacha exposes a 64-bit counter and a 64-bit stream. Counter
        // word 13 is domain 1 in the RFC 8439 state. Each block has 16 words.
        rng.set_stream(height ^ (1 << 63));
        rng.set_word_pos(1 << 36);
        let mut tensor = [0; 2128];
        for (i, w) in tensor[..2112].iter_mut().enumerate() {
            let scale = if i < 1088 { ONE / 4 } else { ONE / 8 };
            *w = ((u64::from(rng.next_u32()) * (2 * scale) as u64) >> 32) as i64 - scale;
        }
        Self { seed, tensor }
    }

    fn score(&self, nonce: u64) -> u64 {
        let stream = 0x48595048454e5731 ^ nonce.wrapping_mul(0x9e3779b9);
        let input: [i64; 16] = std::array::from_fn(|i| {
            let offset = 4 * (i % 8);
            let word = u32::from_le_bytes(self.seed[offset..offset + 4].try_into().unwrap());
            2 * (mix(u64::from(word) ^ stream ^ i as u64) >> 32) as i64 - ONE
        });
        let hidden: [i64; 64] = layer(&input, &self.tensor[..1024], &self.tensor[1024..1088]);
        let output: [i64; 16] = layer(&hidden, &self.tensor[1088..2112], &self.tensor[2112..]);
        mix(output
            .into_iter()
            .fold(0x9e3779b97f4a7c15, |acc, y| mix(acc ^ y as u64)))
    }

    fn gate(&self, nonce: u64, score: u64) -> Digest {
        hash(&[
            b"Hyphen/neural-gate/v3\0",
            &self.seed,
            &nonce.to_le_bytes(),
            &score.to_le_bytes(),
        ])
    }
}

fn layer<const N: usize>(input: &[i64], weights: &[i64], bias: &[i64]) -> [i64; N] {
    std::array::from_fn(|i| {
        let row = &weights[i * input.len()..(i + 1) * input.len()];
        let x = input
            .iter()
            .zip(row)
            .fold(i128::from(bias[i]), |sum, (&x, &w)| {
                sum + ((i128::from(x) * i128::from(w)) >> 32)
            });
        let unit = i128::from(ONE);
        if x.abs() >= 3 * unit {
            return (x.signum() * unit) as i64;
        }
        let square = (x * x) >> 32;
        (x * (27 * unit + square) / (27 * unit + 9 * square)) as i64
    })
}

/// Store every `stride`th fill state and recompute the skipped suffix on read.
fn memory(gate: &Digest, stride: usize) -> (Digest, usize) {
    let keyed = |data: &[u8]| -> Digest { blake3::keyed_hash(gate, data).into() };
    let mut state = keyed(b"Hyphen/neural-memory/v3\0");
    let mut saved = Vec::with_capacity(CELLS.div_ceil(stride));
    for i in 0..CELLS {
        if i % stride == 0 {
            saved.push(state);
        }
        state = keyed(&state);
    }
    let mut hashes = 2 + 2 * CELLS;
    let mut pair = [0; 64];
    for _ in 0..CELLS {
        let index = usize::from(u16::from_le_bytes([state[0], state[1]])) % CELLS;
        let mut cell = saved[index / stride];
        for _ in 0..index % stride {
            cell = keyed(&cell);
        }
        hashes += index % stride;
        pair[..32].copy_from_slice(&state);
        pair[32..].copy_from_slice(&cell);
        state = keyed(&pair);
    }
    (hash(&[b"Hyphen/neural-final/v3\0", gate, &state]), hashes)
}

fn commitment(parent: &Digest, height: u64, target: u64, miner: &Digest, nonce: u64) -> Digest {
    hash(&[
        b"Hyphen/neural-work-commitment/v1",
        parent,
        &height.to_le_bytes(),
        &target.to_le_bytes(),
        miner,
        &nonce.to_le_bytes(),
    ])
}

fn reference_vector() -> Result<()> {
    let expected: Value = serde_json::from_str(include_str!(
        "../../../test-vectors/neural-block-work-v3.json"
    ))?;
    let parent: Digest = blake3::Hash::from_hex(GENESIS)?.into();
    let miner = [19; 32];
    let net = Network::new(&parent, 1, &miner);
    for nonce in 0..65536 {
        let score = net.score(nonce);
        let gate = net.gate(nonce, score);
        if low(&gate) >= INITIAL {
            continue;
        }
        let (digest, _) = memory(&gate, 1);
        if low(&digest) >= INITIAL {
            continue;
        }
        let hex = hyphen_crypto::hex_encode;
        let actual = json!({"parent": GENESIS, "height": 1, "miner_key": hex(miner), "seed": hex(net.seed), "nonce": nonce, "neural_score": score, "gate_digest": hex(gate), "memory_digest": hex(digest), "memory_score": low(&digest), "threshold": INITIAL, "commitment": hex(commitment(&parent, 1, INITIAL, &miner, nonce))});
        if actual != expected {
            return Err("reference work transcript mismatch".into());
        }
        for stride in [1, 2, 3, 4, 8, 16, 32] {
            let start = Instant::now();
            let (other, hashes) = memory(&gate, stride);
            if other != digest {
                return Err("checkpoint recomputation mismatch".into());
            }
            let saved_bytes = 32 * CELLS.div_ceil(stride);
            // The seed and every keyed update fit one compression block. The
            // unkeyed final transcript takes two. The admission gate is excluded.
            println!(
                "{}",
                json!({"nonce": nonce, "stride": stride, "saved_digest_bytes": saved_bytes, "hashes": hashes, "compression_blocks": hashes + 1, "bram36_capacity_blocks": (saved_bytes * 8).div_ceil(36 * 1024), "elapsed_ns": start.elapsed().as_nanos() as u64})
            );
        }
        return Ok(());
    }
    Err("no reference work in vector window".into())
}

fn uint(bytes: &mut Vec<u8>, n: u64) {
    match n {
        0..251 => bytes.push(n as u8),
        251..=0xffff => {
            bytes.push(251);
            bytes.extend((n as u16).to_le_bytes());
        }
        0x10000..=0xffffffff => {
            bytes.push(252);
            bytes.extend((n as u32).to_le_bytes());
        }
        _ => {
            bytes.push(253);
            bytes.extend(n.to_le_bytes());
        }
    }
}

fn header_hash(h: &BlockHeader) -> Digest {
    let mut bytes = Vec::with_capacity(448);
    for n in [u64::from(h.version), h.height, h.timestamp] {
        uint(&mut bytes, n);
    }
    for field in [
        h.prev_hash,
        h.tx_root,
        h.commitment_root,
        h.nullifier_root,
        h.state_root,
        h.receipt_root,
        h.uncle_root,
        h.pow_commitment,
        h.epoch_seed,
    ] {
        bytes.extend(field.0);
    }
    uint(&mut bytes, h.difficulty);
    uint(&mut bytes, h.nonce);
    bytes.extend(h.extra_nonce);
    bytes.extend(h.miner_pubkey);
    uint(&mut bytes, h.total_fee);
    uint(&mut bytes, h.reward);
    bytes.push(h.view_tag);
    uint(&mut bytes, u64::from(h.block_size));
    hash(&[&bytes])
}

fn target(history: &[Block]) -> u64 {
    if history.len() < 17 {
        return INITIAL;
    }
    let window = &history[history.len() - 17..];
    let parent = &window[16].header;
    let elapsed = parent
        .timestamp
        .saturating_sub(window[0].header.timestamp)
        .clamp(1, 1_920_000);
    let scale = 1u128 << 96;
    let work: u128 = window[1..]
        .iter()
        .map(|b| scale / u128::from(b.header.difficulty))
        .sum();
    let estimate = scale * u128::from(elapsed) / (30_000 * work);
    estimate.clamp(
        u128::from(parent.difficulty.div_ceil(4)),
        (u128::from(parent.difficulty) * 4).min(1 << 62),
    ) as u64
}

fn check_archive(path: &Path) -> Result<()> {
    let archive = ChainArchive::read(path)?;
    if archive.version != 1
        || &archive.network_magic != b"HYN3"
        || archive.genesis_hash.to_string() != GENESIS
        || hyphen_crypto::hex_encode(archive.consensus_params_hash) != PARAMS
    {
        return Err("archive identity mismatch".into());
    }
    let mut parent = archive.genesis_hash.0;
    let mut weight = 0u128;
    let start = Instant::now();
    for (index, block) in archive.blocks.iter().enumerate() {
        let h = &block.header;
        let [nonce] = block.pow_witnesses[..] else {
            return Err("expected one nonce".into());
        };
        let height = index as u64 + 1;
        let threshold = target(&archive.blocks[..index]);
        if h.height != height
            || h.difficulty != threshold
            || h.prev_hash.0 != parent
            || h.pow_commitment.0 != commitment(&parent, height, threshold, &h.miner_pubkey, nonce)
        {
            return Err(format!("invalid work header at {height}").into());
        }
        let net = Network::new(&parent, height, &h.miner_pubkey);
        let gate = net.gate(nonce, net.score(nonce));
        if low(&gate) >= INITIAL || low(&memory(&gate, 1).0) >= threshold {
            return Err(format!("invalid work at {height}").into());
        }
        parent = header_hash(h);
        weight += u128::from(u64::MAX / threshold);
    }
    println!(
        "{}",
        json!({"archive":path,"blocks":archive.blocks.len(),"tip":hyphen_crypto::hex_encode(parent),"post_genesis_weight":weight.to_string(),"work_check_ns":start.elapsed().as_nanos() as u64})
    );
    Ok(())
}

fn main() -> Result<()> {
    reference_vector()?;
    for path in std::env::args_os().skip(1) {
        check_archive(Path::new(&path))?;
    }
    Ok(())
}

#[test]
fn frozen_vector_and_checkpoint_strides() {
    reference_vector().unwrap();
}
