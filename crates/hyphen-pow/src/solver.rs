use hyphen_core::block::BlockHeader;
use hyphen_core::config::ChainConfig;
use hyphen_crypto::Hash256;

use crate::arena::EpochArena;
use crate::difficulty::difficulty_to_target;
use crate::kernels::{execute_kernel, EpochKernelParams};
use crate::scratchpad::Scratchpad;

#[derive(Clone, Debug)]
pub struct PowResult {
    pub hash: Hash256,
    pub nonce: u64,
    pub extra_nonce: [u8; 32],
}

pub fn evaluate_pow(
    header: &BlockHeader,
    arena: &EpochArena,
    cfg: &ChainConfig,
) -> Hash256 {
    let epoch = EpochKernelParams::derive(arena.params.epoch_seed.as_bytes());
    evaluate_pow_with_epoch(header, arena, cfg, &epoch)
}

/// Evaluate PoW with pre-computed epoch params (avoids re-deriving per nonce).
pub fn evaluate_pow_with_epoch(
    header: &BlockHeader,
    arena: &EpochArena,
    cfg: &ChainConfig,
    epoch: &EpochKernelParams,
) -> Hash256 {
    let header_bytes = header.serialise_for_hash();
    let seed = hyphen_crypto::blake3_hash(&header_bytes);

    let mut sp = Scratchpad::new(cfg.scratchpad_size, &seed);

    let page_count = arena.params.page_count();

    for round in 0..cfg.pow_rounds {
        let page_idx = sp.next_page(page_count);
        let page = arena.page(page_idx);

        let kernel_id = sp.select_kernel(page[32], cfg.kernel_count);

        let kernel_out = execute_kernel(kernel_id, page, &sp.state, epoch);

        sp.mix_state(&kernel_out);

        let write_pos = u64::from_le_bytes(kernel_out[0..8].try_into().unwrap()) as usize;
        let write_val = u64::from_le_bytes(kernel_out[8..16].try_into().unwrap());
        sp.write_u64(write_pos, write_val);

        let link_slot = sp.select_link();
        let linked_page = arena.page_link(page_idx, link_slot);
        let link_data = arena.page(linked_page);
        let link_mix = u64::from_le_bytes(link_data[32..40].try_into().unwrap());
        sp.write_u64(write_pos.wrapping_add(8), link_mix);

        if round % cfg.writeback_interval == 0 {
            sp.writeback();
        }
    }

    sp.finalize()
}

pub fn try_nonce(
    header: &mut BlockHeader,
    arena: &EpochArena,
    cfg: &ChainConfig,
    nonce: u64,
) -> Option<PowResult> {
    header.nonce = nonce;
    let epoch = EpochKernelParams::derive(arena.params.epoch_seed.as_bytes());
    let hash = evaluate_pow_with_epoch(header, arena, cfg, &epoch);
    let target = difficulty_to_target(header.difficulty);
    if hash_below_target(&hash, &target) {
        Some(PowResult {
            hash,
            nonce,
            extra_nonce: header.extra_nonce,
        })
    } else {
        None
    }
}

pub fn mine_block(
    header: &mut BlockHeader,
    arena: &EpochArena,
    cfg: &ChainConfig,
) -> PowResult {
    let epoch = EpochKernelParams::derive(arena.params.epoch_seed.as_bytes());
    let mut nonce = header.nonce;
    loop {
        header.nonce = nonce;
        let hash = evaluate_pow_with_epoch(header, arena, cfg, &epoch);
        let target = difficulty_to_target(header.difficulty);
        if hash_below_target(&hash, &target) {
            return PowResult {
                hash,
                nonce,
                extra_nonce: header.extra_nonce,
            };
        }
        nonce = nonce.wrapping_add(1);
    }
}

pub fn verify_pow(
    header: &BlockHeader,
    arena: &EpochArena,
    cfg: &ChainConfig,
) -> bool {
    let hash = evaluate_pow(header, arena, cfg);
    let target = difficulty_to_target(header.difficulty);
    hash_below_target(&hash, &target)
}

fn hash_below_target(hash: &Hash256, target: &[u8; 32]) -> bool {
    for (h, t) in hash.as_bytes().iter().zip(target.iter()) {
        match h.cmp(t) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    true
}
