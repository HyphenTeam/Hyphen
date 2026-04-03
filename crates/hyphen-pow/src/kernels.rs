#![allow(clippy::needless_range_loop)]

// EMK: Epoch-Mutating Kernels — kernel constants (rotation amounts,
// S-Box permutations, mixing coefficients, stride salts) are derived from
// the epoch seed each epoch, making fixed-function hardware sub-optimal.

/// Epoch-derived parameters that mutate kernel behaviour.
///
/// Generated deterministically from the epoch seed so that all nodes
/// agree on the same constants for the same epoch.
#[derive(Clone)]
pub struct EpochKernelParams {
    /// 256-byte S-Box, Fisher-Yates shuffled from the AES S-Box using
    /// epoch-derived randomness.
    pub sbox: [u8; 256],
    /// 12 per-kernel rotation offsets (one per kernel).  Each is in [0, 63].
    pub rot_offsets: [u32; 12],
    /// 12 per-kernel mixing multiplicands.
    pub mix_constants: [u64; 12],
    /// 8 slot-permutation indices for cross-lane mixing.
    pub slot_perm: [usize; 8],
    /// Stride mutator for page-offset stepping in each kernel.
    pub stride_salt: [u64; 12],
}

impl EpochKernelParams {
    /// Derive all mutable kernel parameters from a 32-byte epoch seed.
    pub fn derive(epoch_seed: &[u8; 32]) -> Self {
        // Use BLAKE3 in keyed mode to produce a long deterministic stream
        let key: [u8; 32] = *epoch_seed;
        let mut h = blake3::Hasher::new_keyed(&key);
        h.update(b"EMK_epoch_kernel_params_v1");
        let mut xof = h.finalize_xof();

        // ── S-Box: Fisher-Yates shuffle of the base AES S-Box ──
        let mut sbox = BASE_SBOX;
        let mut rand_buf = [0u8; 512]; // enough for 256 swaps
        xof.fill(&mut rand_buf);
        for i in (1..256).rev() {
            let j = (u16::from_le_bytes([rand_buf[i * 2], rand_buf[i * 2 + 1]]) as usize)
                % (i + 1);
            sbox.swap(i, j);
        }

        // ── rotation offsets ──
        let mut rot_buf = [0u8; 12];
        xof.fill(&mut rot_buf);
        let mut rot_offsets = [0u32; 12];
        for i in 0..12 {
            rot_offsets[i] = (rot_buf[i] & 63) as u32;
        }

        // ── mixing multiplicands (odd, to preserve invertibility) ──
        let mut mix_buf = [0u8; 96];
        xof.fill(&mut mix_buf);
        let mut mix_constants = [0u64; 12];
        for i in 0..12 {
            mix_constants[i] =
                u64::from_le_bytes(mix_buf[i * 8..(i + 1) * 8].try_into().unwrap()) | 1;
        }

        // ── slot permutation (Knuth shuffle of [0..8]) ──
        let mut slot_perm = [0usize, 1, 2, 3, 4, 5, 6, 7];
        let mut perm_buf = [0u8; 8];
        xof.fill(&mut perm_buf);
        for i in (1..8).rev() {
            let j = (perm_buf[i] as usize) % (i + 1);
            slot_perm.swap(i, j);
        }

        // ── per-kernel stride salts ──
        let mut stride_buf = [0u8; 96];
        xof.fill(&mut stride_buf);
        let mut stride_salt = [0u64; 12];
        for i in 0..12 {
            // Stride between 31 and 251 (prime-ish range) for good page coverage
            let raw =
                u64::from_le_bytes(stride_buf[i * 8..(i + 1) * 8].try_into().unwrap());
            stride_salt[i] = 31 + (raw % 221);
        }

        Self {
            sbox,
            rot_offsets,
            mix_constants,
            slot_perm,
            stride_salt,
        }
    }
}

#[inline]
pub fn execute_kernel(
    kernel_id: u8,
    page: &[u8],
    state: &[u8; 64],
    epoch: &EpochKernelParams,
) -> [u8; 64] {
    match kernel_id {
        0 => kernel_div_chain(page, state, epoch),
        1 => kernel_bit_weave(page, state, epoch),
        2 => kernel_sparse_step(page, state, epoch),
        3 => kernel_prefix_scan(page, state, epoch),
        4 => kernel_micro_sort(page, state, epoch),
        5 => kernel_var_decode(page, state, epoch),
        6 => kernel_hash_mix(page, state, epoch),
        7 => kernel_branch_maze(page, state, epoch),
        8 => kernel_aes_cascade(page, state, epoch),
        9 => kernel_float_emulate(page, state, epoch),
        10 => kernel_scatter_gather(page, state, epoch),
        11 => kernel_mod_exp_chain(page, state, epoch),
        _ => kernel_div_chain(page, state, epoch), // fallback
    }
}

#[inline]
fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    let o = off % (buf.len().saturating_sub(7).max(1));
    u64::from_le_bytes(buf[o..o + 8].try_into().unwrap())
}

#[inline]
fn state_u64(state: &[u8; 64], idx: usize) -> u64 {
    u64::from_le_bytes(state[idx * 8..(idx + 1) * 8].try_into().unwrap())
}

fn to_output(vals: &[u64; 8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, v) in vals.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}

fn kernel_div_chain(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }
    let stride = ep.stride_salt[0] as usize;
    let rot = ep.rot_offsets[0];

    for step in 0..64u64 {
        let page_val = read_u64_le(page, (step as usize).wrapping_mul(stride) % page.len());
        let divisor = page_val.wrapping_add(3) | 3;
        let slot = step as usize % 8;
        let dividend = acc[slot].wrapping_add(acc[(slot + 1) % 8]).wrapping_add(step);
        acc[slot] = dividend / divisor;
        acc[(slot + 3) % 8] = acc[(slot + 3) % 8]
            .wrapping_add(dividend % divisor)
            .rotate_left(rot);
    }
    to_output(&acc)
}

fn kernel_bit_weave(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }
    let stride = ep.stride_salt[1] as usize;
    let mix_c = ep.mix_constants[1];
    let rot_off = ep.rot_offsets[1];
    for step in 0..64u64 {
        let data = read_u64_le(page, (step as usize).wrapping_mul(stride).wrapping_add(17) % page.len());
        let rot_amount = ((data & 63) as u32).wrapping_add(rot_off) & 63;
        let slot = step as usize % 8;
        acc[slot] = acc[slot].rotate_left(rot_amount) ^ data;
        acc[(slot + 5) % 8] = acc[(slot + 5) % 8].rotate_right((acc[slot] & 63) as u32);
        acc[(slot + 2) % 8] ^= acc[slot].wrapping_mul(mix_c);
    }
    to_output(&acc)
}

fn kernel_sparse_step(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }
    let stride = ep.stride_salt[2] as usize;
    let mix_c = ep.mix_constants[2];

    for step in 0..48u64 {
        let idx_raw = read_u64_le(page, (step as usize).wrapping_mul(stride) % page.len());
        let idx = (idx_raw as usize) % (page.len() / 8);
        let val = read_u64_le(page, idx * 8 % page.len());
        let slot = step as usize % 8;
        acc[slot] = acc[slot]
            .wrapping_add(val.wrapping_mul(acc[(slot + 1) % 8] | 1));
        acc[(slot + 4) % 8] ^= val.rotate_left((acc[slot] & 31) as u32)
            .wrapping_mul(mix_c);
    }
    to_output(&acc)
}

fn kernel_prefix_scan(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let stride = ep.stride_salt[3] as usize;
    let mix = ep.mix_constants[3];
    let mut arr = [0u64; 64];
    for i in 0..64 {
        arr[i] = read_u64_le(page, i.wrapping_mul(stride) % page.len())
            .wrapping_add(state_u64(state, i % 8))
            ^ mix.wrapping_mul(i as u64);
    }
    // Blelloch-style up-sweep
    let mut d = 1;
    while d < 64 {
        let mut i = 0;
        while i < 64 {
            let left = i + d - 1;
            let right = i + 2 * d - 1;
            if right < 64 {
                arr[right] = arr[right].wrapping_add(arr[left]);
            }
            i += 2 * d;
        }
        d *= 2;
    }
    // Down-sweep
    arr[63] = 0;
    d = 32;
    while d >= 1 {
        let mut i = 0;
        while i < 64 {
            let left = i + d - 1;
            let right = i + 2 * d - 1;
            if right < 64 {
                let tmp = arr[left];
                arr[left] = arr[right];
                arr[right] = arr[right].wrapping_add(tmp);
            }
            i += 2 * d;
        }
        d /= 2;
    }

    let mut acc = [0u64; 8];
    for i in 0..64 {
        acc[i % 8] ^= arr[i];
    }
    to_output(&acc)
}

fn kernel_micro_sort(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let stride = ep.stride_salt[4] as usize;
    let mix_c = ep.mix_constants[4];
    let mut arr = [0u64; 32];
    for i in 0..32 {
        arr[i] = read_u64_le(page, i.wrapping_mul(stride) % page.len())
            ^ state_u64(state, i % 8);
    }
    for i in 1..32 {
        let key = arr[i];
        let mut j = i;
        while j > 0 && arr[j - 1] > key {
            arr[j] = arr[j - 1];
            j -= 1;
        }
        arr[j] = key;
    }
    let mut acc = [0u64; 8];
    for i in 0..32 {
        acc[i % 8] = acc[i % 8].wrapping_add(arr[i].wrapping_mul((i as u64 + 1).wrapping_mul(mix_c)));
    }
    to_output(&acc)
}

fn kernel_var_decode(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }
    let rot_off = ep.rot_offsets[5];
    let mix_c = ep.mix_constants[5];
    let mut cursor = (state_u64(state, 0) as usize) % page.len();
    for step in 0..48u64 {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        for _ in 0..10 {
            let byte = page[cursor % page.len()];
            cursor = cursor.wrapping_add(1);
            result |= ((byte & 0x7F) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 || shift >= 64 {
                break;
            }
        }
        let slot = step as usize % 8;
        acc[slot] = acc[slot].wrapping_add(result.wrapping_mul(mix_c));
        acc[(slot + 3) % 8] ^= result.rotate_left(((step as u32) & 63).wrapping_add(rot_off) & 63);
    }
    to_output(&acc)
}

static BASE_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

fn kernel_hash_mix(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let mut block = [0u8; 64];
    block.copy_from_slice(state);
    let stride = ep.stride_salt[6] as usize;

    for round in 0..16u32 {
        let page_off = (round as usize).wrapping_mul(stride) % (page.len().saturating_sub(16).max(1));
        // SubBytes through epoch-mutated S-Box
        for b in block.iter_mut() {
            *b = ep.sbox[*b as usize];
        }
        // XOR with page data
        for i in 0..16 {
            block[i + (round as usize % 4) * 16] ^= page[page_off + i % page.len().min(16)];
        }
        // MixColumns-style
        for col in 0..4 {
            let base = col * 16;
            let a = block[base];
            block[base] = block[base + 1];
            block[base + 1] = block[base + 2];
            block[base + 2] = block[base + 3];
            block[base + 3] = a ^ block[base];
        }
    }
    block
}

fn kernel_branch_maze(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }
    let mix_c = ep.mix_constants[7];
    let rot_off = ep.rot_offsets[7];
    let stride = ep.stride_salt[7] as usize;

    let mut cursor = (acc[0] as usize) % page.len();
    for step in 0..64u64 {
        let val = read_u64_le(page, cursor);
        let slot = step as usize % 8;
        let cross = ep.slot_perm[slot];

        match val & 0x07 {
            0 => {
                acc[slot] = acc[slot].wrapping_add(val);
                cursor = (cursor.wrapping_add((val as usize).wrapping_mul(stride))) % page.len();
            }
            1 => {
                acc[slot] = acc[slot].wrapping_sub(val.rotate_left(rot_off & 63));
                cursor = (cursor.wrapping_add(acc[slot] as usize)) % page.len();
            }
            2 => {
                acc[slot] ^= val.wrapping_mul(mix_c);
                cursor = (cursor.wrapping_add(17 + step as usize)) % page.len();
            }
            3 => {
                let div = (val >> 32) | 1;
                acc[slot] = acc[slot].wrapping_mul(val | 1) / div;
                cursor = (cursor.wrapping_add(div as usize)) % page.len();
            }
            4 => {
                acc[slot] = acc[slot].rotate_left(((val & 63) as u32).wrapping_add(rot_off) & 63);
                acc[cross] ^= val;
                cursor = (cursor.wrapping_add(acc[cross] as usize)) % page.len();
            }
            5 => {
                acc[slot] = acc[slot].wrapping_add((val.count_ones() as u64).wrapping_mul(step));
                cursor = (cursor.wrapping_add(stride + val as usize)) % page.len();
            }
            6 => {
                acc[slot] = (acc[slot] ^ val).reverse_bits();
                cursor = (cursor.wrapping_add(acc[slot] as usize)) % page.len();
            }
            _ => {
                acc[slot] = acc[slot]
                    .wrapping_add(val)
                    .wrapping_mul(mix_c);
                let jump = (val >> 8) as usize;
                cursor = (cursor.wrapping_add(jump)) % page.len();
            }
        }
        // Epoch-dependent post-step diffusion
        acc[slot] ^= mix_c.wrapping_mul(step.wrapping_add(1));
    }
    to_output(&acc)
}

// ─── Kernel 8: AES S-Box cascade with data-dependent mixing ───
// Uses the full AES S-Box in a feedback loop where every output byte feeds
// the next round as index.  GPUs lack native AES-NI; CPUs with AES-NI can
// accelerate SubBytes but the serial dependency chain prevents parallelism.
fn kernel_aes_cascade(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let mut buf = [0u8; 64];
    buf.copy_from_slice(state);
    let stride = ep.stride_salt[8] as usize;

    for round in 0..24u32 {
        let page_off = (round as usize).wrapping_mul(stride) % page.len().saturating_sub(64).max(1);

        // SubBytes through epoch-mutated S-Box (serial dependency chain)
        for i in 0..64 {
            buf[i] = ep.sbox[buf[i] as usize];
        }

        // ShiftRows-inspired rotation: each 16-byte lane rotated by lane index
        for lane in 0..4usize {
            let base = lane * 16;
            let shift = lane + 1;
            let mut tmp = [0u8; 16];
            for i in 0..16 {
                tmp[i] = buf[base + (i + shift) % 16];
            }
            buf[base..base + 16].copy_from_slice(&tmp);
        }

        // XOR with page data (memory dependency)
        let safe_len = page.len().min(page_off + 64) - page_off;
        for i in 0..safe_len.min(64) {
            buf[i] ^= page[page_off + i];
        }

        // MixColumns-style: Galois field multiply-accumulate across columns
        for col in 0..16 {
            let a = buf[col] as u16;
            let b = buf[col + 16] as u16;
            let c = buf[col + 32] as u16;
            let d = buf[col + 48] as u16;
            let mixed = (a.wrapping_mul(2) ^ b.wrapping_mul(3) ^ c ^ d) as u8;
            buf[col] ^= mixed;
            buf[col + 16] ^= (a ^ b.wrapping_mul(2) ^ c.wrapping_mul(3) ^ d) as u8;
            buf[col + 32] ^= (a ^ b ^ c.wrapping_mul(2) ^ d.wrapping_mul(3)) as u8;
            buf[col + 48] ^= (a.wrapping_mul(3) ^ b ^ c ^ d.wrapping_mul(2)) as u8;
        }
    }
    buf
}

// ─── Kernel 9: Floating-point emulated arithmetic ───
// Emulates an IEEE-754-like pipeline using integer arithmetic.
// ASICs optimise for either integer or float, rarely both well.
// We encode f64 ops as u64 bit patterns to create execution diversity.
fn kernel_float_emulate(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }
    let stride = ep.stride_salt[9] as usize;
    let mix_c = ep.mix_constants[9];

    for step in 0..64u64 {
        let data = read_u64_le(page, (step as usize).wrapping_mul(stride) % page.len());
        let slot = step as usize % 8;

        // Convert to f64, perform transcendental-like computation, convert back
        // We avoid actual f64 (non-deterministic on some HW) and instead
        // emulate fixed-point arithmetic at 32.32 precision.
        let a_hi = (acc[slot] >> 32) as u32;
        let a_lo = acc[slot] as u32;
        let d_hi = (data >> 32) as u32;
        let d_lo = data as u32;

        // Fixed-point multiply: (a_hi.a_lo) * (d_hi.d_lo) keeping middle bits
        let cross1 = (a_hi as u64).wrapping_mul(d_lo as u64);
        let cross2 = (a_lo as u64).wrapping_mul(d_hi as u64);
        let full = (a_hi as u64).wrapping_mul(d_hi as u64);
        let mid = cross1.wrapping_add(cross2).wrapping_add(full << 16);

        // Approximate reciprocal: Newton–Raphson style
        let denom = data | 0x8000_0000_0000_0001; // ensure nonzero
        let est = (u64::MAX / denom).wrapping_add(1);
        let refined = est.wrapping_mul(2u64.wrapping_sub(denom.wrapping_mul(est) >> 32));

        acc[slot] = mid ^ refined;
        acc[(slot + 3) % 8] = acc[(slot + 3) % 8].wrapping_add(
            mid.wrapping_mul(mix_c).rotate_left((step as u32) & 63),
        );
        acc[(slot + 6) % 8] ^= refined.wrapping_sub(acc[slot]);
    }
    to_output(&acc)
}

// ─── Kernel 10: Recursive memory scatter-gather ───
// Reads from data-dependent page offsets, then writes results back to a
// local scratchpad before re-reading.  This creates a long dependency chain
// that rewards large CPU caches and deep out-of-order pipelines.
fn kernel_scatter_gather(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let mut scratch = [0u8; 2048];
    for i in 0..2048 {
        scratch[i] = state[i % 64] ^ (i as u8).wrapping_mul(0x9D);
    }

    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }
    let mix_c = ep.mix_constants[10];
    let rot_off = ep.rot_offsets[10];

    for step in 0..80u64 {
        let slot = step as usize % 8;
        let cross = ep.slot_perm[slot];

        let page_idx = (acc[slot] as usize) % page.len().saturating_sub(7).max(1);
        let page_val = read_u64_le(page, page_idx);

        let scratch_idx = (page_val as usize) % (2048 - 7);
        let scratch_val = u64::from_le_bytes(
            scratch[scratch_idx..scratch_idx + 8].try_into().unwrap(),
        );

        let mixed = page_val
            .wrapping_mul(scratch_val | 1)
            .rotate_left(((acc[(slot + 1) % 8] & 63) as u32).wrapping_add(rot_off) & 63);
        acc[slot] = acc[slot].wrapping_add(mixed);

        let wb_idx = (acc[slot] as usize) % (2048 - 7);
        scratch[wb_idx..wb_idx + 8].copy_from_slice(&acc[slot].to_le_bytes());

        // Cross-lane mixing via epoch-permuted slot
        acc[cross] ^= acc[slot].wrapping_mul(mix_c);
    }
    to_output(&acc)
}

// ─── Kernel 11: Modular exponentiation chain ───
// Performs repeated modular multiplications over a 128-bit modulus.
// Division / modulo operations are expensive for ASICs but cheap on CPUs
// with hardware dividers.  The chain is fully serial.
fn kernel_mod_exp_chain(page: &[u8], state: &[u8; 64], ep: &EpochKernelParams) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }
    let stride = ep.stride_salt[11] as usize;
    let mix_c = ep.mix_constants[11];

    for step in 0..56u64 {
        let slot = step as usize % 8;
        let data = read_u64_le(page, (step as usize).wrapping_mul(stride) % page.len());

        // Build a 64-bit modulus from page+state data (always odd, never zero)
        let modulus = data.wrapping_add(acc[(slot + 2) % 8]) | 0x8000_0000_0000_0001;

        // Sequential modular multiply chain (6 iterations)
        let mut base = acc[slot];
        let mut result: u64 = 1;
        let exp_bits = acc[(slot + 1) % 8];

        for bit in 0..6u32 {
            // Square
            let sq = (base as u128).wrapping_mul(base as u128);
            base = (sq % modulus as u128) as u64;

            // Conditional multiply
            if (exp_bits >> (bit * 10)) & 1 == 1 {
                let prod = (result as u128).wrapping_mul(base as u128);
                result = (prod % modulus as u128) as u64;
            }
        }

        acc[slot] = result;
        // Feedback: combine remainder into another lane
        let remainder = acc[slot] % (data | 1);
        acc[(slot + 5) % 8] = acc[(slot + 5) % 8]
            .wrapping_add(remainder.wrapping_mul(mix_c))
            .rotate_left((step as u32) & 63);
    }
    to_output(&acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_kernels_produce_output() {
        let seed = [0xAA_u8; 32];
        let ep = EpochKernelParams::derive(&seed);
        let page = vec![0xABu8; 4096];
        let state = [0x42u8; 64];
        for k in 0..12 {
            let out = execute_kernel(k, &page, &state, &ep);
            assert!(out.iter().any(|&b| b != 0), "kernel {k} produced zero output");
        }
    }

    #[test]
    fn different_epochs_different_results() {
        let page = vec![0xABu8; 4096];
        let state = [0x42u8; 64];
        let ep1 = EpochKernelParams::derive(&[1u8; 32]);
        let ep2 = EpochKernelParams::derive(&[2u8; 32]);
        for k in 0..12 {
            let out1 = execute_kernel(k, &page, &state, &ep1);
            let out2 = execute_kernel(k, &page, &state, &ep2);
            assert_ne!(out1, out2, "kernel {k} should differ across epochs");
        }
    }
}
