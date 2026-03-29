#![allow(clippy::needless_range_loop)]

#[inline]
pub fn execute_kernel(kernel_id: u8, page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    match kernel_id {
        0 => kernel_div_chain(page, state),
        1 => kernel_bit_weave(page, state),
        2 => kernel_sparse_step(page, state),
        3 => kernel_prefix_scan(page, state),
        4 => kernel_micro_sort(page, state),
        5 => kernel_var_decode(page, state),
        6 => kernel_hash_mix(page, state),
        7 => kernel_branch_maze(page, state),
        _ => kernel_div_chain(page, state), // fallback
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

fn kernel_div_chain(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }

    // 64 iterations: each uses page data as divisor, previous acc as dividend
    for step in 0..64u64 {
        let page_val = read_u64_le(page, (step as usize * 61) % page.len());
        let divisor = page_val.wrapping_add(3) | 3;
        let slot = step as usize % 8;
        let dividend = acc[slot].wrapping_add(acc[(slot + 1) % 8]).wrapping_add(step);
        acc[slot] = dividend / divisor;
        acc[(slot + 3) % 8] = acc[(slot + 3) % 8].wrapping_add(dividend % divisor);
    }
    to_output(&acc)
}

fn kernel_bit_weave(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }
    for step in 0..64u64 {
        let data = read_u64_le(page, (step as usize * 43 + 17) % page.len());
        let rot_amount = (data & 63) as u32;
        let slot = step as usize % 8;
        acc[slot] = acc[slot].rotate_left(rot_amount) ^ data;
        acc[(slot + 5) % 8] = acc[(slot + 5) % 8].rotate_right((acc[slot] & 63) as u32);
        acc[(slot + 2) % 8] ^= acc[slot].wrapping_mul(0x9E3779B97F4A7C15);
    }
    to_output(&acc)
}

fn kernel_sparse_step(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }

    // Simulate sparse matrix-vector multiply:
    // use page offsets as indirect indices into a virtual 512-element vector
    for step in 0..48u64 {
        let idx_raw = read_u64_le(page, (step as usize * 83) % page.len());
        let idx = (idx_raw as usize) % (page.len() / 8);
        let val = read_u64_le(page, idx * 8 % page.len());
        let slot = step as usize % 8;
        acc[slot] = acc[slot]
            .wrapping_add(val.wrapping_mul(acc[(slot + 1) % 8] | 1));
        acc[(slot + 4) % 8] ^= val.rotate_left((acc[slot] & 31) as u32);
    }
    to_output(&acc)
}

fn kernel_prefix_scan(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut arr = [0u64; 64];
    for i in 0..64 {
        arr[i] = read_u64_le(page, i * 61 % page.len())
            .wrapping_add(state_u64(state, i % 8));
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

fn kernel_micro_sort(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut arr = [0u64; 32];
    for i in 0..32 {
        arr[i] = read_u64_le(page, i * 127 % page.len())
            ^ state_u64(state, i % 8);
    }
    // Insertion sort – strongly branch-dependent, CPU-friendly
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
        acc[i % 8] = acc[i % 8].wrapping_add(arr[i].wrapping_mul(i as u64 + 1));
    }
    to_output(&acc)
}

fn kernel_var_decode(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    // LEB128-style variable-length decoding
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }
    let mut cursor = (state_u64(state, 0) as usize) % page.len();
    for step in 0..48u64 {
        // decode one LEB128 value
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
        acc[slot] = acc[slot].wrapping_add(result);
        acc[(slot + 3) % 8] ^= result.rotate_left((step as u32) & 63);
    }
    to_output(&acc)
}

static SBOX: [u8; 256] = [
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

fn kernel_hash_mix(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut block = [0u8; 64];
    block.copy_from_slice(state);

    for round in 0..16u32 {
        let page_off = (round as usize * 251) % (page.len().saturating_sub(16).max(1));
        // SubBytes
        for b in block.iter_mut() {
            *b = SBOX[*b as usize];
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

fn kernel_branch_maze(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for i in 0..8 {
        acc[i] = state_u64(state, i);
    }

    let mut cursor = (acc[0] as usize) % page.len();
    for step in 0..64u64 {
        let val = read_u64_le(page, cursor);
        let slot = step as usize % 8;

        // Multi-way branch
        match val & 0x07 {
            0 => {
                acc[slot] = acc[slot].wrapping_add(val);
                cursor = (cursor.wrapping_add(val as usize * 7)) % page.len();
            }
            1 => {
                acc[slot] = acc[slot].wrapping_sub(val.rotate_left(13));
                cursor = (cursor.wrapping_add(acc[slot] as usize)) % page.len();
            }
            2 => {
                acc[slot] ^= val.wrapping_mul(0xBF58476D1CE4E5B9);
                cursor = (cursor.wrapping_add(17 + step as usize)) % page.len();
            }
            3 => {
                let div = (val >> 32) | 1;
                acc[slot] = acc[slot].wrapping_mul(val | 1) / div;
                cursor = (cursor.wrapping_add(div as usize)) % page.len();
            }
            4 => {
                acc[slot] = acc[slot].rotate_left((val & 63) as u32);
                acc[(slot + 1) % 8] ^= val;
                cursor = (cursor.wrapping_add(acc[(slot + 1) % 8] as usize)) % page.len();
            }
            5 => {
                acc[slot] = acc[slot].wrapping_add(val.count_ones() as u64 * step);
                cursor = (cursor.wrapping_add(3 + val as usize)) % page.len();
            }
            6 => {
                acc[slot] = (acc[slot] ^ val).reverse_bits();
                cursor = (cursor.wrapping_add(acc[slot] as usize)) % page.len();
            }
            _ => {
                acc[slot] = acc[slot]
                    .wrapping_add(val)
                    .wrapping_mul(0x94D049BB133111EB);
                let jump = (val >> 8) as usize;
                cursor = (cursor.wrapping_add(jump)) % page.len();
            }
        }
    }
    to_output(&acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_kernels_produce_output() {
        let page = vec![0xABu8; 4096];
        let state = [0x42u8; 64];
        for k in 0..8 {
            let out = execute_kernel(k, &page, &state);
        // output should not be all zeros
            assert!(out.iter().any(|&b| b != 0), "kernel {k} produced zero output");
        }
    }
}
