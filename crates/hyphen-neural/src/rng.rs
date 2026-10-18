//! ChaCha20 keystream generator.
//!
//! The challenge has to be reconstructible by the contract, by every miner and
//! by any auditor from a 32-byte seed alone. A cryptographic generator is used
//! instead of a small xorshift so that nothing about the next epoch's weights
//! can be predicted from a previous epoch's weights, and so the same code can
//! serve as the domain-separated derivation function for weights, preimages and
//! solver restarts.
//!
//! This is the RFC 8439 block function with a 96-bit nonce and a 32-bit block
//! counter. It protects no secret; it expands a public seed into public
//! pseudo-random data, deterministically and without an allocator.

/// Number of ChaCha20 rounds.
pub const ROUNDS: usize = 20;

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// Deterministic keystream over a 32-byte key and 12-byte nonce.
pub struct ChaCha20 {
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    buffer: [u8; 64],
    position: usize,
}

impl ChaCha20 {
    /// Creates a generator positioned at the start of block counter zero.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut key_words = [0u32; 8];
        for (word, chunk) in key_words.iter_mut().zip(key.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let mut nonce_words = [0u32; 3];
        for (word, chunk) in nonce_words.iter_mut().zip(nonce.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let mut generator = Self {
            key: key_words,
            nonce: nonce_words,
            counter: 0,
            buffer: [0u8; 64],
            position: 64,
        };
        generator.refill();
        generator
    }

    /// Creates a generator for a named derivation domain of one epoch.
    ///
    /// The domain tag separates weight derivation, preimage derivation and
    /// solver restarts: none of them can be derived from another's output.
    pub fn domain(seed: &[u8; 32], epoch: u64, domain: u32) -> Self {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&domain.to_le_bytes());
        nonce[4..].copy_from_slice(&epoch.to_le_bytes());
        Self::new(seed, &nonce)
    }

    fn refill(&mut self) {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&CONSTANTS);
        state[4..12].copy_from_slice(&self.key);
        state[12] = self.counter;
        state[13..].copy_from_slice(&self.nonce);

        let mut working = state;
        for _ in 0..ROUNDS / 2 {
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }
        for (index, chunk) in self.buffer.chunks_exact_mut(4).enumerate() {
            let word = working[index].wrapping_add(state[index]);
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        self.position = 0;
        self.counter = self.counter.wrapping_add(1);
    }

    fn next_byte(&mut self) -> u8 {
        if self.position == 64 {
            self.refill();
        }
        let byte = self.buffer[self.position];
        self.position += 1;
        byte
    }

    /// Returns the next 32-bit word of the keystream.
    pub fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([
            self.next_byte(),
            self.next_byte(),
            self.next_byte(),
            self.next_byte(),
        ])
    }

    /// Returns the next 64-bit little-endian word of the keystream.
    pub fn next_u64(&mut self) -> u64 {
        let low = self.next_u32() as u64;
        let high = self.next_u32() as u64;
        low | (high << 32)
    }

    /// Returns a uniform value in `[0, bound)` by rejection sampling.
    ///
    /// Returns `None` only for `bound == 0`. Rejection rather than a modulo
    /// keeps the mapping unbiased.
    pub fn next_below(&mut self, bound: u64) -> Option<u64> {
        if bound == 0 {
            return None;
        }
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let candidate = self.next_u64();
            if candidate < zone {
                return Some(candidate % bound);
            }
        }
    }

    /// Fills a byte slice with the keystream.
    pub fn fill(&mut self, destination: &mut [u8]) {
        for byte in destination.iter_mut() {
            *byte = self.next_byte();
        }
    }
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 section 2.3.2: key `00..1f`, nonce
    /// `00:00:00:09:00:00:00:4a:00:00:00:00`, block counter 1.
    #[test]
    fn matches_the_rfc_8439_block_vector() {
        let key: [u8; 32] = core::array::from_fn(|index| index as u8);
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let expected = [
            0xe4e7_f110u32,
            0x1559_3bd1,
            0x1fdd_0f50,
            0xc471_20a3,
            0xc7f4_d1c7,
            0x0368_c033,
            0x9aaa_2204,
            0x4e6c_d4c3,
            0x4664_82d2,
            0x09aa_9f07,
            0x05d7_c214,
            0xa202_8bd9,
            0xd19c_12b5,
            0xb94e_16de,
            0xe883_d0cb,
            0x4e3c_50a2,
        ];
        let mut generator = ChaCha20::new(&key, &nonce);
        // `new` already emitted block counter 0; the next block is counter 1.
        generator.refill();
        for word in expected {
            assert_eq!(generator.next_u32(), word);
        }
    }

    #[test]
    fn same_seed_same_stream_and_different_domains_differ() {
        let seed = [7u8; 32];
        let mut first = ChaCha20::domain(&seed, 9, 1);
        let mut second = ChaCha20::domain(&seed, 9, 1);
        let mut other = ChaCha20::domain(&seed, 9, 2);
        let mut other_epoch = ChaCha20::domain(&seed, 10, 1);
        for _ in 0..64 {
            let value = first.next_u64();
            assert_eq!(value, second.next_u64());
            assert_ne!(value, other.next_u64());
            assert_ne!(value, other_epoch.next_u64());
        }
    }

    #[test]
    fn bounded_values_respect_the_bound() {
        let mut generator = ChaCha20::domain(&[0u8; 32], 0, 3);
        for _ in 0..1000 {
            assert!(generator.next_below(7).unwrap() < 7);
        }
        assert_eq!(generator.next_below(0), None);
    }

    #[test]
    fn fill_and_next_u32_agree() {
        let seed = [3u8; 32];
        let mut bytes = [0u8; 100];
        ChaCha20::domain(&seed, 1, 1).fill(&mut bytes);
        let mut words = ChaCha20::domain(&seed, 1, 1);
        let mut expected = Vec::new();
        for _ in 0..25 {
            expected.extend_from_slice(&words.next_u32().to_le_bytes());
        }
        assert_eq!(&bytes[..], &expected[..]);
    }
}
