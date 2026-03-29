use hyphen_crypto::Hash256;

pub struct Scratchpad {
    pub data: Vec<u8>,
    pub state: [u8; 64],
}

impl Scratchpad {
    pub fn new(size: usize, seed: &Hash256) -> Self {
        assert!(size >= 64);
        let mut data = vec![0u8; size];

        let key: [u8; 32] = *seed.as_bytes();
        let hasher = blake3::Hasher::new_keyed(&key);
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut data);

        let mut state = [0u8; 64];
        state[..32].copy_from_slice(seed.as_bytes());
        let h2 = blake3::keyed_hash(&key, &data[..64]);
        state[32..].copy_from_slice(&h2.as_bytes()[..32]);

        Self { data, state }
    }

    #[inline]
    pub fn read_u64(&self, pos: usize) -> u64 {
        let idx = pos % (self.data.len() - 7);
        u64::from_le_bytes(self.data[idx..idx + 8].try_into().unwrap())
    }

    #[inline]
    pub fn write_u64(&mut self, pos: usize, val: u64) {
        let idx = pos % (self.data.len() - 7);
        self.data[idx..idx + 8].copy_from_slice(&val.to_le_bytes());
    }

    #[inline]
    pub fn mix_state(&mut self, kernel_out: &[u8; 64]) {
        for (s, k) in self.state.iter_mut().zip(kernel_out.iter()) {
            *s ^= *k;
        }
    }

    pub fn writeback(&mut self) {
        let pos_raw = u64::from_le_bytes(self.state[0..8].try_into().unwrap()) as usize;
        let base = pos_raw % (self.data.len().saturating_sub(64));
        for i in 0..64 {
            self.data[base + i] ^= self.state[i];
        }
    }

    #[inline]
    pub fn next_page(&self, page_count: usize) -> usize {
        let raw = u64::from_le_bytes(self.state[8..16].try_into().unwrap());
        raw as usize % page_count
    }

    #[inline]
    pub fn select_kernel(&self, page_first_byte: u8, kernel_count: u8) -> u8 {
        let mix = self.state[16] ^ page_first_byte;
        mix % kernel_count
    }

    #[inline]
    pub fn select_link(&self) -> usize {
        (self.state[17] & 0x03) as usize
    }

    pub fn finalize(&self) -> Hash256 {
        let full = blake3::keyed_hash(
            self.state[..32].try_into().unwrap(),
            &self.data,
        );
        Hash256::from_bytes(*full.as_bytes())
    }
}
