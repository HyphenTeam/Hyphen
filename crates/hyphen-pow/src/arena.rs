use blake3::Hasher as B3;
use hyphen_crypto::Hash256;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArenaParams {
    pub total_size: usize,
    pub page_size: usize,
    pub epoch_seed: Hash256,
}

impl ArenaParams {
    pub fn page_count(&self) -> usize {
        self.total_size / self.page_size
    }
}

pub struct EpochArena {
    pub params: ArenaParams,
    pub data: Vec<u8>,
}

impl EpochArena {
    pub fn generate(epoch_seed: Hash256, total_size: usize, page_size: usize) -> Self {
        assert!(total_size >= page_size && page_size >= 64);
        assert!(total_size.is_multiple_of(page_size));
        let page_count = total_size / page_size;
        let mut data = vec![0u8; total_size];

        let key: [u8; 32] = *epoch_seed.as_bytes();
        for p in 0..page_count {
            let offset = p * page_size;
            let mut hasher = B3::new_keyed(&key);
            hasher.update(&(p as u64).to_le_bytes());
            let mut reader = hasher.finalize_xof();
            reader.fill(&mut data[offset..offset + page_size]);
        }

        for p in 0..page_count {
            let offset = p * page_size;
            let mut link_seed = [0u8; 32];
            link_seed.copy_from_slice(&data[offset + page_size - 32..offset + page_size]);

            let mut hasher = B3::new_keyed(&key);
            hasher.update(&link_seed);
            let link_hash: [u8; 32] = hasher.finalize().into();

            for i in 0..4 {
                let start = i * 8;
                let raw = u64::from_le_bytes(link_hash[start..start + 8].try_into().unwrap());
                let target = (raw % page_count as u64).to_le_bytes();
                data[offset + i * 8..offset + i * 8 + 8].copy_from_slice(&target);
            }
        }

        Self {
            params: ArenaParams {
                total_size,
                page_size,
                epoch_seed,
            },
            data,
        }
    }

    #[inline]
    pub fn page(&self, index: usize) -> &[u8] {
        let off = index * self.params.page_size;
        &self.data[off..off + self.params.page_size]
    }

    #[inline]
    pub fn page_link(&self, page_index: usize, link_slot: usize) -> usize {
        assert!(link_slot < 4);
        let off = page_index * self.params.page_size + link_slot * 8;
        let raw = u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap());
        raw as usize % self.params.page_count()
    }
}
