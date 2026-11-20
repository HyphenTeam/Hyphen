use hyphen_crypto::Hash256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NullifierError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("duplicate nullifier")]
    Duplicate,
}

type Result<T> = std::result::Result<T, NullifierError>;

pub struct NullifierSet {
    pub(crate) tree: sled::Tree,
}

impl NullifierSet {
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            tree: db.open_tree("nullifiers")?,
        })
    }

    pub fn contains(&self, nullifier: &[u8; 32]) -> Result<bool> {
        Ok(self.tree.contains_key(nullifier)?)
    }

    pub fn spent_height(&self, nullifier: &[u8; 32]) -> Result<Option<u64>> {
        self.tree
            .get(nullifier)?
            .map(|height| {
                height
                    .as_ref()
                    .try_into()
                    .map(u64::from_le_bytes)
                    .map_err(|_| sled::Error::Unsupported("invalid nullifier height".into()).into())
            })
            .transpose()
    }

    /// Stream a sorted namespace of canonical key images without copying the set.
    pub fn with_prefix<'a>(&'a self, prefix: &[u8]) -> impl Iterator<Item = Result<[u8; 32]>> + 'a {
        self.tree.scan_prefix(prefix).keys().map(|entry| {
            entry?
                .as_ref()
                .try_into()
                .map_err(|_| sled::Error::Unsupported("invalid nullifier length".into()).into())
        })
    }

    pub fn insert(&self, nullifier: &[u8; 32], block_height: u64) -> Result<()> {
        let prev = self.tree.insert(nullifier, &block_height.to_le_bytes())?;
        if prev.is_some() {
            return Err(NullifierError::Duplicate);
        }
        Ok(())
    }

    pub fn remove(&self, nullifier: &[u8; 32]) -> Result<()> {
        self.tree.remove(nullifier)?;
        Ok(())
    }

    pub fn root_hash(&self) -> Result<Hash256> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"Hyphen_nullifier_root");
        for entry in self.tree.iter() {
            let (key, val) = entry?;
            hasher.update(&key);
            hasher.update(&val);
        }
        Ok(Hash256::from_bytes(*hasher.finalize().as_bytes()))
    }

    pub fn flush(&self) -> Result<()> {
        self.tree.flush()?;
        Ok(())
    }
}
