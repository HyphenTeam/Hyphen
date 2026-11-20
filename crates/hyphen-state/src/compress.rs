use std::io::Read;
use thiserror::Error;

const ZSTD_LEVEL: i32 = 3;

#[derive(Debug, Error)]
pub enum CompressError {
    #[error("compression failed: {0}")]
    Compress(String),
    #[error("decompression failed: {0}")]
    Decompress(String),
}

#[inline]
pub fn compress(data: &[u8]) -> Result<Vec<u8>, CompressError> {
    if data.len() > crate::DEFAULT_WIRE_BYTES {
        return Err(CompressError::Compress("state exceeds byte limit".into()));
    }
    zstd::bulk::compress(data, ZSTD_LEVEL).map_err(|e| CompressError::Compress(e.to_string()))
}

#[inline]
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, CompressError> {
    decompress_bounded(data, crate::DEFAULT_WIRE_BYTES)
        .map_err(|e| CompressError::Decompress(e.to_string()))
}

fn decompress_bounded(data: &[u8], limit: usize) -> std::io::Result<Vec<u8>> {
    let mut decoder = zstd::stream::read::Decoder::new(data)?;
    decoder.window_log_max(crate::DEFAULT_WIRE_BYTES.ilog2())?;
    let mut output = Vec::new();
    decoder.take(limit as u64 + 1).read_to_end(&mut output)?;
    if output.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "state exceeds byte limit",
        ));
    }
    Ok(output)
}

pub struct CompressedTree {
    inner: sled::Tree,
}

impl CompressedTree {
    pub fn new(tree: sled::Tree) -> Self {
        Self { inner: tree }
    }

    pub fn insert(
        &self,
        key: impl AsRef<[u8]>,
        value: &[u8],
    ) -> Result<Option<Vec<u8>>, CompressError> {
        self.replace(key.as_ref(), Some(compress(value)?.into()))
    }

    pub fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, CompressError> {
        match self
            .inner
            .get(key)
            .map_err(|e| CompressError::Decompress(e.to_string()))?
        {
            Some(data) => Ok(Some(decompress(&data)?)),
            None => Ok(None),
        }
    }

    pub fn contains_key(&self, key: impl AsRef<[u8]>) -> Result<bool, CompressError> {
        self.inner
            .contains_key(key)
            .map_err(|e| CompressError::Decompress(e.to_string()))
    }

    pub fn remove(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, CompressError> {
        self.replace(key.as_ref(), None)
    }

    fn replace(
        &self,
        key: &[u8],
        next: Option<sled::IVec>,
    ) -> Result<Option<Vec<u8>>, CompressError> {
        let mut old = self.get_raw(key)?;
        loop {
            let value = old.as_deref().map(decompress).transpose()?;
            match self
                .inner
                .compare_and_swap(key, old, next.clone())
                .map_err(|e| CompressError::Compress(e.to_string()))?
            {
                Ok(()) => return Ok(value),
                Err(conflict) => old = conflict.current,
            }
        }
    }

    pub fn flush(&self) -> Result<(), CompressError> {
        self.inner
            .flush()
            .map_err(|e| CompressError::Compress(e.to_string()))?;
        Ok(())
    }

    pub fn iter(&self) -> CompressedIter {
        CompressedIter {
            inner: self.inner.iter(),
        }
    }

    pub fn insert_raw(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), CompressError> {
        self.inner
            .insert(key, value.as_ref())
            .map_err(|e| CompressError::Compress(e.to_string()))?;
        Ok(())
    }

    pub fn get_raw(&self, key: impl AsRef<[u8]>) -> Result<Option<sled::IVec>, CompressError> {
        self.inner
            .get(key)
            .map_err(|e| CompressError::Decompress(e.to_string()))
    }

    pub fn inner(&self) -> &sled::Tree {
        &self.inner
    }
}

pub struct CompressedIter {
    inner: sled::Iter,
}

impl Iterator for CompressedIter {
    type Item = Result<(sled::IVec, Vec<u8>), CompressError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next()? {
            Ok((key, val)) => match decompress(&val) {
                Ok(decompressed) => Some(Ok((key, decompressed))),
                Err(e) => Some(Err(e)),
            },
            Err(e) => Some(Err(CompressError::Decompress(e.to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_decompress_roundtrip() {
        let data = b"Hyphen blockchain data for compression testing, repeated enough to benefit from compression.";
        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn concatenated_frames_share_one_output_budget() {
        let data = compress(b"1234").unwrap().repeat(2);
        assert_eq!(decompress_bounded(&data, 8).unwrap(), b"12341234");
        assert_eq!(
            decompress_bounded(&data, 7).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn compressed_tree_roundtrip() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let tree = db.open_tree("test_compressed").unwrap();
        let ct = CompressedTree::new(tree);

        let key = b"block_hash_001";
        let value = b"serialized block data with lots of repeated content for compression";

        ct.insert(key, value).unwrap();
        let retrieved = ct.get(key).unwrap().unwrap();
        assert_eq!(value.as_slice(), retrieved.as_slice());
        assert!(ct.contains_key(key).unwrap());

        ct.remove(key).unwrap();
        assert!(!ct.contains_key(key).unwrap());

        ct.insert_raw(key, b"invalid snapshot").unwrap();
        assert!(ct.insert(key, value).is_err());
        assert!(ct.remove(key).is_err());
        assert_eq!(
            ct.get_raw(key).unwrap().unwrap().as_ref(),
            b"invalid snapshot"
        );
    }
}
