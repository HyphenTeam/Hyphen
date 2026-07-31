#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;

type NestedCorpus = (
    bool,
    Option<char>,
    Vec<u64>,
    BTreeMap<String, Vec<u8>>,
    Vec<Vec<Option<u32>>>,
);

fuzz_target!(|data: &[u8]| {
    let _ = rustbinary::legacy_options()
        .with_little_endian()
        .with_fixint_encoding()
        .with_limit(1024 * 1024)
        .with_collection_limit(4096)
        .reject_trailing_bytes()
        .deserialize::<NestedCorpus>(data);
});
