#![no_main]

use std::collections::BTreeMap;

use hyphen_codec::{deserialize_with_limits, Limits};
use libfuzzer_sys::fuzz_target;

type NestedCorpus = (
    bool,
    Option<char>,
    Vec<u64>,
    BTreeMap<String, Vec<u8>>,
    Vec<Vec<Option<u32>>>,
);

fuzz_target!(|data: &[u8]| {
    let limits = Limits::new(1024 * 1024, 4096, 32);
    let _ = deserialize_with_limits::<NestedCorpus>(data, limits);
});
