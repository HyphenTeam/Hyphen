#![no_main]

use hyphen_tx::Transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Transaction::deserialise_limited(data);
});
