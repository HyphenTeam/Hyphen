#![no_main]

use hyphen_rpc::messages::RpcRequest;
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let _ = RpcRequest::decode(data);
});
