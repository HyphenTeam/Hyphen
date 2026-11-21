//! Capped NFT collection for the HYN3 signed Wasm ledger.
#![no_std]

#[path = "../include/abi.rs"]
mod abi;
use abi::{Account, caller, read, request, respond, write};
use core::arch::wasm32::unreachable;

#[used]
#[unsafe(link_section = "hyphen.app")]
static MANIFEST: [u8; 72] = *br#"{"abi":1,"category":"utility","name":"NFT Collection","version":"1.0.0"}"#;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unreachable()
}

const ZERO: Account = [0; 32];
const OWNER: core::ops::Range<usize> = 0..32;
const APPROVED: core::ops::Range<usize> = 32..64;
const METADATA: core::ops::Range<usize> = 64..96;
const REVISION: core::ops::Range<usize> = 96..104;

fn number(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

#[unsafe(no_mangle)]
pub extern "C" fn init() {
    let mut buf = [0; 8];
    let cap = number(request(&mut buf));
    assert!(cap > 0 && read::<32>(b"issuer").is_none());
    write(b"issuer", &caller());
    write(b"cap", &cap.to_le_bytes());
    write(b"issued", &0u64.to_le_bytes());
}

#[unsafe(no_mangle)]
pub extern "C" fn hyphen_execute() {
    let mut buf = [0; 65];
    let body = request(&mut buf);
    let signer = caller();
    if let [1, mint @ ..] = body {
        assert_eq!(mint.len(), 64);
        assert_eq!(Some(signer), read(b"issuer"));
        assert_ne!(mint[..32], ZERO);
        let id = number(&read::<8>(b"issued").unwrap())
            .checked_add(1)
            .unwrap();
        assert!(id <= number(&read::<8>(b"cap").unwrap()));
        let mut token = [0; 104];
        token[OWNER].copy_from_slice(&mint[..32]);
        token[METADATA].copy_from_slice(&mint[32..]);
        write(&id.to_le_bytes(), &token);
        write(b"issued", &id.to_le_bytes());
        respond(&id.to_le_bytes());
        return;
    }
    assert!(body.len() >= 17);
    let key = &body[1..9];
    let mut token = read::<104>(key).unwrap();
    let owner: Account = token[OWNER].try_into().unwrap();
    assert_ne!(owner, ZERO);
    let revision = number(&token[REVISION]);
    assert_eq!(number(&body[9..17]), revision);
    match (body[0], &body[17..]) {
        (2, to) if to.len() == 32 => {
            assert!(signer == owner || signer == token[APPROVED]);
            assert!(to != ZERO && to != owner);
            token[OWNER].copy_from_slice(to);
            token[APPROVED].fill(0);
        }
        (3, delegate) if delegate.len() == 32 => {
            assert!(signer == owner && delegate != owner);
            token[APPROVED].copy_from_slice(delegate);
        }
        (4, []) => {
            assert_eq!(signer, owner);
            token[OWNER].fill(0);
            token[APPROVED].fill(0);
        }
        _ => unreachable(),
    }
    token[REVISION].copy_from_slice(&revision.checked_add(1).unwrap().to_le_bytes());
    write(key, &token);
}

#[unsafe(no_mangle)]
pub extern "C" fn hyphen_query() {
    let mut buf = [0; 9];
    match request(&mut buf) {
        [0] => {
            let mut result = [0; 48];
            result[..32].copy_from_slice(&read::<32>(b"issuer").unwrap());
            result[32..40].copy_from_slice(&read::<8>(b"cap").unwrap());
            result[40..].copy_from_slice(&read::<8>(b"issued").unwrap());
            respond(&result);
        }
        [1, id @ ..] if id.len() == 8 => {
            let token = read::<104>(id);
            respond(token.as_ref().map_or(&[], |value| value.as_slice()));
        }
        _ => unreachable(),
    }
}
