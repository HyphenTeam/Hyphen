//! Fixed-supply, two-asset market for the Hyphen Wasm ABI.
#![no_std]

use core::arch::wasm32::unreachable;
#[path = "../include/abi.rs"]
mod abi;
use abi::{Account, caller, read, request, respond, write};

#[used]
#[unsafe(link_section = "hyphen.app")]
static MANIFEST: [u8; 67] =
    *br#"{"abi":1,"category":"defi","name":"Limit Orders","version":"1.0.0"}"#;

#[link(wasm_import_module = "env")]
unsafe extern "C" {
    fn h_storage_delete(key: *const u8, len: usize) -> i32;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unreachable()
}

const ORDER_BYTES: usize = 25;
const MAX_REQUEST: usize = 1 + 32 + ORDER_BYTES;

fn remove(key: &[u8]) {
    assert_eq!(unsafe { h_storage_delete(key.as_ptr(), key.len()) }, 0);
}

fn amount(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn account_key(kind: u8, account: &Account) -> [u8; 33] {
    let mut key = [kind; 33];
    key[1..].copy_from_slice(account);
    key
}

fn balance_key(asset: u8, account: &Account) -> [u8; 33] {
    assert!(asset <= 1);
    account_key(asset, account)
}

fn balance(key: &[u8; 33]) -> u64 {
    read(key).map(u64::from_le_bytes).unwrap_or(0)
}

fn debit(account: &Account, asset: u8, units: u64) {
    let key = balance_key(asset, account);
    let remaining = balance(&key).checked_sub(units).unwrap();
    if remaining == 0 {
        remove(&key);
    } else {
        write(&key, &remaining.to_le_bytes());
    }
}

fn credit(account: &Account, asset: u8, units: u64) {
    let key = balance_key(asset, account);
    write(
        &key,
        &balance(&key).checked_add(units).unwrap().to_le_bytes(),
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn init() {
    let mut buffer = [0; MAX_REQUEST];
    let supplies = request(&mut buffer);
    assert_eq!(supplies.len(), 16);
    assert!(read::<16>(b"supply").is_none());
    let owner = caller();
    for (asset, bytes) in supplies.chunks_exact(8).enumerate() {
        let units = amount(bytes);
        assert!(units > 0);
        credit(&owner, asset as u8, units);
    }
    write(b"supply", supplies);
}

fn place(maker: &Account, terms: &[u8]) {
    assert_eq!(terms.len(), 17);
    let offered = amount(&terms[1..9]);
    assert!(offered > 0 && amount(&terms[9..]) > 0);
    let key = account_key(b'o', maker);
    assert!(read::<ORDER_BYTES>(&key).is_none());
    let last = read(b"last").map(u64::from_le_bytes).unwrap_or(0);
    let id = last.checked_add(1).unwrap().to_le_bytes();
    debit(maker, terms[0], offered);
    let mut order = [0; ORDER_BYTES];
    order[..8].copy_from_slice(&id);
    order[8..].copy_from_slice(terms);
    write(&key, &order);
    write(b"last", &id);
}

fn fill(taker: &Account, maker: &Account, expected: &[u8]) {
    assert_ne!(taker, maker);
    let key = account_key(b'o', maker);
    let order = read::<ORDER_BYTES>(&key).unwrap();
    assert_eq!(order.as_slice(), expected);
    let sell = order[8];
    let price = amount(&order[17..]);
    remove(&key);
    debit(taker, 1 - sell, price);
    credit(maker, 1 - sell, price);
    credit(taker, sell, amount(&order[9..17]));
}

#[unsafe(no_mangle)]
pub extern "C" fn hyphen_execute() {
    let mut buffer = [0; MAX_REQUEST];
    let signer = caller();
    match request(&mut buffer) {
        [1, asset, data @ ..] if data.len() == 40 => {
            let recipient = data[..32].try_into().unwrap();
            let units = amount(&data[32..]);
            assert!(units > 0 && recipient != &signer);
            debit(&signer, *asset, units);
            credit(recipient, *asset, units);
        }
        [2, terms @ ..] => place(&signer, terms),
        [3, data @ ..] if data.len() == 32 + ORDER_BYTES => {
            fill(&signer, data[..32].try_into().unwrap(), &data[32..]);
        }
        [4, id @ ..] if id.len() == 8 => {
            let key = account_key(b'o', &signer);
            let order = read::<ORDER_BYTES>(&key).unwrap();
            assert_eq!(&order[..8], id);
            remove(&key);
            credit(&signer, order[8], amount(&order[9..17]));
        }
        _ => unreachable(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn hyphen_query() {
    let mut buffer = [0; MAX_REQUEST];
    match request(&mut buffer) {
        [0] => respond(&read::<16>(b"supply").unwrap()),
        [1, asset, account @ ..] => {
            respond(&balance(&balance_key(*asset, account.try_into().unwrap())).to_le_bytes())
        }
        [2, account @ ..] => {
            let order = read::<ORDER_BYTES>(&account_key(b'o', account.try_into().unwrap()));
            respond(order.as_ref().map_or(&[], |bytes| bytes.as_slice()));
        }
        _ => unreachable(),
    }
}
