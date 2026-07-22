use hyphen_wallet::Wallet;

fn main() {
    let wallet = Wallet::from_seed([0x42; 32]);
    println!("WARNING: fixed public test seed; never send real value to this address");
    println!("devnet_address={}", wallet.address(false).encode());
}
