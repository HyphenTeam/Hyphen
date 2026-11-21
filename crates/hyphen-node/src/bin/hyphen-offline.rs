//! Wallet and full-node commands for the HYOF whole-reserve payment protocol.
mod common;
#[path = "hyphen-offline/confirmation.rs"]
mod confirmation;
#[path = "hyphen-offline/journal.rs"]
mod journal;
use journal::Journal;

use clap::{Parser, Subcommand};
use hyphen_consensus::Blockchain;
use hyphen_core::{ChainConfig, ChainIdentity};
use hyphen_crypto::{
    Hash256, MerkleProof, PublicKey, SecretKey, StealthAddress, blake3_hash, blake3_hash_many,
    fill_system_random,
};
use hyphen_rpc::messages::*;
use hyphen_tx::{
    Transaction,
    offline::{Funding, Invoice, Reserve, SPENT_PREFIX, Voucher, redeem_with_receipt, spent_image},
};
use hyphen_wallet::HyphenAddress;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufWriter, IsTerminal, Read, Seek, SeekFrom, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

type Result<T> = common::Result<T>;
const PACKET_LIMIT: usize = hyphen_tx::offline::MAX_CLAIM_BYTES;
const CHECKPOINT_MAGIC: &[u8; 8] = b"HYOFCK01";

#[derive(Parser)]
#[command(
    about = "Conditional offline payments on hyphen-neural-devnet-v3. Wallet commands read a raw 64-byte BIP39 seed from stdin."
)]
struct Cli {
    #[arg(long, default_value_t = 0)]
    account: u32,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Produce funding terms. Pay the printed address exactly `amount` atomic units online.
    Reserve { amount: u64, fee: u64, out: PathBuf },
    /// Install a checkpoint from your own stopped node into your local wallet journal.
    Checkpoint {
        data_dir: PathBuf,
        out: PathBuf,
        journal: PathBuf,
    },
    /// Attach canonical funding and an inclusion proof to the initial voucher.
    Issue {
        data_dir: PathBuf,
        reserve: PathBuf,
        index: u64,
        out: PathBuf,
    },
    /// Look up a confirmed regular funding transaction's output position.
    Locate {
        data_dir: PathBuf,
        txid: String,
        #[arg(default_value_t = 0)]
        ordinal: u32,
    },
    /// Renew the proof and index after resync, retaining every signed delegation.
    Refresh {
        data_dir: PathBuf,
        packet: PathBuf,
        index: u64,
        out: PathBuf,
    },
    /// Verify the offered voucher against your own checkpoint and sign a fresh request.
    Request {
        checkpoint: PathBuf,
        packet: PathBuf,
        net_amount: u64,
        journal: PathBuf,
        out: PathBuf,
    },
    /// Authorize a request after checking the authenticated recipient key and net amount.
    Transfer {
        checkpoint: PathBuf,
        packet: PathBuf,
        invoice: PathBuf,
        recipient: String,
        net_amount: u64,
        journal: PathBuf,
        out: PathBuf,
    },
    /// Verify delivery against your locally retained invoice and record one conditional receipt.
    Accept {
        checkpoint: PathBuf,
        packet: PathBuf,
        invoice: PathBuf,
        net_amount: u64,
        journal: PathBuf,
    },
    /// Build a signed settlement transaction for a regular wallet address while offline.
    Redeem {
        checkpoint: PathBuf,
        packet: PathBuf,
        destination: String,
        net_amount: u64,
        journal: PathBuf,
        out: PathBuf,
    },
    /// Relay an already signed transaction to a node on this network.
    Submit {
        transaction: PathBuf,
        #[arg(long, default_value = "127.0.0.1:48333")]
        rpc: SocketAddr,
    },
    /// Display the delegation key for out-of-band verification by the payer.
    PublicKey,
    /// Resolve an offline receipt's current chain outcome from a local stopped node.
    Status {
        data_dir: PathBuf,
        packet: PathBuf,
        #[arg(long)]
        expected_tx: Option<String>,
    },
    /// Succeed only for the canonical payout of this invoice to the expected wallet address.
    Confirm {
        data_dir: PathBuf,
        #[command(flatten)]
        order: confirmation::Order,
    },
    /// Reconcile a retained order with your running, synchronized HYN3 node.
    ConfirmOnline {
        #[arg(long, default_value = "127.0.0.1:48333")]
        rpc: SocketAddr,
        #[command(flatten)]
        order: confirmation::Order,
    },
    /// Verify two signed deliveries and identify a key that authorized conflicting requests.
    VerifyConflict {
        first: PathBuf,
        second: PathBuf,
        /// Read a signed settlement transaction as the second artifact.
        #[arg(long)]
        settlement: bool,
    },
}

// Fixed file limits cover a 32-sibling Merkle proof and sixteen signed links.
#[derive(Serialize, Deserialize, rustbinary::CompactBinary)]
struct Packet {
    voucher: Voucher,
    height: u64,
    proof: MerkleProof,
}

fn encoded<T: rustbinary::CompactEncode>(value: &T) -> Result<Vec<u8>> {
    Ok(hyphen_core::wire_config(PACKET_LIMIT).serialize(value)?)
}

fn load<T: for<'a> rustbinary::CompactDecode<'a>>(path: &Path) -> Result<T> {
    let data = common::read_bytes(path, PACKET_LIMIT)?;
    Ok(rustbinary::options()
        .with_limit(PACKET_LIMIT as u64)
        .with_collection_limit(32)
        .reject_trailing_bytes()
        .with_compact_format()
        .deserialize(&data)?)
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn publish(file: NamedTempFile, path: &Path) -> Result<()> {
    file.as_file().sync_all()?;
    file.persist_noclobber(path)?;
    #[cfg(unix)]
    File::open(parent_dir(path))?.sync_all()?;
    Ok(())
}

fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = NamedTempFile::new_in(parent_dir(path))?;
    file.write_all(bytes)?;
    publish(file, path)
}

fn check_relay_fee(reserve: &Reserve, cfg: &ChainConfig) -> Result<()> {
    let floor = hyphen_economics::minimum_fee(PACKET_LIMIT, cfg);
    if reserve.fee < floor {
        return Err(format!(
            "fee must cover relay policy through the last transfer ({floor} atomic units)"
        )
        .into());
    }
    Ok(())
}

fn wallet_key(chain: Hash256, account: u32) -> Result<SecretKey> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err("pipe the unlocked wallet's raw BIP39 seed to stdin".into());
    }
    let mut seed = Zeroizing::new([0u8; 64]);
    let mut input = stdin.lock();
    input.read_exact(&mut *seed)?;
    if input.read(&mut [0])? != 0 {
        return Err("expected exactly 64 seed bytes".into());
    }
    Ok(SecretKey(
        blake3_hash_many(&[
            b"Hyphen/offline/wallet-key/v1",
            chain.as_ref(),
            &account.to_le_bytes(),
            seed.as_slice(),
        ])
        .0,
    ))
}

fn db(dir: &Path) -> Result<Blockchain> {
    if !dir.join("conf").is_file() {
        return Err("expected an existing stopped HYN3 node database".into());
    }
    Ok(Blockchain::open(
        dir.to_str().ok_or("invalid database path")?,
        ChainConfig::neural_devnet(),
    )?)
}

fn connect(rpc: SocketAddr, cfg: &ChainConfig) -> Result<TcpStream> {
    let timeout = Duration::from_secs(15);
    let mut stream = TcpStream::connect_timeout(&rpc, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    common::check_identity(&mut stream, cfg)?;
    Ok(stream)
}

fn put_u64(writer: &mut impl Write, n: u64) -> std::io::Result<()> {
    writer.write_all(&n.to_le_bytes())
}
fn get_u64(reader: &mut impl Read) -> std::io::Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

// A fresh local authentication key per snapshot binds every fixed-width cell
// to its byte position. The journal installs that key only after syncing the
// complete file. Checking one incoming payment reads O(log(spent)) cells.
fn cell_tag(key: &[u8; 32], slot: u64, value: &[u8; 32]) -> Hash256 {
    let mut bytes = [0; 40];
    bytes[..8].copy_from_slice(&slot.to_le_bytes());
    bytes[8..].copy_from_slice(value);
    hyphen_crypto::blake3_keyed(key, &bytes)
}

fn checkpoint(dir: &Path, out: &Path, journal_dir: &Path) -> Result<()> {
    let chain = db(dir)?;
    let tip = chain.tip()?;
    let journal = Journal::open(journal_dir)?;
    if let Some(old) = journal.get(CHECKPOINT_MAGIC)? {
        if old.len() != 96 {
            return Err("invalid wallet checkpoint pin".into());
        }
        let work = u128::from_le_bytes(old[..16].try_into()?);
        if work > tip.cumulative_difficulty
            || (work == tip.cumulative_difficulty && &old[16..48] != tip.hash.as_ref())
        {
            return Err("checkpoint would regress the wallet's verified chain work".into());
        }
    }
    let mut key = Zeroizing::new([0; 32]);
    fill_system_random(&mut *key);
    let mut staged = NamedTempFile::new_in(parent_dir(out))?;
    let mut writer = BufWriter::new(staged.as_file_mut());
    writer.write_all(CHECKPOINT_MAGIC)?;
    writer.write_all(chain.chain_id().as_ref())?;
    put_u64(&mut writer, tip.height)?;
    let mut slot = 0u64;
    let mut cell = |value: &[u8; 32]| -> Result<()> {
        writer.write_all(value)?;
        writer.write_all(cell_tag(&key, slot, value).as_ref())?;
        slot += 1;
        Ok(())
    };
    // Root[h] covers the state after block h. Each header commits to its parent state.
    for height in 1..=tip.height {
        cell(
            chain
                .store()
                .get_block_by_height(height)?
                .header
                .commitment_root
                .as_bytes(),
        )?;
    }
    cell(chain.commitment_tree.read().root().as_bytes())?;
    let mut count = 0;
    for image in chain.nullifiers.with_prefix(SPENT_PREFIX) {
        cell(&image?)?;
        count += 1;
    }
    put_u64(&mut writer, count)?;
    writer.write_all(CHECKPOINT_MAGIC)?;
    writer.flush()?;
    drop(writer);
    publish(staged, out)?;
    let mut pin = Zeroizing::new([0; 96]);
    pin[..16].copy_from_slice(&tip.cumulative_difficulty.to_le_bytes());
    pin[16..48].copy_from_slice(tip.hash.as_ref());
    pin[48..56].copy_from_slice(&tip.height.to_le_bytes());
    pin[56..64].copy_from_slice(&count.to_le_bytes());
    pin[64..].copy_from_slice(&*key);
    journal.set(CHECKPOINT_MAGIC, &pin[..])?;
    println!(
        "checkpoint_height={} tip={} spent_reserves={count}",
        tip.height, tip.hash
    );
    Ok(())
}

fn checked(
    path: &Path,
    packet: &Path,
    chain: Hash256,
    net: u64,
    journal: &Journal,
) -> Result<Packet> {
    let packet: Packet = load(packet)?;
    let funding = &packet.voucher.funding;
    check_relay_fee(&funding.reserve, &ChainConfig::neural_devnet())?;
    if funding.reserve.chain != chain
        || funding.reserve.net()? != net
        || packet.proof.leaf_index != funding.index
    {
        return Err("unexpected network, amount or reserve index".into());
    }
    let mut file = File::open(path)?;
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    let mut identity = [0; 32];
    file.read_exact(&mut identity)?;
    let height = get_u64(&mut file)?;
    if magic != *CHECKPOINT_MAGIC || identity != chain.0 || packet.height > height {
        return Err("invalid checkpoint or proof newer than checkpoint".into());
    }
    let roots = height
        .checked_add(1)
        .and_then(|n| n.checked_mul(64))
        .and_then(|n| n.checked_add(48))
        .ok_or("invalid checkpoint height")?;
    file.seek(SeekFrom::End(-16))?;
    let count = get_u64(&mut file)?;
    file.read_exact(&mut magic)?;
    if magic != *CHECKPOINT_MAGIC
        || count
            .checked_mul(64)
            .and_then(|n| n.checked_add(roots))
            .and_then(|n| n.checked_add(16))
            != Some(file.metadata()?.len())
    {
        return Err("incomplete checkpoint".into());
    }
    let pin = journal
        .get(CHECKPOINT_MAGIC)?
        .ok_or("wallet has no independently installed checkpoint")?;
    if pin.len() != 96 || pin[48..56] != height.to_le_bytes() || pin[56..64] != count.to_le_bytes()
    {
        return Err("checkpoint differs from current wallet pin".into());
    }
    let key: &[u8; 32] = pin[64..].try_into()?;
    let mut cell = |slot: u64| -> Result<[u8; 32]> {
        file.seek(SeekFrom::Start(48 + 64 * slot))?;
        let mut bytes = [0; 32];
        let mut tag = [0; 32];
        file.read_exact(&mut bytes)?;
        file.read_exact(&mut tag)?;
        if cell_tag(key, slot, &bytes).0 != tag {
            return Err("checkpoint cell authentication failed".into());
        }
        Ok(bytes)
    };
    let root = cell(packet.height)?;
    let locked = funding.output()?;
    if !packet.proof.verify(&locked.note_hash(), &Hash256(root)) {
        return Err("reserve absent from independently verified checkpoint".into());
    }
    let (mut lo, mut hi) = (0, count);
    let spent = spent_image(chain, &locked);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        match cell(height + 1 + mid)?.cmp(spent.as_bytes()) {
            std::cmp::Ordering::Equal => return Err("reserve already settled at checkpoint".into()),
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    Ok(packet)
}

// Persist one decision per signing head before releasing any signature. A crash
// after flushing permits an identical retry. Restored copies can still fork.
fn record(
    db: &Journal,
    domain: &[u8],
    owner: PublicKey,
    source: Hash256,
    decision: Hash256,
) -> Result<bool> {
    let key = blake3_hash_many(&[domain, owner.as_bytes(), source.as_ref()]);
    if let Some(previous) = db.get(key.as_ref())? {
        if previous == decision.as_ref() {
            return Ok(false);
        }
        return Err("a conflicting decision is already recorded in this wallet".into());
    }
    db.set(key.as_ref(), decision.as_ref())?;
    Ok(true)
}

fn funded(db: &Blockchain, reserve: Reserve, index: u64) -> Result<Packet> {
    let entry = db.canonical_output(index)?;
    let output = &entry.transaction.outputs[entry.output_index as usize];
    let funding = Funding {
        reserve,
        index,
        ephemeral: output.ephemeral_pubkey,
        ordinal: entry.output_index,
    };
    if funding.reserve.chain != db.chain_id()
        || db
            .nullifiers
            .contains(&spent_image(db.chain_id(), output).0)?
        || funding.output()?.note_hash() != output.note_hash()
    {
        return Err("reserve absent, spent or funded for a different amount".into());
    }
    let proof = db
        .commitment_tree
        .read()
        .prove(index)
        .ok_or("missing reserve proof")?;
    Ok(Packet {
        voucher: Voucher {
            funding,
            transfers: vec![],
        },
        height: entry.tip.height,
        proof,
    })
}

const SPEND: &[u8] = b"Hyphen/offline/wallet-spend/v1";

// A reserve can return to a previous holder. Check every outgoing instruction
// this wallet remembers, including the original funder's first delegation.
struct ReceiptHistory {
    owner: PublicKey,
    receipt_key: Hash256,
    departures: Vec<(Hash256, Invoice)>,
}

impl ReceiptHistory {
    fn new(voucher: &Voucher, owner: PublicKey) -> Self {
        Self {
            owner,
            receipt_key: blake3_hash_many(&[
                b"Hyphen/offline/receipt/v1",
                owner.as_bytes(),
                voucher.funding.id().as_ref(),
            ]),
            departures: Vec::new(),
        }
    }

    fn visit(&mut self) -> impl FnMut(Hash256, PublicKey, &Invoice) + '_ {
        |source, signer, invoice| {
            if signer == self.owner {
                self.departures.push((source, invoice.clone()));
            }
        }
    }

    /// Called only after the entire history and its terminal owner have been authenticated.
    fn accept(self, journal: &Journal, head: Hash256) -> Result<bool> {
        let previous = journal.get(self.receipt_key.as_ref())?;
        let mut follows_previous = previous.is_none();
        for (source, departure) in self.departures {
            let slot = blake3_hash_many(&[SPEND, self.owner.as_bytes(), source.as_ref()]);
            if let Some(decision) = journal.get(slot.as_ref())? {
                if decision != blake3_hash(&encoded(&departure)?).as_ref() {
                    return Err(
                        "return transfer differs from this wallet's recorded payment".into(),
                    );
                }
                follows_previous |= previous.as_deref() == Some(source.as_ref());
            }
        }
        if previous.as_deref() == Some(head.as_ref()) {
            return Ok(false);
        }
        if !follows_previous {
            return Err("receipt conflicts with the wallet's previous receipt".into());
        }
        journal.set(self.receipt_key.as_ref(), head.as_ref())?;
        Ok(true)
    }
}

fn accept_receipt(
    journal: &Journal,
    voucher: &Voucher,
    chain: Hash256,
    owner: PublicKey,
) -> Result<(Hash256, bool)> {
    let mut history = ReceiptHistory::new(voucher, owner);
    let (head, holder) = voucher.verify_history(chain, history.visit())?;
    if holder != owner {
        return Err("receipt belongs to a different holder".into());
    }
    Ok((head, history.accept(journal, head)?))
}

fn authorize_transfer(
    journal: &Journal,
    mut voucher: Voucher,
    chain: Hash256,
    key: &SecretKey,
    invoice: Invoice,
) -> Result<Voucher> {
    let decision = blake3_hash(&encoded(&invoice)?);
    let mut history = ReceiptHistory::new(&voucher, key.public_key());
    let head = voucher.transfer_with_receipt(chain, key, invoice, history.visit())?;
    history.accept(journal, head)?;
    record(journal, SPEND, key.public_key(), head, decision)?;
    Ok(voucher)
}

fn authorize_redemption(
    journal: &Journal,
    voucher: Voucher,
    chain: Hash256,
    key: &SecretKey,
    destination: StealthAddress,
) -> Result<Transaction> {
    let mut history = ReceiptHistory::new(&voucher, key.public_key());
    let (head, tx) = redeem_with_receipt(voucher, chain, key, destination, history.visit())?;
    let decision = blake3_hash_many(&[
        b"Hyphen/offline/wallet-redemption/v1",
        head.as_ref(),
        &destination.view_public,
        &destination.spend_public,
    ]);
    history.accept(journal, head)?;
    record(journal, SPEND, key.public_key(), head, decision)?;
    Ok(tx)
}

#[cfg(test)]
#[test]
fn returning_funds_must_follow_the_wallets_recorded_first_transfer() {
    let directory = tempfile::tempdir().unwrap();
    let wallet = Journal::open(directory.path()).unwrap();
    let owner = SecretKey([1; 32]);
    let payee = SecretKey([2; 32]);
    let chain = ChainIdentity::of(&ChainConfig::neural_devnet()).genesis_hash;
    let reserve = Reserve {
        chain,
        owner: owner.public_key(),
        nonce: [9; 32],
        amount: 10_000_000,
        fee: 1_000_000,
    };
    let (ephemeral, _, _) =
        hyphen_crypto::stealth::derive_one_time_key(&reserve.address().unwrap(), 0).unwrap();
    let funding = Funding {
        reserve,
        index: 0,
        ordinal: 0,
        ephemeral: ephemeral.0,
    };
    let first = funding.id();
    let outgoing = Invoice::new(first, &payee, [3; 32]);
    record(
        &wallet,
        SPEND,
        owner.public_key(),
        first,
        blake3_hash(&encoded(&outgoing).unwrap()),
    )
    .unwrap();

    let returned = |invoice| {
        let mut voucher = Voucher {
            funding: funding.clone(),
            transfers: vec![],
        };
        assert_eq!(
            voucher
                .transfer_with_receipt(chain, &owner, invoice, |_, _, _| {})
                .unwrap(),
            first
        );
        let (head, _) = voucher.holder(chain).unwrap();
        voucher
            .transfer(chain, &payee, Invoice::new(head, &owner, [4; 32]))
            .unwrap();
        voucher
    };
    let competing = returned(Invoice::new(first, &payee, [5; 32]));
    assert!(accept_receipt(&wallet, &competing, chain, owner.public_key()).is_err());
    let competing_head = competing.holder(chain).unwrap().0;
    let next = Invoice::new(competing_head, &payee, [6; 32]);
    assert!(
        authorize_transfer(&wallet, competing.clone(), chain, &owner, next)
            .unwrap_err()
            .to_string()
            .contains("recorded payment")
    );
    let destination = competing.funding.reserve.address().unwrap();
    assert!(
        authorize_redemption(&wallet, competing, chain, &owner, destination)
            .unwrap_err()
            .to_string()
            .contains("recorded payment")
    );
    let valid = returned(outgoing);
    let (head, _) = valid.holder(chain).unwrap();
    assert_eq!(
        accept_receipt(&wallet, &valid, chain, owner.public_key()).unwrap(),
        (head, true)
    );
    assert_eq!(
        accept_receipt(&wallet, &valid, chain, owner.public_key()).unwrap(),
        (head, false)
    );
}

#[cfg(test)]
#[test]
fn independently_signed_offers_require_locally_verified_funding() {
    let dir = tempfile::tempdir().unwrap();
    let node = dir.path().join("node");
    let snapshot = dir.path().join("checkpoint");
    let wallet = dir.path().join("receiver");
    let cfg = ChainConfig::neural_devnet();
    let chain = ChainIdentity::of(&cfg).genesis_hash;
    drop(Blockchain::open(node.to_str().unwrap(), cfg).unwrap());
    checkpoint(&node, &snapshot, &wallet).unwrap();
    let journal = Journal::open(&wallet).unwrap();
    let receiver = SecretKey([80; 32]);
    let offered = dir.path().join("delivery");
    for id in 1..=32 {
        let payer = SecretKey([id; 32]);
        let reserve = Reserve {
            chain,
            owner: payer.public_key(),
            nonce: [id; 32],
            amount: 10_000_000,
            fee: 1_000_000,
        };
        let (ephemeral, _, _) =
            hyphen_crypto::stealth::derive_one_time_key(&reserve.address().unwrap(), 0).unwrap();
        let funding = Funding {
            reserve,
            index: 0,
            ordinal: 0,
            ephemeral: ephemeral.0,
        };
        let mut foreign_tree = hyphen_crypto::MerkleTree::new();
        foreign_tree.append(funding.output().unwrap().note_hash());
        let intermediary = SecretKey([79; 32]);
        let invoice = Invoice::new(funding.id(), &intermediary, [id; 32]);
        let mut voucher = Voucher {
            funding,
            transfers: vec![],
        };
        voucher.transfer(chain, &payer, invoice).unwrap();
        let request = Invoice::new(voucher.holder(chain).unwrap().0, &receiver, [id; 32]);
        voucher.transfer(chain, &intermediary, request).unwrap();
        assert_eq!(voucher.holder(chain).unwrap().1, receiver.public_key());
        let packet = Packet {
            voucher,
            height: 0,
            proof: foreign_tree.prove(0).unwrap(),
        };
        std::fs::write(&offered, encoded(&packet).unwrap()).unwrap();
        let error = checked(&snapshot, &offered, chain, 9_000_000, &journal)
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "reserve absent from independently verified checkpoint"
        );
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = ChainConfig::neural_devnet();
    let chain = ChainIdentity::of(&cfg).genesis_hash;
    let key = || wallet_key(chain, cli.account);
    match cli.command {
        Command::PublicKey => println!("{}", key()?.public_key()),
        Command::Status {
            data_dir,
            packet,
            expected_tx,
        } => {
            let packet: Packet = load(&packet)?;
            let (head, _) = packet.voucher.holder(chain)?;
            let funding = &packet.voucher.funding;
            let locked = funding.output()?;
            let image = spent_image(chain, &locked);
            let db = db(&data_dir)?;
            if let Some(spend) = confirmation::canonical_spend(
                OfflineSpendResponse::from_chain(&db, image)?,
                chain,
                image,
            )? {
                let status = match (spend.claim.receipt == head, expected_tx) {
                    (true, None) => "settled",
                    (true, Some(expected)) if expected == spend.transaction.to_string() => {
                        "confirmed"
                    }
                    _ => "conflicting_claim_confirmed",
                };
                println!(
                    "status={status} transaction={} block={} height={} confirmations={} tip={}",
                    spend.transaction, spend.block, spend.height, spend.confirmations, spend.tip
                );
            } else {
                let tip = db.tip()?;
                let present = if funding.index < tip.total_outputs {
                    let entry = db.canonical_output(funding.index)?;
                    entry.transaction.outputs[entry.output_index as usize].note_hash()
                        == locked.note_hash()
                } else {
                    false
                };
                let status = if present {
                    "funded_unsettled"
                } else {
                    "funding_absent_at_index"
                };
                println!("status={status} tip_height={} tip={}", tip.height, tip.hash);
            }
        }
        Command::Confirm { data_dir, order } => {
            let db = db(&data_dir)?;
            order.confirm(chain, |image| {
                Ok(OfflineSpendResponse::from_chain(&db, image)?)
            })?;
        }
        Command::ConfirmOnline { rpc, order } => {
            if !rpc.ip().is_loopback() {
                return Err("confirmation requires your own node on a loopback endpoint".into());
            }
            order.confirm(chain, |image| {
                common::request(
                    &mut connect(rpc, &cfg)?,
                    METHOD_GET_OFFLINE_SPEND,
                    GetOfflineSpendRequest {
                        reserve_spend: image.to_vec(),
                    },
                )
            })?;
        }
        Command::VerifyConflict {
            first,
            second,
            settlement,
        } => {
            let a: Packet = load(&first)?;
            let evidence = if settlement {
                let bytes = common::read_bytes(&second, PACKET_LIMIT)?;
                let claim =
                    confirmation::verify_saved_settlement(&bytes, &a.voucher.funding, chain)?;
                confirmation::competing_settlement(&a.voucher, &claim, chain)?
            } else {
                let b: Packet = load(&second)?;
                confirmation::conflict_evidence(&a.voucher, &b.voucher, chain)?
            }
            .ok_or("no conflicting signed requests or conflicting redemption for this delivery")?;
            println!(
                "status=conflicting_authorizations funding={} {evidence}",
                a.voucher.funding.id()
            );
        }
        Command::Locate {
            data_dir,
            txid,
            ordinal,
        } => {
            let hash = Hash256(
                hyphen_crypto::hex_decode(&txid)?
                    .try_into()
                    .map_err(|_| "expected 32-byte transaction hash")?,
            );
            let chain = db(&data_dir)?;
            let (block_hash, position) = chain.store().get_tx_location(&hash)?;
            let block = chain.store().get_block_by_hash(&block_hash)?;
            if chain
                .store()
                .get_block_hash_at_height(block.header.height)?
                != block_hash
            {
                return Err("funding block is not canonical".into());
            }
            let (mut first, mut end) = (0, chain.tip()?.total_outputs);
            while first < end {
                let mid = first + (end - first) / 2;
                if chain.store().output_record(mid)?.3 < block.header.height {
                    first = mid + 1;
                } else {
                    end = mid;
                }
            }
            let mut index = first;
            for bytes in block
                .transactions
                .get(..position as usize)
                .ok_or("invalid transaction position")?
                .iter()
                .filter(|blob| !hyphen_consensus::chain::protocol_envelope(blob))
            {
                index = index
                    .checked_add(Transaction::deserialise_limited(bytes)?.outputs.len() as u64)
                    .ok_or("output index overflow")?;
            }
            index = index
                .checked_add(u64::from(ordinal))
                .ok_or("output index overflow")?;
            let entry = chain.canonical_output(index)?;
            if entry.output_index != ordinal || entry.transaction.hash() != hash {
                return Err("invalid funding output ordinal".into());
            }
            println!("{index}");
        }
        Command::Reserve { amount, fee, out } => {
            let mut nonce = [0; 32];
            fill_system_random(&mut nonce);
            let reserve = Reserve {
                chain,
                owner: key()?.public_key(),
                amount,
                fee,
                nonce,
            };
            let address = reserve.address()?;
            check_relay_fee(&reserve, &cfg)?;
            save(&out, &encoded(&reserve)?)?;
            println!(
                "{}",
                HyphenAddress::new_testnet(address.view_public, address.spend_public).encode()
            );
        }
        Command::Checkpoint {
            data_dir,
            out,
            journal,
        } => checkpoint(&data_dir, &out, &journal)?,
        Command::Issue {
            data_dir,
            reserve,
            index,
            out,
        } => {
            let reserve: Reserve = load(&reserve)?;
            let packet = funded(&db(&data_dir)?, reserve, index)?;
            save(&out, &encoded(&packet)?)?;
        }
        Command::Refresh {
            data_dir,
            packet,
            index,
            out,
        } => {
            let old: Packet = load(&packet)?;
            old.voucher.holder(chain)?;
            let id = old.voucher.funding.id();
            let mut fresh = funded(&db(&data_dir)?, old.voucher.funding.reserve, index)?;
            if fresh.voucher.funding.id() != id {
                return Err("different canonical reserve".into());
            }
            fresh.voucher.transfers = old.voucher.transfers;
            save(&out, &encoded(&fresh)?)?;
        }
        Command::Request {
            checkpoint,
            packet,
            net_amount,
            journal,
            out,
        } => {
            let journal = Journal::open(&journal)?;
            let packet = checked(&checkpoint, &packet, chain, net_amount, &journal)?;
            if packet.voucher.transfers.len() == hyphen_tx::offline::MAX_HOPS {
                return Err("transfer limit reached".into());
            }
            let mut nonce = [0; 32];
            fill_system_random(&mut nonce);
            let invoice = Invoice::new(packet.voucher.holder(chain)?.0, &key()?, nonce);
            save(&out, &encoded(&invoice)?)?;
            println!("recipient={}", invoice.recipient);
        }
        Command::Transfer {
            checkpoint,
            packet,
            invoice,
            recipient,
            net_amount,
            journal,
            out,
        } => {
            let journal = Journal::open(&journal)?;
            let mut packet = checked(&checkpoint, &packet, chain, net_amount, &journal)?;
            let invoice: Invoice = load(&invoice)?;
            if invoice.recipient.to_string() != recipient {
                return Err("request differs from expected recipient".into());
            }
            let key = key()?;
            packet.voucher = authorize_transfer(&journal, packet.voucher, chain, &key, invoice)?;
            save(&out, &encoded(&packet)?)?;
        }
        Command::Accept {
            checkpoint,
            packet,
            invoice,
            net_amount,
            journal,
        } => {
            let journal = Journal::open(&journal)?;
            let packet = checked(&checkpoint, &packet, chain, net_amount, &journal)?;
            let saved: Invoice = load(&invoice)?;
            let delivery = packet
                .voucher
                .transfers
                .last()
                .ok_or("missing signed transfer")?;
            let owner = key()?.public_key();
            if saved.recipient != owner || encoded(&saved)? != encoded(&delivery.invoice)? {
                return Err("delivery differs from this wallet's retained request".into());
            }
            let (head, first) = accept_receipt(&journal, &packet.voucher, chain, owner)?;
            println!("conditional_receipt={head} net_atomic={net_amount} new={first}");
        }
        Command::Redeem {
            checkpoint,
            packet,
            destination,
            net_amount,
            journal,
            out,
        } => {
            let journal = Journal::open(&journal)?;
            let packet = checked(&checkpoint, &packet, chain, net_amount, &journal)?;
            if destination.len() > 128 {
                return Err("invalid payout address length".into());
            }
            let addr = HyphenAddress::decode(&destination)?;
            if !addr.is_testnet() {
                return Err("expected devnet payout address".into());
            }
            let key = key()?;
            let tx = authorize_redemption(
                &journal,
                packet.voucher,
                chain,
                &key,
                StealthAddress {
                    view_public: addr.view_public,
                    spend_public: addr.spend_public,
                },
            )?;
            let hash = tx.hash();
            save(&out, &tx.serialise())?;
            println!("signed_transaction={hash}");
        }
        Command::Submit { transaction, rpc } => {
            let bytes = common::read_bytes(&transaction, PACKET_LIMIT)?;
            hyphen_tx::offline::decode_claim(&bytes)?;
            let hash = blake3_hash(&bytes);
            let mut stream = connect(rpc, &cfg)?;
            let result: SubmitTransactionResponse = common::request(
                &mut stream,
                METHOD_SUBMIT_TX,
                SubmitTransactionRequest { tx_data: bytes },
            )?;
            if !result.accepted {
                return Err(result.error.into());
            }
            if result.tx_hash != hash.0 {
                return Err("RPC transaction hash differs".into());
            }
            println!("submitted={hash}");
        }
    }
    Ok(())
}
