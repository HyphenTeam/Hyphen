use super::{Result, TaskRecord, TaskStatus, common, verify_record};
use clap::{Args, Subcommand};
use hyphen_consensus::Blockchain;
use hyphen_crypto::{
    Commitment, Hash256, PublicKey, Signature, StealthAddress, blake3_hash, blake3_hash_many,
};
use hyphen_tx::offline::{
    Funding, MAX_CLAIM_BYTES, Reserve, Voucher, decode_claim, redeem, spent_image,
    verified_settlement,
};
use hyphen_wallet::HyphenAddress;
use std::{
    io::Write,
    num::NonZeroU64,
    path::{Path, PathBuf},
};

#[path = "../hyphen-offline/journal.rs"]
mod journal;

#[derive(Args)]
pub(super) struct Reward {
    #[arg(value_parser = common::parse_hash)]
    task: Hash256,
    /// Stopped, locally validated HYN3 database.
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long, value_parser = common::parse_hash)]
    expect_tip: Option<Hash256>,
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Print the reserve address and exact gross funding amount for this quote.
    Reserve { fee: u64 },
    /// Sign the payout address as the worker whose result finalized.
    Invoice {
        destination: String,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Authorize a native redemption from the selected reserve. Relay with hyphen-offline submit.
    Pay {
        invoice: PathBuf,
        index: u64,
        fee: u64,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify the canonical payout against the retained signed worker invoice.
    Confirm {
        invoice: PathBuf,
        #[arg(value_parser = common::parse_hash)]
        reserve_spend: Hash256,
        #[arg(long, default_value = "1")]
        min_confirmations: NonZeroU64,
    },
}

#[derive(rustbinary::CompactBinary)]
struct PayoutInvoice {
    destination: StealthAddress,
    signature: Signature,
}

fn finalized(record: &TaskRecord) -> Result<(PublicKey, Hash256, u64)> {
    let TaskStatus::Finalized {
        result,
        finalized_height,
        ..
    } = &record.status
    else {
        return Err("reward payment requires a finalized task".into());
    };
    Ok((
        result.claim.worker,
        result.claim.statement_digest(),
        *finalized_height,
    ))
}

fn invoice_digest(record: &TaskRecord, dest: &StealthAddress) -> Result<Hash256> {
    let (_, result, _) = finalized(record)?;
    Ok(blake3_hash_many(&[
        b"Hyphen/compute-payout-invoice/v1\0",
        record.task.spec.id().as_ref(),
        result.as_ref(),
        &dest.view_public,
        &dest.spend_public,
    ]))
}

fn terms(record: &TaskRecord, fee: u64) -> Result<Reserve> {
    let spec = &record.task.spec;
    Ok(Reserve {
        chain: spec.chain_id,
        owner: spec.scientist,
        nonce: blake3_hash_many(&[b"Hyphen/compute-reward-reserve/v1\0", spec.id().as_ref()]).0,
        amount: spec
            .reward
            .checked_add(fee)
            .ok_or("reward plus fee exceeds u64")?,
        fee,
    })
}

fn load_invoice(path: &Path, record: &TaskRecord) -> Result<PayoutInvoice> {
    let bytes = common::read_bytes(path, 128)?;
    let invoice: PayoutInvoice = hyphen_wire::wire_config(128).deserialize(&bytes)?;
    invoice.destination.recipient_points()?;
    let (worker, _, _) = finalized(record)?;
    worker.verify(
        invoice_digest(record, &invoice.destination)?.as_ref(),
        &invoice.signature,
    )?;
    Ok(invoice)
}

fn save(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    file.write_all(data)?;
    file.as_file().sync_all()?;
    match file.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(e)
            if e.error.kind() == std::io::ErrorKind::AlreadyExists
                && common::read_bytes(path, data.len())? == data =>
        {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn funded(db: &Blockchain, terms: Reserve, index: u64) -> Result<Funding> {
    let entry = db.canonical_output(index)?;
    let output = &entry.transaction.outputs[entry.output_index as usize];
    let funding = Funding {
        reserve: terms,
        index,
        ordinal: entry.output_index,
        ephemeral: output.ephemeral_pubkey,
    };
    if funding.output()?.note_hash() != output.note_hash() {
        return Err("canonical output differs from task reserve".into());
    }
    Ok(funding)
}

impl Reward {
    pub(super) fn run(self) -> Result<()> {
        let db = common::checked_local_state(&self.data_dir, self.expect_tip)?;
        let chain = db.chain_id();
        let record = db
            .compute_task(self.task)
            .ok_or("task absent from canonical state")?;
        verify_record(&record, self.task, chain)?;
        match self.action {
            Action::Reserve { fee } => {
                let floor = hyphen_economics::minimum_fee(MAX_CLAIM_BYTES, &db.cfg);
                if fee < floor {
                    return Err(format!("reserve fee must cover relay policy ({floor})").into());
                }
                let reserve = terms(&record, fee)?;
                let dest = reserve.address()?;
                println!(
                    "address={} gross_atomic={} fee_atomic={} net_atomic={}",
                    HyphenAddress::new_testnet(dest.view_public, dest.spend_public),
                    reserve.amount,
                    fee,
                    reserve.net()?
                );
            }
            Action::Invoice {
                destination,
                key_file,
                out,
            } => {
                let address = HyphenAddress::decode(&destination)?;
                let key = common::read_key(&key_file)?;
                if !address.is_testnet() || key.public_key() != finalized(&record)?.0 {
                    return Err(
                        "expected the finalized worker key and a devnet payout address".into(),
                    );
                }
                let destination = StealthAddress {
                    view_public: address.view_public,
                    spend_public: address.spend_public,
                };
                let signature = key.sign(invoice_digest(&record, &destination)?.as_ref());
                save(
                    &out,
                    &hyphen_wire::wire_config(128).serialize(&PayoutInvoice {
                        destination,
                        signature,
                    })?,
                )?;
            }
            Action::Pay {
                invoice,
                index,
                fee,
                key_file,
                journal,
                out,
            } => {
                let invoice = load_invoice(&invoice, &record)?;
                let key = common::read_key(&key_file)?;
                let funding = funded(&db, terms(&record, fee)?, index)?;
                let image = spent_image(chain, &funding.output()?);
                if db.nullifiers.contains(&image.0)? {
                    return Err("task reserve already spent".into());
                }
                let decision = blake3_hash_many(&[
                    b"Hyphen/compute-reward-decision/v1\0",
                    image.as_ref(),
                    invoice_digest(&record, &invoice.destination)?.as_ref(),
                ]);
                let tx = redeem(
                    Voucher {
                        funding,
                        transfers: Vec::new(),
                    },
                    chain,
                    &key,
                    invoice.destination,
                )?;
                let bytes = tx.serialise();
                if tx.fee < hyphen_economics::minimum_fee(bytes.len(), &db.cfg) {
                    return Err("fee below relay policy".into());
                }
                let log = journal::Journal::open(&journal)?;
                let slot =
                    blake3_hash_many(&[b"Hyphen/compute-reward-journal/v1\0", self.task.as_ref()]);
                match log.get(slot.as_ref())? {
                    Some(prior) if prior != decision.as_ref() => {
                        return Err(
                            "a different payment for this task is already authorized".into()
                        );
                    }
                    None => log.set(slot.as_ref(), decision.as_ref())?,
                    _ => (),
                }
                save(&out, &bytes)?;
                println!("transaction={} reserve_spend={image}", blake3_hash(&bytes));
            }
            Action::Confirm {
                invoice,
                reserve_spend,
                min_confirmations,
            } => {
                let invoice = load_invoice(&invoice, &record)?;
                let (tip, spend) = db.offline_spend(reserve_spend)?;
                let spend = spend.ok_or("no canonical reserve payout")?;
                let tx = decode_claim(&spend.transaction)?;
                let claim = verified_settlement(
                    &tx,
                    chain,
                    spend.source.global_index,
                    spend.source.one_time_pubkey,
                    Commitment(spend.source.commitment),
                )?;
                let reserve = terms(&record, tx.fee)?;
                let funding = &claim.voucher.funding;
                let confirmations = tip
                    .height
                    .checked_sub(spend.height)
                    .and_then(|depth| depth.checked_add(1))
                    .ok_or("inconsistent settlement height")?;
                if funding.reserve.address()? != reserve.address()?
                    || !claim.voucher.transfers.is_empty()
                    || spent_image(chain, &funding.output()?) != reserve_spend
                    || claim.destination != invoice.destination
                    || spend.height <= finalized(&record)?.2
                    || confirmations < min_confirmations.get()
                {
                    return Err(
                        "payout differs from the final task, invoice or required depth".into(),
                    );
                }
                println!(
                    "status=confirmed task={} transaction={} tip={} height={} confirmations={} net_atomic={}",
                    self.task,
                    blake3_hash(&spend.transaction),
                    tip.hash,
                    spend.height,
                    confirmations,
                    reserve.net()?
                );
            }
        }
        Ok(())
    }
}
