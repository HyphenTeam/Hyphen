use super::{Packet, Result, encoded};
use hyphen_consensus::Blockchain;
use hyphen_crypto::{Hash256, blake3_hash};
use hyphen_tx::Transaction;
use hyphen_tx::offline::{
    CLAIM_VERSION, Invoice, VerifiedSettlement, spent_image, verified_settlement,
};
use hyphen_wallet::HyphenAddress;
use std::num::NonZeroU64;

pub(super) struct CanonicalSpend {
    pub image: Hash256,
    pub transaction: Hash256,
    pub block: Hash256,
    pub height: u64,
    pub confirmations: u64,
    pub tip: Hash256,
    pub claim: VerifiedSettlement,
}

pub(super) fn canonical_spend(db: &Blockchain, image: Hash256) -> Result<Option<CanonicalSpend>> {
    let Some(height) = db.nullifiers.spent_height(image.as_bytes())? else {
        return Ok(None);
    };
    let block = db.store().get_block_by_height(height)?;
    for blob in &block.transactions {
        if blob.first() != Some(&CLAIM_VERSION) {
            continue;
        }
        let tx = Transaction::deserialise_limited(blob)?;
        let [input] = tx.inputs.as_slice() else {
            continue;
        };
        if input.key_image != image.0 {
            continue;
        }
        let [source] = input.ring.as_slice() else {
            return Err("malformed canonical reserve spend".into());
        };
        let entry = db.canonical_output(source.global_index)?;
        let locked = &entry.transaction.outputs[entry.output_index as usize];
        let claim = verified_settlement(
            &tx,
            db.chain_id(),
            source.global_index,
            locked.one_time_pubkey,
            locked.commitment,
        )?;
        let tip = db.tip()?;
        let confirmations = tip
            .height
            .checked_sub(height)
            .and_then(|n| n.checked_add(1))
            .ok_or("canonical spend height inconsistent with tip")?;
        return Ok(Some(CanonicalSpend {
            image,
            transaction: blake3_hash(blob),
            block: block.hash(),
            height,
            confirmations,
            tip: tip.hash,
            claim,
        }));
    }
    Err("canonical spend missing from indexed block".into())
}

pub(super) fn confirm(
    db: &Blockchain,
    packet: &Packet,
    invoice: &Invoice,
    destination: &str,
    net: u64,
    min_confirmations: NonZeroU64,
) -> Result<CanonicalSpend> {
    let voucher = &packet.voucher;
    let chain = db.chain_id();
    let (head, _) = voucher.holder(chain)?;
    let last = voucher.transfers.last().ok_or("missing signed transfer")?;
    if encoded(&last.invoice)? != encoded(invoice)? || voucher.funding.reserve.net()? != net {
        return Err("delivery differs from the retained request or expected amount".into());
    }
    if destination.len() > 128 {
        return Err("invalid payout address length".into());
    }
    let address = HyphenAddress::decode(destination)?;
    let image = spent_image(chain, &voucher.funding.output()?);
    let spend = canonical_spend(db, image)?.ok_or("no confirmed settlement")?;
    if spend.claim.receipt != head {
        return Err("a competing receipt settled on the canonical chain".into());
    }
    if !address.is_testnet()
        || address.spend_public != spend.claim.destination.spend_public
        || address.view_public != spend.claim.destination.view_public
    {
        return Err("settlement differs from the expected payout address".into());
    }
    if spend.confirmations < min_confirmations.get() {
        return Err("insufficient settlement confirmations".into());
    }
    Ok(spend)
}
