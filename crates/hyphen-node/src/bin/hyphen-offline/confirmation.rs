use super::{Packet, Result, common, encoded, load, save};
use hyphen_crypto::{Commitment, Hash256, blake3_hash};
use hyphen_rpc::messages::OfflineSpendResponse;
use hyphen_tx::offline::{
    Funding, Invoice, MAX_CLAIM_BYTES, VerifiedSettlement, Voucher, decode_claim, spent_image,
    verified_settlement,
};
use hyphen_wallet::HyphenAddress;
use std::num::NonZeroU64;
use std::path::PathBuf;

pub(super) struct CanonicalSpend {
    pub image: Hash256,
    pub transaction: Hash256,
    pub block: Hash256,
    pub height: u64,
    pub confirmations: u64,
    pub tip: Hash256,
    pub claim: VerifiedSettlement,
    transaction_bytes: Vec<u8>,
}

pub(super) fn canonical_spend(
    snapshot: OfflineSpendResponse,
    chain: Hash256,
    image: Hash256,
) -> Result<Option<CanonicalSpend>> {
    let tip = Hash256(
        snapshot
            .tip
            .try_into()
            .map_err(|_| "invalid canonical tip hash")?,
    );
    let Some(spend) = snapshot.spend else {
        return Ok(None);
    };
    let source = spend.source.ok_or("canonical reserve source missing")?;
    let height = spend.height;
    let block = Hash256(
        spend
            .block
            .try_into()
            .map_err(|_| "invalid settlement block hash")?,
    );
    let confirmations = snapshot
        .tip_height
        .checked_sub(height)
        .and_then(|n| n.checked_add(1))
        .ok_or("canonical spend height inconsistent with tip")?;
    if source.block_height >= height
        || (confirmations == 1 && block != tip)
        || spend.transaction.len() > MAX_CLAIM_BYTES
    {
        return Err("inconsistent canonical settlement record".into());
    }
    let tx = decode_claim(&spend.transaction)?;
    let [input] = tx.inputs.as_slice() else {
        return Err("expected one reserve input".into());
    };
    if input.key_image != image.0 {
        return Err("settlement spends a different reserve".into());
    }
    let claim = verified_settlement(
        &tx,
        chain,
        source.global_index,
        source
            .one_time_pubkey
            .try_into()
            .map_err(|_| "invalid canonical reserve key")?,
        Commitment(
            source
                .commitment
                .try_into()
                .map_err(|_| "invalid canonical reserve commitment")?,
        ),
    )?;
    Ok(Some(CanonicalSpend {
        image,
        transaction: blake3_hash(&spend.transaction),
        block,
        height,
        confirmations,
        tip,
        claim,
        transaction_bytes: spend.transaction,
    }))
}

#[derive(clap::Args)]
pub(super) struct Order {
    packet: PathBuf,
    invoice: PathBuf,
    destination: String,
    net_amount: u64,
    #[arg(long, default_value = "1")]
    min_confirmations: NonZeroU64,
    /// Require this exact tip for the settlement and its confirmation depth.
    #[arg(long, value_parser = common::parse_hash)]
    expect_tip: Option<Hash256>,
    /// Preserve the verified canonical transaction, including a competing payout, for later review.
    #[arg(long)]
    save_settlement: Option<PathBuf>,
}

pub(super) fn verify_saved_settlement(
    bytes: &[u8],
    funding: &Funding,
    chain: Hash256,
) -> Result<VerifiedSettlement> {
    let tx = decode_claim(bytes)?;
    let [input] = tx.inputs.as_slice() else {
        return Err("expected one settlement input".into());
    };
    let [source] = input.ring.as_slice() else {
        return Err("expected one reserve reference".into());
    };
    let output = funding.output()?;
    Ok(verified_settlement(
        &tx,
        chain,
        source.global_index,
        output.one_time_pubkey,
        output.commitment,
    )?)
}

pub(super) fn conflict_evidence(
    voucher: &Voucher,
    other: &Voucher,
    chain: Hash256,
) -> Result<Option<String>> {
    Ok(voucher
        .conflicting_authorization(other, chain)?
        .map(|edge| {
            format!(
                "signer={} head={} request_a={} request_b={}",
                edge.signer, edge.head, edge.first_request, edge.second_request
            )
        }))
}

pub(super) fn competing_settlement(
    voucher: &Voucher,
    claim: &VerifiedSettlement,
    chain: Hash256,
) -> Result<Option<String>> {
    if let Some(evidence) = conflict_evidence(voucher, &claim.voucher, chain)? {
        return Ok(Some(evidence));
    }
    let mut evidence = None;
    voucher.verify_history(chain, |head, signer, _| {
        if head == claim.receipt {
            evidence = Some(format!("redeemed_and_delegated_by={signer} head={head}"));
        }
    })?;
    Ok(evidence)
}

impl Order {
    pub(super) fn confirm(
        &self,
        chain: Hash256,
        lookup: impl FnOnce(Hash256) -> Result<OfflineSpendResponse>,
    ) -> Result<()> {
        let packet: Packet = load(&self.packet)?;
        let invoice: Invoice = load(&self.invoice)?;
        let voucher = &packet.voucher;
        let (head, _) = voucher.holder(chain)?;
        let last = voucher.transfers.last().ok_or("missing signed transfer")?;
        if encoded(&last.invoice)? != encoded(&invoice)?
            || voucher.funding.reserve.net()? != self.net_amount
        {
            return Err("delivery differs from the retained request or expected amount".into());
        }
        if self.destination.len() > 128 {
            return Err("invalid payout address length".into());
        }
        let address = HyphenAddress::decode(&self.destination)?;
        let image = spent_image(chain, &voucher.funding.output()?);
        let snapshot = lookup(image)?;
        if self
            .expect_tip
            .is_some_and(|tip| snapshot.tip != tip.as_bytes())
        {
            return Err("settlement tip differs from the expected block hash".into());
        }
        let spend = canonical_spend(snapshot, chain, image)?.ok_or("no confirmed settlement")?;
        if let Some(path) = &self.save_settlement {
            match save(path, &spend.transaction_bytes) {
                Ok(()) => (),
                Err(error) => {
                    // An exact retry can reuse an existing evidence file. Never replace a prior winner.
                    let exists = error
                        .downcast_ref::<tempfile::PersistError>()
                        .is_some_and(|e| e.error.kind() == std::io::ErrorKind::AlreadyExists);
                    if !exists
                        || common::read_bytes(path, MAX_CLAIM_BYTES)?.as_slice()
                            != spend.transaction_bytes
                    {
                        return Err(error);
                    }
                }
            }
        }
        if spend.claim.receipt != head {
            let mut reason = format!(
                "a competing receipt settled on the canonical chain: reserve_spend={image} transaction={} block={} tip={}",
                spend.transaction, spend.block, spend.tip
            );
            if let Some(evidence) = competing_settlement(voucher, &spend.claim, chain)? {
                reason.push(' ');
                reason.push_str(&evidence);
            }
            return Err(reason.into());
        }
        if !address.is_testnet()
            || address.spend_public != spend.claim.destination.spend_public
            || address.view_public != spend.claim.destination.view_public
        {
            return Err("settlement differs from the expected payout address".into());
        }
        if spend.confirmations < self.min_confirmations.get() {
            return Err("insufficient settlement confirmations".into());
        }
        println!(
            "status=confirmed reserve_spend={} receipt={} transaction={} block={} height={} confirmations={} tip={} net_atomic={}",
            spend.image,
            spend.claim.receipt,
            spend.transaction,
            spend.block,
            spend.height,
            spend.confirmations,
            spend.tip,
            self.net_amount
        );
        Ok(())
    }
}
