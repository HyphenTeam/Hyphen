//! Whole-note offline delegation. A funded note has a NUMS spend key. Each
//! successful claim consumes the reserve output in the normal nullifier set.
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::CompressedRistretto, scalar::Scalar,
};
use hyphen_crypto::{
    Commitment, Hash256, PublicKey, SecretKey, Signature, StealthAddress, blake3_hash_many,
    hash::{hash_to_point, hash_to_scalar},
    stealth,
};
use serde::{Deserialize, Serialize};

use crate::{Transaction, TxInput, TxOutput, builder::build_coinbase_tx, transaction::OutputRef};

pub const CLAIM_VERSION: u8 = 209;
pub const MAX_HOPS: usize = 16;
pub const MAX_CLAIM_BYTES: usize = 8192;
const MAX_CLAIM_EXTRA: usize = 4096;
/// Odd first byte excludes every canonical compressed Ristretto key image.
pub const SPENT_PREFIX: &[u8; 1] = &[0xff];
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
pub struct Reserve {
    pub chain: Hash256,
    pub owner: PublicKey,
    pub nonce: [u8; 32],
    pub amount: u64,
    pub fee: u64,
}

impl Reserve {
    pub fn net(&self) -> Result<u64> {
        if self.fee == 0 || self.amount <= self.fee {
            return Err("reserve must cover a positive fee and payout");
        }
        Ok(self.amount - self.fee)
    }

    fn terms(&self) -> Hash256 {
        blake3_hash_many(&[
            b"Hyphen/offline/reserve/v1",
            self.chain.as_bytes(),
            self.owner.as_bytes(),
            &self.nonce,
            &self.amount.to_le_bytes(),
            &self.fee.to_le_bytes(),
        ])
    }

    /// The public view scalar is one. Nobody knows the discrete logarithm of
    /// the spend point, including the party that chose the terms and nonce.
    pub fn address(&self) -> Result<StealthAddress> {
        self.net()?;
        let owner = self
            .owner
            .to_verifying_key()
            .map_err(|_| "invalid reserve owner")?;
        if owner.is_weak() {
            return Err("weak reserve owner");
        }
        Ok(StealthAddress {
            view_public: G.compress().to_bytes(),
            spend_public: hash_to_point(self.terms().as_ref()).compress().to_bytes(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
pub struct Funding {
    pub reserve: Reserve,
    pub index: u64,
    pub ephemeral: [u8; 32],
    pub ordinal: u32,
}

impl Funding {
    pub fn id(&self) -> Hash256 {
        blake3_hash_many(&[
            b"Hyphen/offline/funding/v1",
            self.reserve.terms().as_ref(),
            &self.ordinal.to_le_bytes(),
            &self.ephemeral,
        ])
    }

    pub fn output(&self) -> Result<TxOutput> {
        let address = self.reserve.address()?;
        let point = CompressedRistretto(self.ephemeral)
            .decompress()
            .ok_or("invalid funding ephemeral key")?;
        if point == Default::default() {
            return Err("identity funding ephemeral key");
        }
        let mut input = [0; 40];
        input[..32].copy_from_slice(&self.ephemeral);
        input[32..].copy_from_slice(&u64::from(self.ordinal).to_le_bytes());
        let shared = hash_to_scalar(b"Hyphen_ECDH", &input);
        let spend = CompressedRistretto(address.spend_public)
            .decompress()
            .ok_or("invalid NUMS point")?;
        Ok(output(
            self.reserve.amount,
            shared,
            self.ephemeral,
            (shared * G + spend).compress().to_bytes(),
        ))
    }
}

/// Name the actual canonical key and commitment. Identical outputs at multiple
/// indices share a spend marker, including after reorg or deliberate copying.
pub fn spent_image(chain: Hash256, locked: &TxOutput) -> Hash256 {
    let mut image = blake3_hash_many(&[
        b"Hyphen/offline/spent/v1",
        chain.as_ref(),
        &locked.one_time_pubkey,
        locked.commitment.as_bytes(),
    ]);
    image.0[0] = SPENT_PREFIX[0];
    image
}

fn output(
    amount: u64,
    shared: Scalar,
    ephemeral_pubkey: [u8; 32],
    one_time_pubkey: [u8; 32],
) -> TxOutput {
    TxOutput {
        commitment: Commitment::create(amount, stealth::derive_commitment_blinding(&shared)),
        one_time_pubkey,
        ephemeral_pubkey,
        encrypted_amount: stealth::encrypt_amount(amount, &shared),
        view_tag: stealth::compute_view_tag(&shared),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
pub struct Invoice {
    pub recipient: PublicKey,
    pub nonce: [u8; 32],
    pub signature: Signature,
}

impl Invoice {
    fn digest(head: Hash256, recipient: PublicKey, nonce: &[u8; 32]) -> Hash256 {
        blake3_hash_many(&[
            b"Hyphen/offline/request/v1",
            head.as_ref(),
            recipient.as_bytes(),
            nonce,
        ])
    }

    pub fn new(head: Hash256, recipient: &SecretKey, nonce: [u8; 32]) -> Self {
        let public = recipient.public_key();
        Self {
            recipient: public,
            nonce,
            signature: recipient.sign(Self::digest(head, public, &nonce).as_ref()),
        }
    }

    fn authorization(&self, head: Hash256) -> Result<Hash256> {
        let request = Self::digest(head, self.recipient, &self.nonce);
        self.recipient
            .verify(request.as_ref(), &self.signature)
            .map_err(|_| "invalid recipient request")?;
        Ok(blake3_hash_many(&[
            b"Hyphen/offline/transfer/v1",
            request.as_ref(),
            self.signature.as_bytes(),
        ]))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
pub struct Transfer {
    pub invoice: Invoice,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
pub struct Voucher {
    pub funding: Funding,
    pub transfers: Vec<Transfer>,
}

/// Two different requests authorized by the same key from the same delegation state.
pub struct ConflictingAuthorization {
    pub head: Hash256,
    pub signer: PublicKey,
    pub first_request: Hash256,
    pub second_request: Hash256,
}

impl Voucher {
    /// Authenticate both complete histories before reporting any signer. Different
    /// encodings/signatures of the same request do not prove different instructions.
    pub fn conflicting_authorization(
        &self,
        other: &Self,
        chain: Hash256,
    ) -> Result<Option<ConflictingAuthorization>> {
        let mut left = Vec::new();
        self.verify_history(chain, |head, signer, invoice| {
            left.push((
                head,
                signer,
                Invoice::digest(head, invoice.recipient, &invoice.nonce),
            ));
        })?;
        let mut edges = left.into_iter();
        let mut conflict = None;
        other.verify_history(chain, |head, signer, invoice| {
            if let Some((previous_head, previous_signer, first_request)) = edges.next()
                && previous_head == head
                && previous_signer == signer
            {
                let second_request = Invoice::digest(head, invoice.recipient, &invoice.nonce);
                if first_request != second_request {
                    conflict = Some(ConflictingAuthorization {
                        head,
                        signer,
                        first_request,
                        second_request,
                    });
                }
            }
        })?;
        Ok(conflict)
    }

    pub fn holder(&self, chain: Hash256) -> Result<(Hash256, PublicKey)> {
        self.verify_history(chain, |_, _, _| {})
    }

    /// Report each authorized outgoing edge while verifying the delegation chain.
    /// Callers must wait for success before persisting any observed edge.
    pub fn verify_history(
        &self,
        chain: Hash256,
        mut visit: impl FnMut(Hash256, PublicKey, &Invoice),
    ) -> Result<(Hash256, PublicKey)> {
        if self.funding.reserve.chain != chain || self.transfers.len() > MAX_HOPS {
            return Err("wrong chain or transfer limit exceeded");
        }
        let mut head = self.funding.id();
        let mut owner = self.funding.reserve.owner;
        for transfer in &self.transfers {
            let digest = transfer.invoice.authorization(head)?;
            owner
                .verify(digest.as_ref(), &transfer.signature)
                .map_err(|_| "invalid transfer authorization")?;
            visit(head, owner, &transfer.invoice);
            head = blake3_hash_many(&[
                b"Hyphen/offline/link/v1",
                digest.as_ref(),
                transfer.signature.as_bytes(),
            ]);
            owner = transfer.invoice.recipient;
        }
        Ok((head, owner))
    }

    pub fn transfer(&mut self, chain: Hash256, owner: &SecretKey, invoice: Invoice) -> Result<()> {
        let (head, current) = self.holder(chain)?;
        if self.transfers.len() >= MAX_HOPS || current != owner.public_key() {
            return Err("transfer limit or wrong signing key");
        }
        let signature = owner.sign(invoice.authorization(head)?.as_ref());
        self.transfers.push(Transfer { invoice, signature });
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
struct Claim {
    voucher: Voucher,
    destination: StealthAddress,
    signature: Signature,
}

fn withdrawal(head: Hash256, dest: &StealthAddress) -> Hash256 {
    blake3_hash_many(&[
        b"Hyphen/offline/redeem/v1",
        head.as_ref(),
        &dest.view_public,
        &dest.spend_public,
    ])
}

// Bind the public range proof and selected chain position to the terminal
// signature so a relay cannot re-encode a withdrawal under another txid.
fn settlement_digest(withdrawal: Hash256, tx: &Transaction, index: u64) -> Result<Hash256> {
    let proof = crate::wire_config(MAX_CLAIM_BYTES)
        .serialize(&tx.prunable.range_proof)
        .map_err(|_| "oversized settlement proof")?;
    Ok(blake3_hash_many(&[
        b"Hyphen/offline/settlement/v1",
        withdrawal.as_ref(),
        &index.to_le_bytes(),
        &proof,
    ]))
}

pub fn redeem(
    voucher: Voucher,
    chain: Hash256,
    key: &SecretKey,
    destination: StealthAddress,
) -> Result<Transaction> {
    let (head, holder) = voucher.holder(chain)?;
    if key.public_key() != holder {
        return Err("redemption requires the current holder");
    }
    let digest = withdrawal(head, &destination);
    let funding = &voucher.funding;
    let mut tx = build_coinbase_tx(
        destination.view_public,
        destination.spend_public,
        funding.reserve.net()?,
        0,
        digest,
    )
    .map_err(|_| "cannot construct redemption output")?;
    tx.version = CLAIM_VERSION;
    tx.fee = funding.reserve.fee;
    let locked = funding.output()?;
    tx.inputs.push(TxInput {
        ring: vec![OutputRef {
            global_index: funding.index,
        }],
        key_image: spent_image(chain, &locked).0,
        pseudo_output: locked.commitment,
        epoch_context: [0; 32],
        temporal_nonce: [0; 32],
        causal_binding: [0; 32],
    });
    let signature = key.sign(settlement_digest(digest, &tx, funding.index)?.as_ref());
    tx.extra = crate::wire_config(MAX_CLAIM_EXTRA)
        .serialize(&Claim {
            voucher,
            destination,
            signature,
        })
        .map_err(|_| "claim serialization failed")?;
    Ok(tx)
}

/// The caller resolves the index in the canonical parent output set and checks
/// and commits the declared key image in the same batch as the payout.
pub fn verify_claim(
    tx: &Transaction,
    chain: Hash256,
    canonical_index: u64,
    key: [u8; 32],
    commitment: Commitment,
) -> Result<()> {
    verified_settlement(tx, chain, canonical_index, key, commitment).map(|_| ())
}

/// Receipt head and payout address authenticated by a successful claim verification.
pub struct VerifiedSettlement {
    pub receipt: Hash256,
    pub destination: StealthAddress,
    pub voucher: Voucher,
}

pub fn verified_settlement(
    tx: &Transaction,
    chain: Hash256,
    canonical_index: u64,
    key: [u8; 32],
    commitment: Commitment,
) -> Result<VerifiedSettlement> {
    let ([input], [payout]) = (tx.inputs.as_slice(), tx.outputs.as_slice()) else {
        return Err("expected one reserve and one payout");
    };
    if tx.version != CLAIM_VERSION
        || input.ring.len() != 1
        || !tx.prunable.clsag_signatures.is_empty()
        || tx.extra.len() > MAX_CLAIM_EXTRA
        || input.epoch_context != [0; 32]
        || input.temporal_nonce != [0; 32]
        || input.causal_binding != [0; 32]
    {
        return Err("invalid claim shape");
    }
    let claim: Claim = rustbinary::options()
        .with_limit(MAX_CLAIM_EXTRA as u64)
        .with_collection_limit(MAX_HOPS as u64)
        .reject_trailing_bytes()
        .with_compact_format()
        .deserialize(&tx.extra)
        .map_err(|_| "malformed claim")?;
    let funding = &claim.voucher.funding;
    if funding.reserve.chain != chain
        || funding.index != input.ring[0].global_index
        || canonical_index != funding.index
        || tx.fee != funding.reserve.fee
    {
        return Err("incorrect claim source, fee or nullifier");
    }
    let locked = funding.output()?;
    if key != locked.one_time_pubkey
        || commitment != locked.commitment
        || input.pseudo_output != commitment
        || input.key_image != spent_image(chain, &locked).0
    {
        return Err("canonical reserve does not match funding terms");
    }
    let (head, owner) = claim.voucher.holder(chain)?;
    let digest = withdrawal(head, &claim.destination);
    owner
        .verify(
            settlement_digest(digest, tx, canonical_index)?.as_ref(),
            &claim.signature,
        )
        .map_err(|_| "invalid redemption authorization")?;
    let (ephemeral, pk, shared) =
        stealth::derive_consensus_one_time_key(&claim.destination, 0, digest.as_bytes())
            .map_err(|_| "invalid payout address")?;
    let expected = output(
        funding.reserve.net()?,
        shared,
        ephemeral.0,
        pk.compress().to_bytes(),
    );
    if expected.note_hash() != payout.note_hash() {
        return Err("payout differs from authorized withdrawal");
    }
    let point = expected
        .commitment
        .to_point()
        .map_err(|_| "invalid payout commitment")?;
    tx.prunable
        .range_proof
        .verify(&[point])
        .map_err(|_| "invalid payout range proof")?;
    Ok(VerifiedSettlement {
        receipt: head,
        destination: claim.destination,
        voucher: claim.voucher,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_chain_binds_requests_and_survives_reserve_relocation() {
        let chain = Hash256([3; 32]);
        let mut owner = SecretKey([2; 32]);
        let reserve = Reserve {
            chain,
            owner: owner.public_key(),
            nonce: [1; 32],
            amount: 10_000_000,
            fee: 1_000_000,
        };
        let (ephemeral, _, _) =
            stealth::derive_one_time_key(&reserve.address().unwrap(), 1).unwrap();
        let mut voucher = Voucher {
            funding: Funding {
                reserve,
                index: 77,
                ephemeral: ephemeral.0,
                ordinal: 1,
            },
            transfers: vec![],
        };
        for i in 0..MAX_HOPS {
            let next = SecretKey([i as u8 + 3; 32]);
            let invoice = Invoice::new(voucher.holder(chain).unwrap().0, &next, [i as u8; 32]);
            voucher.transfer(chain, &owner, invoice).unwrap();
            owner = next;
        }
        let extra = Invoice::new(voucher.holder(chain).unwrap().0, &owner, [23; 32]);
        assert!(voucher.transfer(chain, &owner, extra).is_err());
        let mut reordered = voucher.clone();
        reordered.transfers.swap(1, 2);
        assert!(reordered.holder(chain).is_err());
        let mut changed = voucher.clone();
        changed.transfers[1].invoice.nonce[0] ^= 1;
        assert!(changed.holder(chain).is_err());
        let locked = voucher.funding.output().unwrap();
        let address = stealth::generate_keys().2;
        let original = redeem(voucher.clone(), chain, &owner, address).unwrap();
        voucher.funding.index = 12;
        let relocated = redeem(voucher, chain, &owner, address).unwrap();
        assert_ne!(relocated.hash(), original.hash());
        assert_eq!(original.inputs[0].key_image, relocated.inputs[0].key_image);
        assert!(
            CompressedRistretto(original.inputs[0].key_image)
                .decompress()
                .is_none()
        );
        let check = |tx: &Transaction, index| {
            verify_claim(tx, chain, index, locked.one_time_pubkey, locked.commitment)
        };
        check(&original, 77).unwrap();
        check(&relocated, 12).unwrap();
        assert!(relocated.serialise().len() <= MAX_CLAIM_BYTES);
        assert!(check(&original, 12).is_err());
        assert!(
            verify_claim(
                &relocated,
                Hash256::ZERO,
                12,
                locked.one_time_pubkey,
                locked.commitment
            )
            .is_err()
        );
        assert!(verify_claim(&relocated, chain, 12, [0; 32], locked.commitment).is_err());
        assert!(
            verify_claim(
                &relocated,
                chain,
                12,
                locked.one_time_pubkey,
                Commitment([0; 32])
            )
            .is_err()
        );
        for mutate in [
            (|tx: &mut Transaction| tx.fee += 1) as fn(&mut Transaction),
            |tx| tx.outputs[0].one_time_pubkey[0] ^= 1,
            |tx| tx.outputs[0].encrypted_amount[0] ^= 1,
            |tx| tx.inputs[0].key_image[0] ^= 1,
            |tx| {
                tx.extra.pop();
            },
            |tx| tx.extra.push(0),
            |tx| tx.prunable.range_proof.proof.mu[0] ^= 1,
            |tx| tx.outputs.push(tx.outputs[0].clone()),
        ] {
            let mut corrupt = relocated.clone();
            mutate(&mut corrupt);
            assert!(check(&corrupt, 12).is_err());
        }
    }
}
