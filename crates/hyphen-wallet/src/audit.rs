//! User-controlled selective disclosure for a single shielded output.
//!
//! This is the implementable first half of H-SAC. It reveals an amount and
//! Pedersen opening to a specifically named auditor and proves knowledge of
//! the output's one-time secret key. It is not a provenance ZK proof and the
//! package is not encrypted; confidential delivery is an external transport
//! requirement.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use hyphen_crypto::{Hash256, PublicKey};
use hyphen_tx::note::OwnedNote;
use hyphen_tx::transaction::Transaction;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SELECTIVE_DISCLOSURE_VERSION: u8 = 0;
const D_CONTEXT: &[u8] = b"HYPHEN_SAC_DISCLOSURE_CONTEXT_V0";
const D_CHALLENGE: &[u8] = b"HYPHEN_SAC_OWNERSHIP_CHALLENGE_V0";
const D_CAPABILITY: &[u8] = b"HYPHEN_SAC_CAPABILITY_ID_V0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnershipProof {
    pub nonce_point: [u8; 32],
    pub response: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectiveDisclosure {
    pub version: u8,
    pub chain_id: Hash256,
    pub txid: Hash256,
    pub output_index: u32,
    pub global_index: u64,
    pub auditor: PublicKey,
    pub scope_hash: Hash256,
    pub issued_at: u64,
    pub expires_at: u64,
    pub disclosure_nonce: [u8; 32],
    pub commitment: [u8; 32],
    pub one_time_pubkey: [u8; 32],
    pub value: u64,
    pub blinding: [u8; 32],
    pub ownership_proof: OwnershipProof,
}

impl SelectiveDisclosure {
    /// Fixed-width, big-endian context authenticated by the ownership proof.
    pub fn canonical_context(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(293);
        bytes.push(self.version);
        bytes.extend_from_slice(self.chain_id.as_bytes());
        bytes.extend_from_slice(self.txid.as_bytes());
        bytes.extend_from_slice(&self.output_index.to_be_bytes());
        bytes.extend_from_slice(&self.global_index.to_be_bytes());
        bytes.extend_from_slice(self.auditor.as_bytes());
        bytes.extend_from_slice(self.scope_hash.as_bytes());
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.extend_from_slice(&self.disclosure_nonce);
        bytes.extend_from_slice(&self.commitment);
        bytes.extend_from_slice(&self.one_time_pubkey);
        bytes.extend_from_slice(&self.value.to_be_bytes());
        bytes.extend_from_slice(&self.blinding);
        bytes
    }

    pub fn capability_id(&self) -> Hash256 {
        hash_parts(
            D_CAPABILITY,
            &[
                &self.canonical_context(),
                &self.ownership_proof.nonce_point,
                &self.ownership_proof.response,
            ],
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AuditVerificationContext {
    pub chain_id: Hash256,
    pub auditor: PublicKey,
    pub scope_hash: Hash256,
    pub now: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("unsupported selective-disclosure version")]
    UnsupportedVersion,
    #[error("disclosure validity interval is invalid")]
    InvalidValidity,
    #[error("disclosure is not valid at the verification time")]
    OutsideValidity,
    #[error("disclosure is bound to another chain")]
    WrongChain,
    #[error("disclosure is bound to another auditor")]
    WrongAuditor,
    #[error("disclosure scope does not match")]
    WrongScope,
    #[error("transaction hash does not match the disclosure")]
    WrongTransaction,
    #[error("transaction output does not match the disclosure")]
    WrongOutput,
    #[error("disclosed amount and blinding do not open the commitment")]
    InvalidOpening,
    #[error("one-time spend key does not own the output")]
    NotOwner,
    #[error("ownership proof is malformed")]
    MalformedProof,
    #[error("ownership proof verification failed")]
    InvalidOwnershipProof,
}

#[allow(clippy::too_many_arguments)]
pub fn generate_disclosure(
    owned: &OwnedNote,
    transaction: &Transaction,
    output_index: u32,
    chain_id: Hash256,
    auditor: PublicKey,
    scope_hash: Hash256,
    issued_at: u64,
    expires_at: u64,
) -> Result<SelectiveDisclosure, AuditError> {
    if expires_at <= issued_at {
        return Err(AuditError::InvalidValidity);
    }
    let output = transaction
        .outputs
        .get(output_index as usize)
        .ok_or(AuditError::WrongOutput)?;
    if output.commitment != owned.note.commitment
        || output.one_time_pubkey != owned.note.one_time_pubkey
        || output.ephemeral_pubkey != owned.note.ephemeral_pubkey
        || output.encrypted_amount != owned.note.encrypted_amount
    {
        return Err(AuditError::WrongOutput);
    }
    verify_opening(owned.value, owned.blinding, *output.commitment.as_bytes())?;

    let secret = Scalar::from_bytes_mod_order(owned.spend_sk);
    let expected_point = secret * RISTRETTO_BASEPOINT_POINT;
    let expected_public = expected_point.compress().to_bytes();
    if expected_point.is_identity() || expected_public != output.one_time_pubkey {
        return Err(AuditError::NotOwner);
    }

    let mut disclosure_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut disclosure_nonce);
    let mut disclosure = SelectiveDisclosure {
        version: SELECTIVE_DISCLOSURE_VERSION,
        chain_id,
        txid: transaction.hash(),
        output_index,
        global_index: owned.note.global_index,
        auditor,
        scope_hash,
        issued_at,
        expires_at,
        disclosure_nonce,
        commitment: *output.commitment.as_bytes(),
        one_time_pubkey: output.one_time_pubkey,
        value: owned.value,
        blinding: owned.blinding,
        ownership_proof: OwnershipProof {
            nonce_point: [0; 32],
            response: [0; 32],
        },
    };
    loop {
        let nonce = Scalar::random(&mut OsRng);
        if nonce == Scalar::ZERO {
            continue;
        }
        let nonce_point = (nonce * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        let challenge = ownership_challenge(
            &disclosure.canonical_context(),
            &nonce_point,
            &disclosure.one_time_pubkey,
        );
        if challenge == Scalar::ZERO {
            continue;
        }
        disclosure.ownership_proof = OwnershipProof {
            nonce_point,
            response: (nonce + challenge * secret).to_bytes(),
        };
        break;
    }
    Ok(disclosure)
}

pub fn verify_disclosure(
    disclosure: &SelectiveDisclosure,
    transaction: &Transaction,
    context: AuditVerificationContext,
) -> Result<(), AuditError> {
    if disclosure.version != SELECTIVE_DISCLOSURE_VERSION {
        return Err(AuditError::UnsupportedVersion);
    }
    if disclosure.expires_at <= disclosure.issued_at {
        return Err(AuditError::InvalidValidity);
    }
    if context.now < disclosure.issued_at || context.now > disclosure.expires_at {
        return Err(AuditError::OutsideValidity);
    }
    if disclosure.chain_id != context.chain_id {
        return Err(AuditError::WrongChain);
    }
    if disclosure.auditor != context.auditor {
        return Err(AuditError::WrongAuditor);
    }
    if disclosure.scope_hash != context.scope_hash {
        return Err(AuditError::WrongScope);
    }
    if disclosure.txid != transaction.hash() {
        return Err(AuditError::WrongTransaction);
    }
    let output = transaction
        .outputs
        .get(disclosure.output_index as usize)
        .ok_or(AuditError::WrongOutput)?;
    if output.commitment.as_bytes() != &disclosure.commitment
        || output.one_time_pubkey != disclosure.one_time_pubkey
    {
        return Err(AuditError::WrongOutput);
    }
    verify_opening(disclosure.value, disclosure.blinding, disclosure.commitment)?;
    verify_ownership(disclosure)
}

fn verify_opening(value: u64, blinding: [u8; 32], commitment: [u8; 32]) -> Result<(), AuditError> {
    let expected =
        hyphen_crypto::pedersen::Commitment::create(value, Scalar::from_bytes_mod_order(blinding));
    if expected.as_bytes() != &commitment {
        return Err(AuditError::InvalidOpening);
    }
    Ok(())
}

fn verify_ownership(disclosure: &SelectiveDisclosure) -> Result<(), AuditError> {
    let public = CompressedRistretto(disclosure.one_time_pubkey)
        .decompress()
        .ok_or(AuditError::MalformedProof)?;
    let nonce_point = CompressedRistretto(disclosure.ownership_proof.nonce_point)
        .decompress()
        .ok_or(AuditError::MalformedProof)?;
    if public.is_identity() {
        return Err(AuditError::NotOwner);
    }
    if nonce_point.is_identity() {
        return Err(AuditError::MalformedProof);
    }
    let response = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        disclosure.ownership_proof.response,
    ))
    .ok_or(AuditError::MalformedProof)?;
    let challenge = ownership_challenge(
        &disclosure.canonical_context(),
        &disclosure.ownership_proof.nonce_point,
        &disclosure.one_time_pubkey,
    );
    if challenge == Scalar::ZERO {
        return Err(AuditError::MalformedProof);
    }
    if response * RISTRETTO_BASEPOINT_POINT != nonce_point + challenge * public {
        return Err(AuditError::InvalidOwnershipProof);
    }
    Ok(())
}

fn ownership_challenge(context: &[u8], nonce_point: &[u8; 32], public: &[u8; 32]) -> Scalar {
    let digest = hash_parts(D_CONTEXT, &[context]);
    hyphen_crypto::hash::hash_to_scalar(
        D_CHALLENGE,
        &[digest.as_bytes().as_slice(), nonce_point, public].concat(),
    )
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Hash256 {
    let total_len = domain.len() + 1 + parts.iter().map(|part| part.len()).sum::<usize>();
    let mut bytes = Vec::with_capacity(total_len);
    bytes.extend_from_slice(domain);
    bytes.push(0);
    for part in parts {
        bytes.extend_from_slice(part);
    }
    hyphen_crypto::blake3_hash(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_crypto::pedersen::Commitment;
    use hyphen_crypto::SecretKey;
    use hyphen_proof::range_proof::AggregatedRangeProof;
    use hyphen_tx::note::Note;
    use hyphen_tx::transaction::{Transaction, TxOutput, TxPrunable};

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn fixture() -> (OwnedNote, Transaction) {
        let value = 42u64;
        let blinding = Scalar::from(17u64);
        let spend = Scalar::from(23u64);
        let commitment = Commitment::create(value, blinding);
        let one_time_pubkey = (spend * RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        let output = TxOutput {
            commitment,
            one_time_pubkey,
            ephemeral_pubkey: [4; 32],
            encrypted_amount: [5; 32],
            view_tag: 6,
        };
        let (range_proof, _) = AggregatedRangeProof::prove(&[value], &[blinding]).unwrap();
        let transaction = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![output],
            fee: 0,
            extra: vec![],
            prunable: TxPrunable {
                clsag_signatures: vec![],
                range_proof,
            },
        };
        let owned = OwnedNote {
            note: Note {
                commitment,
                one_time_pubkey,
                ephemeral_pubkey: [4; 32],
                encrypted_amount: [5; 32],
                global_index: 99,
                block_height: 10,
            },
            value,
            blinding: blinding.to_bytes(),
            spend_sk: spend.to_bytes(),
        };
        (owned, transaction)
    }

    fn context(auditor: PublicKey) -> AuditVerificationContext {
        AuditVerificationContext {
            chain_id: hash(1),
            auditor,
            scope_hash: hash(2),
            now: 150,
        }
    }

    #[test]
    fn targeted_disclosure_verifies_opening_and_ownership() {
        let (owned, transaction) = fixture();
        let auditor = SecretKey([7; 32]).public_key();
        let disclosure =
            generate_disclosure(&owned, &transaction, 0, hash(1), auditor, hash(2), 100, 200)
                .unwrap();
        assert_eq!(disclosure.canonical_context().len(), 293);
        verify_disclosure(&disclosure, &transaction, context(auditor)).unwrap();
    }

    #[test]
    fn amount_scope_auditor_and_expiry_tampering_are_rejected() {
        let (owned, transaction) = fixture();
        let auditor = SecretKey([7; 32]).public_key();
        let disclosure =
            generate_disclosure(&owned, &transaction, 0, hash(1), auditor, hash(2), 100, 200)
                .unwrap();

        let mut amount = disclosure.clone();
        amount.value += 1;
        assert_eq!(
            verify_disclosure(&amount, &transaction, context(auditor)),
            Err(AuditError::InvalidOpening)
        );

        let mut wrong_scope = context(auditor);
        wrong_scope.scope_hash = hash(3);
        assert_eq!(
            verify_disclosure(&disclosure, &transaction, wrong_scope),
            Err(AuditError::WrongScope)
        );

        let wrong_auditor = context(SecretKey([8; 32]).public_key());
        assert_eq!(
            verify_disclosure(&disclosure, &transaction, wrong_auditor),
            Err(AuditError::WrongAuditor)
        );

        let mut expired = context(auditor);
        expired.now = 201;
        assert_eq!(
            verify_disclosure(&disclosure, &transaction, expired),
            Err(AuditError::OutsideValidity)
        );
    }

    #[test]
    fn another_output_secret_cannot_generate_disclosure() {
        let (mut owned, transaction) = fixture();
        owned.spend_sk = Scalar::from(24u64).to_bytes();
        assert_eq!(
            generate_disclosure(
                &owned,
                &transaction,
                0,
                hash(1),
                SecretKey([7; 32]).public_key(),
                hash(2),
                100,
                200,
            ),
            Err(AuditError::NotOwner)
        );
    }

    #[test]
    fn degenerate_identity_ownership_transcripts_are_rejected() {
        let (owned, mut transaction) = fixture();
        let auditor = SecretKey([7; 32]).public_key();
        let mut disclosure =
            generate_disclosure(&owned, &transaction, 0, hash(1), auditor, hash(2), 100, 200)
                .unwrap();
        let identity = curve25519_dalek::ristretto::RistrettoPoint::default()
            .compress()
            .to_bytes();
        transaction.outputs[0].one_time_pubkey = identity;
        disclosure.one_time_pubkey = identity;
        disclosure.txid = transaction.hash();
        disclosure.ownership_proof = OwnershipProof {
            nonce_point: identity,
            response: Scalar::ZERO.to_bytes(),
        };
        assert_eq!(
            verify_disclosure(&disclosure, &transaction, context(auditor)),
            Err(AuditError::NotOwner)
        );
    }

    #[test]
    fn identity_nonce_point_is_rejected_even_for_a_real_owner() {
        let (owned, transaction) = fixture();
        let auditor = SecretKey([7; 32]).public_key();
        let mut disclosure =
            generate_disclosure(&owned, &transaction, 0, hash(1), auditor, hash(2), 100, 200)
                .unwrap();
        disclosure.ownership_proof.nonce_point =
            curve25519_dalek::ristretto::RistrettoPoint::default()
                .compress()
                .to_bytes();
        assert_eq!(
            verify_disclosure(&disclosure, &transaction, context(auditor)),
            Err(AuditError::MalformedProof)
        );
    }

    #[test]
    fn reference_context_vector_is_stable() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/h-sac-disclosure-v0.json"
        ))
        .unwrap();
        assert_eq!(vector["schema"], "hyphen-h-sac-disclosure-vector-v0");
        let disclosure = SelectiveDisclosure {
            version: SELECTIVE_DISCLOSURE_VERSION,
            chain_id: hash(0x11),
            txid: hash(0x22),
            output_index: 1,
            global_index: 2,
            auditor: PublicKey([0x33; 32]),
            scope_hash: hash(0x44),
            issued_at: 100,
            expires_at: 200,
            disclosure_nonce: [0x55; 32],
            commitment: [0x66; 32],
            one_time_pubkey: [0x77; 32],
            value: 42,
            blinding: [0x88; 32],
            ownership_proof: OwnershipProof {
                nonce_point: [0x99; 32],
                response: [0xaa; 32],
            },
        };
        assert_eq!(
            hex::encode(disclosure.canonical_context()),
            vector["canonical_context"].as_str().unwrap()
        );
        assert_eq!(
            disclosure.capability_id().to_string(),
            vector["capability_id"].as_str().unwrap()
        );
    }
}
