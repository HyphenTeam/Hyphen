//! Transport-neutral external signer protocol.
//!
//! USB HID, WebUSB, BLE and QR transports carry these messages but are not
//! implemented here. A device application must implement Hyphen ICD key
//! derivation and CLSAG signing before a vendor can be considered supported.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use hyphen_crypto::clsag::{self, ClsagSignature};
use hyphen_crypto::Hash256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::address::HyphenAddress;

pub const SIGNER_PROTOCOL_VERSION: u32 = 1;
pub const MAX_SIGNER_INPUTS: usize = 16;
pub const MAX_SIGNER_OUTPUTS: usize = 16;
pub const MAX_SIGNER_RING_SIZE: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceFamily {
    Software,
    Ledger,
    Trezor,
    SafePal,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerTransport {
    InProcess,
    UsbHid,
    WebUsb,
    Bluetooth,
    Qr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkBinding {
    pub network_magic: [u8; 4],
    pub genesis_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyLocator {
    pub derivation_scheme: String,
    pub account: u32,
    pub change: u32,
    pub index: u32,
}

impl Default for KeyLocator {
    fn default() -> Self {
        Self {
            derivation_scheme: "hyphen-icd-v1".into(),
            account: 0,
            change: 0,
            index: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewOutput {
    pub address: String,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClsagSigningInput {
    pub amount: u64,
    pub ring_public_keys: Vec<[u8; 32]>,
    pub ring_commitments: Vec<[u8; 32]>,
    pub pseudo_output: [u8; 32],
    pub expected_key_image: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningRequest {
    pub protocol_version: u32,
    pub request_id: [u8; 32],
    pub network: NetworkBinding,
    pub key: KeyLocator,
    pub tx_prefix_hash: [u8; 32],
    pub fee: u64,
    pub outputs: Vec<ReviewOutput>,
    pub inputs: Vec<ClsagSigningInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningResponse {
    pub protocol_version: u32,
    pub request_id: [u8; 32],
    pub signatures: Vec<ClsagSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerCapabilities {
    pub protocol_version: u32,
    pub family: DeviceFamily,
    pub transport: SignerTransport,
    pub firmware: String,
    pub supported_network_magic: Vec<[u8; 4]>,
    pub supports_hyphen_icd_v1: bool,
    pub supports_clsag_v1: bool,
    pub max_ring_size: u32,
}

pub trait ExternalSigner {
    fn capabilities(&mut self) -> Result<SignerCapabilities, SignerError>;
    fn sign(&mut self, request: &SigningRequest) -> Result<SigningResponse, SignerError>;
}

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("unsupported signer capability: {0}")]
    Unsupported(String),
    #[error("request id mismatch")]
    RequestIdMismatch,
    #[error("signature count mismatch")]
    SignatureCountMismatch,
    #[error("invalid curve point in input {0}")]
    InvalidPoint(usize),
    #[error("key image mismatch in input {0}")]
    KeyImageMismatch(usize),
    #[error("CLSAG verification failed in input {0}")]
    ClsagVerification(usize),
    #[error("transport: {0}")]
    Transport(String),
}

impl SigningRequest {
    pub fn new(
        network: NetworkBinding,
        key: KeyLocator,
        tx_prefix_hash: [u8; 32],
        fee: u64,
        outputs: Vec<ReviewOutput>,
        inputs: Vec<ClsagSigningInput>,
    ) -> Result<Self, SignerError> {
        let mut request = Self {
            protocol_version: SIGNER_PROTOCOL_VERSION,
            request_id: [0u8; 32],
            network,
            key,
            tx_prefix_hash,
            fee,
            outputs,
            inputs,
        };
        request.validate_body()?;
        request.request_id = request.compute_request_id();
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), SignerError> {
        self.validate_body()?;
        if self.request_id != self.compute_request_id() {
            return Err(SignerError::RequestIdMismatch);
        }
        Ok(())
    }

    pub fn compute_request_id(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"HyphenSignerRequest/v1");
        bytes.extend_from_slice(&self.protocol_version.to_le_bytes());
        bytes.extend_from_slice(&self.network.network_magic);
        bytes.extend_from_slice(&self.network.genesis_hash);
        push_bytes(&mut bytes, self.key.derivation_scheme.as_bytes());
        bytes.extend_from_slice(&self.key.account.to_le_bytes());
        bytes.extend_from_slice(&self.key.change.to_le_bytes());
        bytes.extend_from_slice(&self.key.index.to_le_bytes());
        bytes.extend_from_slice(&self.tx_prefix_hash);
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for output in &self.outputs {
            push_bytes(&mut bytes, output.address.as_bytes());
            bytes.extend_from_slice(&output.amount.to_le_bytes());
        }
        bytes.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            bytes.extend_from_slice(&input.amount.to_le_bytes());
            bytes.extend_from_slice(&(input.ring_public_keys.len() as u32).to_le_bytes());
            for point in &input.ring_public_keys {
                bytes.extend_from_slice(point);
            }
            for point in &input.ring_commitments {
                bytes.extend_from_slice(point);
            }
            bytes.extend_from_slice(&input.pseudo_output);
            bytes.extend_from_slice(&input.expected_key_image);
        }
        *hyphen_crypto::blake3_hash(&bytes).as_bytes()
    }

    fn validate_body(&self) -> Result<(), SignerError> {
        if self.protocol_version != SIGNER_PROTOCOL_VERSION {
            return Err(SignerError::InvalidRequest(
                "unsupported protocol version".into(),
            ));
        }
        if self.network.genesis_hash == [0u8; 32] || self.tx_prefix_hash == [0u8; 32] {
            return Err(SignerError::InvalidRequest(
                "genesis and transaction hashes must be non-zero".into(),
            ));
        }
        if self.key.derivation_scheme != "hyphen-icd-v1" {
            return Err(SignerError::InvalidRequest(
                "unknown derivation scheme".into(),
            ));
        }
        if self.inputs.is_empty() || self.inputs.len() > MAX_SIGNER_INPUTS {
            return Err(SignerError::InvalidRequest("invalid input count".into()));
        }
        if self.outputs.is_empty() || self.outputs.len() > MAX_SIGNER_OUTPUTS {
            return Err(SignerError::InvalidRequest("invalid output count".into()));
        }

        let expect_mainnet = match self.network.network_magic {
            [0x48, 0x59, 0x50, 0x4e] => true,
            [0x48, 0x59, 0x54, 0x53] => false,
            _ => return Err(SignerError::InvalidRequest("unknown network magic".into())),
        };
        let mut output_total = 0u64;
        for output in &self.outputs {
            let address = HyphenAddress::decode(&output.address)
                .map_err(|error| SignerError::InvalidRequest(error.to_string()))?;
            if address.is_mainnet() != expect_mainnet || output.amount == 0 {
                return Err(SignerError::InvalidRequest(
                    "output address network or amount is invalid".into(),
                ));
            }
            output_total = output_total
                .checked_add(output.amount)
                .ok_or_else(|| SignerError::InvalidRequest("output total overflow".into()))?;
        }

        let mut input_total = 0u64;
        for input in &self.inputs {
            let ring_size = input.ring_public_keys.len();
            if !(2..=MAX_SIGNER_RING_SIZE).contains(&ring_size)
                || input.ring_commitments.len() != ring_size
            {
                return Err(SignerError::InvalidRequest(
                    "invalid ring dimensions".into(),
                ));
            }
            input_total = input_total
                .checked_add(input.amount)
                .ok_or_else(|| SignerError::InvalidRequest("input total overflow".into()))?;
        }
        let required = output_total
            .checked_add(self.fee)
            .ok_or_else(|| SignerError::InvalidRequest("fee total overflow".into()))?;
        if input_total != required {
            return Err(SignerError::InvalidRequest(format!(
                "value mismatch: inputs {input_total}, outputs {output_total}, fee {}",
                self.fee
            )));
        }
        Ok(())
    }
}

impl SignerCapabilities {
    pub fn validate_for(&self, request: &SigningRequest) -> Result<(), SignerError> {
        request.validate()?;
        if self.protocol_version != SIGNER_PROTOCOL_VERSION
            || !self.supports_hyphen_icd_v1
            || !self.supports_clsag_v1
            || !self
                .supported_network_magic
                .contains(&request.network.network_magic)
        {
            return Err(SignerError::Unsupported(
                "device does not advertise the required Hyphen protocol".into(),
            ));
        }
        let request_ring_size = request
            .inputs
            .iter()
            .map(|input| input.ring_public_keys.len())
            .max()
            .unwrap_or(0);
        if request_ring_size > self.max_ring_size as usize {
            return Err(SignerError::Unsupported(format!(
                "device ring limit is {}, request needs {request_ring_size}",
                self.max_ring_size
            )));
        }
        Ok(())
    }
}

pub fn verify_signing_response(
    request: &SigningRequest,
    response: &SigningResponse,
) -> Result<(), SignerError> {
    request.validate()?;
    if response.protocol_version != SIGNER_PROTOCOL_VERSION
        || response.request_id != request.request_id
    {
        return Err(SignerError::RequestIdMismatch);
    }
    if response.signatures.len() != request.inputs.len() {
        return Err(SignerError::SignatureCountMismatch);
    }

    for (index, (input, signature)) in request.inputs.iter().zip(&response.signatures).enumerate() {
        if signature.key_image != input.expected_key_image {
            return Err(SignerError::KeyImageMismatch(index));
        }
        let ring_keys =
            decode_points(&input.ring_public_keys).ok_or(SignerError::InvalidPoint(index))?;
        let ring_commitments =
            decode_points(&input.ring_commitments).ok_or(SignerError::InvalidPoint(index))?;
        let pseudo_output =
            decode_point(&input.pseudo_output).ok_or(SignerError::InvalidPoint(index))?;
        clsag::clsag_verify(
            &request.tx_prefix_hash,
            &ring_keys,
            &ring_commitments,
            &pseudo_output,
            signature,
        )
        .map_err(|_| SignerError::ClsagVerification(index))?;
    }
    Ok(())
}

fn decode_points(points: &[[u8; 32]]) -> Option<Vec<RistrettoPoint>> {
    points.iter().map(decode_point).collect()
}

fn decode_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes).ok()?.decompress()
}

fn push_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u32).to_le_bytes());
    target.extend_from_slice(value);
}

pub fn binding_from_genesis(network_magic: [u8; 4], genesis_hash: Hash256) -> NetworkBinding {
    NetworkBinding {
        network_magic,
        genesis_hash: *genesis_hash.as_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn request_is_network_bound_and_response_is_verified() {
        let spend = Scalar::random(&mut OsRng);
        let decoy = Scalar::random(&mut OsRng) * G;
        let ring_keys = vec![spend * G, decoy];
        let gens = hyphen_crypto::pedersen::PedersenGens::default();
        let real_blind = Scalar::random(&mut OsRng);
        let pseudo_blind = Scalar::random(&mut OsRng);
        let ring_commitments = vec![
            gens.commit(Scalar::from(11u64), real_blind),
            gens.commit(Scalar::from(17u64), Scalar::random(&mut OsRng)),
        ];
        let pseudo = gens.commit(Scalar::from(11u64), pseudo_blind);
        let message = [7u8; 32];
        let signature = clsag::clsag_sign(
            &message,
            &ring_keys,
            &ring_commitments,
            &pseudo,
            0,
            &spend,
            &(real_blind - pseudo_blind),
        )
        .unwrap();
        let address = HyphenAddress::new_mainnet([3u8; 32], [4u8; 32]).encode();
        let request = SigningRequest::new(
            NetworkBinding {
                network_magic: [0x48, 0x59, 0x50, 0x4e],
                genesis_hash: [9u8; 32],
            },
            KeyLocator::default(),
            message,
            1,
            vec![ReviewOutput {
                address,
                amount: 10,
            }],
            vec![ClsagSigningInput {
                amount: 11,
                ring_public_keys: ring_keys
                    .iter()
                    .map(|point| point.compress().to_bytes())
                    .collect(),
                ring_commitments: ring_commitments
                    .iter()
                    .map(|point| point.compress().to_bytes())
                    .collect(),
                pseudo_output: pseudo.compress().to_bytes(),
                expected_key_image: signature.key_image,
            }],
        )
        .unwrap();
        let response = SigningResponse {
            protocol_version: SIGNER_PROTOCOL_VERSION,
            request_id: request.request_id,
            signatures: vec![signature],
        };
        verify_signing_response(&request, &response).unwrap();

        let mut wrong_network = request.clone();
        wrong_network.network.network_magic = [0x48, 0x59, 0x54, 0x53];
        assert!(wrong_network.validate().is_err());
    }
}
