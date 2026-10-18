//! Fixed-width wire encoding for the Alice contract.
//!
//! The encoding is hand-written rather than derived because the contract is
//! `no_std` and allocation-free, and because the format is a consensus surface:
//! every field is little-endian, every length is implicit in the shape, and any
//! trailing or truncated byte is an error. That is the same rule the base chain
//! applies to its own wire profile.

use crate::challenge::{ChallengeDescriptor, DESCRIPTOR_VERSION};
use crate::error::NeuralError;
use crate::mlp::MlpSpec;

/// Size of an encoded [`ChallengeDescriptor`].
pub const DESCRIPTOR_BYTES: usize = 2 + 8 + 2 + 2 + 2 + 8 + 32;

/// Size of an encoded submission header (opcode, epoch, width).
pub const SUBMISSION_HEADER_BYTES: usize = 1 + 8 + 2;

/// Operation codes accepted by `hyphen_execute`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Operation {
    /// Store a descriptor for an epoch. First writer wins.
    Open = 1,
    /// Verify a candidate preimage and record the first accepted one.
    Submit = 2,
    /// Read an epoch's descriptor and settlement state.
    Status = 3,
}

impl Operation {
    /// Decodes an operation code.
    pub fn decode(byte: u8) -> Result<Self, NeuralError> {
        match byte {
            1 => Ok(Self::Open),
            2 => Ok(Self::Submit),
            3 => Ok(Self::Status),
            _ => Err(NeuralError::UnknownOperation),
        }
    }
}

/// Encodes a descriptor into `out` and returns the number of bytes written.
pub fn encode_descriptor(
    descriptor: &ChallengeDescriptor,
    out: &mut [u8],
) -> Result<usize, NeuralError> {
    descriptor.validate()?;
    if out.len() < DESCRIPTOR_BYTES {
        return Err(NeuralError::InvalidBuffer);
    }
    out[0..2].copy_from_slice(&descriptor.version.to_le_bytes());
    out[2..10].copy_from_slice(&descriptor.epoch.to_le_bytes());
    out[10..12].copy_from_slice(&descriptor.spec.input_dim.to_le_bytes());
    out[12..14].copy_from_slice(&descriptor.spec.hidden_dim.to_le_bytes());
    out[14..16].copy_from_slice(&descriptor.spec.output_dim.to_le_bytes());
    out[16..24].copy_from_slice(&descriptor.tolerance_ulp.to_le_bytes());
    out[24..56].copy_from_slice(&descriptor.chain_seed);
    Ok(DESCRIPTOR_BYTES)
}

/// Decodes exactly [`DESCRIPTOR_BYTES`] bytes, rejecting anything else.
pub fn decode_descriptor(bytes: &[u8]) -> Result<ChallengeDescriptor, NeuralError> {
    if bytes.len() != DESCRIPTOR_BYTES {
        return Err(NeuralError::InvalidEncoding);
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    if version != DESCRIPTOR_VERSION {
        return Err(NeuralError::InvalidDescriptor);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[24..56]);
    let descriptor = ChallengeDescriptor {
        version,
        epoch: u64::from_le_bytes(
            bytes[2..10]
                .try_into()
                .map_err(|_| NeuralError::InvalidEncoding)?,
        ),
        spec: MlpSpec {
            input_dim: u16::from_le_bytes([bytes[10], bytes[11]]),
            hidden_dim: u16::from_le_bytes([bytes[12], bytes[13]]),
            output_dim: u16::from_le_bytes([bytes[14], bytes[15]]),
        },
        tolerance_ulp: u64::from_le_bytes(
            bytes[16..24]
                .try_into()
                .map_err(|_| NeuralError::InvalidEncoding)?,
        ),
        chain_seed: seed,
    };
    descriptor.validate()?;
    Ok(descriptor)
}

/// Decodes an `Open` request body (`opcode || descriptor`).
pub fn decode_open(request: &[u8]) -> Result<ChallengeDescriptor, NeuralError> {
    if request.len() != 1 + DESCRIPTOR_BYTES {
        return Err(NeuralError::InvalidEncoding);
    }
    if Operation::decode(request[0])? != Operation::Open {
        return Err(NeuralError::UnknownOperation);
    }
    decode_descriptor(&request[1..])
}

/// Encodes an `Open` request body.
pub fn encode_open(descriptor: &ChallengeDescriptor, out: &mut [u8]) -> Result<usize, NeuralError> {
    if out.len() < 1 + DESCRIPTOR_BYTES {
        return Err(NeuralError::InvalidBuffer);
    }
    out[0] = Operation::Open as u8;
    encode_descriptor(descriptor, &mut out[1..])?;
    Ok(1 + DESCRIPTOR_BYTES)
}

/// Decodes a `Status` request body (`opcode || epoch`).
pub fn decode_status(request: &[u8]) -> Result<u64, NeuralError> {
    if request.len() != 9 {
        return Err(NeuralError::InvalidEncoding);
    }
    if Operation::decode(request[0])? != Operation::Status {
        return Err(NeuralError::UnknownOperation);
    }
    Ok(u64::from_le_bytes(
        request[1..9]
            .try_into()
            .map_err(|_| NeuralError::InvalidEncoding)?,
    ))
}

/// Decodes a `Submit` request body into the epoch and the raw value bytes.
///
/// The value bytes borrow the request, so the contract decodes straight out of
/// its input buffer without a second copy. `width` comes from the descriptor,
/// which makes the accepted length exact.
pub fn decode_submit(request: &[u8], width: usize) -> Result<(u64, &[u8]), NeuralError> {
    let expected = SUBMISSION_HEADER_BYTES + width * 8;
    if request.len() != expected {
        return Err(NeuralError::InvalidEncoding);
    }
    if Operation::decode(request[0])? != Operation::Submit {
        return Err(NeuralError::UnknownOperation);
    }
    let epoch = u64::from_le_bytes(
        request[1..9]
            .try_into()
            .map_err(|_| NeuralError::InvalidEncoding)?,
    );
    let declared = u16::from_le_bytes([request[9], request[10]]) as usize;
    if declared != width {
        return Err(NeuralError::InvalidSolution);
    }
    Ok((epoch, &request[SUBMISSION_HEADER_BYTES..]))
}

/// Encodes a `Submit` request body.
pub fn encode_submit(epoch: u64, solution: &[i64], out: &mut [u8]) -> Result<usize, NeuralError> {
    let width = u16::try_from(solution.len()).map_err(|_| NeuralError::InvalidSolution)?;
    let required = SUBMISSION_HEADER_BYTES + solution.len() * 8;
    if out.len() < required {
        return Err(NeuralError::InvalidBuffer);
    }
    out[0] = Operation::Submit as u8;
    out[1..9].copy_from_slice(&epoch.to_le_bytes());
    out[9..11].copy_from_slice(&width.to_le_bytes());
    for (index, value) in solution.iter().enumerate() {
        let offset = SUBMISSION_HEADER_BYTES + index * 8;
        out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    Ok(required)
}

/// Decodes little-endian Q32.32 values into `out`.
pub fn decode_values_into(bytes: &[u8], out: &mut [i64]) -> Result<usize, NeuralError> {
    if !bytes.len().is_multiple_of(8) || bytes.len() / 8 > out.len() {
        return Err(NeuralError::InvalidEncoding);
    }
    for (index, chunk) in bytes.chunks_exact(8).enumerate() {
        out[index] =
            i64::from_le_bytes(chunk.try_into().map_err(|_| NeuralError::InvalidEncoding)?);
    }
    Ok(bytes.len() / 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::DEFAULT_TOLERANCE_ULP;

    fn descriptor() -> ChallengeDescriptor {
        ChallengeDescriptor {
            version: DESCRIPTOR_VERSION,
            epoch: 0x0102_0304_0506_0708,
            spec: MlpSpec {
                input_dim: 16,
                hidden_dim: 32,
                output_dim: 16,
            },
            tolerance_ulp: DEFAULT_TOLERANCE_ULP,
            chain_seed: [9; 32],
        }
    }

    #[test]
    fn descriptor_round_trips() {
        let descriptor = descriptor();
        let mut bytes = [0u8; DESCRIPTOR_BYTES];
        assert_eq!(
            encode_descriptor(&descriptor, &mut bytes).unwrap(),
            DESCRIPTOR_BYTES
        );
        assert_eq!(decode_descriptor(&bytes).unwrap(), descriptor);
    }

    #[test]
    fn trailing_and_truncated_descriptors_are_rejected() {
        let descriptor = descriptor();
        let mut bytes = [0u8; DESCRIPTOR_BYTES + 1];
        encode_descriptor(&descriptor, &mut bytes).unwrap();
        assert_eq!(decode_descriptor(&bytes), Err(NeuralError::InvalidEncoding));
        assert_eq!(
            decode_descriptor(&bytes[..DESCRIPTOR_BYTES - 1]),
            Err(NeuralError::InvalidEncoding)
        );
    }

    #[test]
    fn submit_round_trips_and_rejects_a_mismatched_width() {
        let solution = [1i64, -2, 3, -4];
        let mut bytes = [0u8; SUBMISSION_HEADER_BYTES + 32];
        let length = encode_submit(42, &solution, &mut bytes).unwrap();
        let (epoch, values) = decode_submit(&bytes[..length], 4).unwrap();
        assert_eq!(epoch, 42);
        let mut decoded = [0i64; 4];
        decode_values_into(values, &mut decoded).unwrap();
        assert_eq!(decoded, solution);
        assert!(decode_submit(&bytes[..length], 3).is_err());
    }

    #[test]
    fn unknown_opcodes_are_rejected() {
        assert_eq!(Operation::decode(0), Err(NeuralError::UnknownOperation));
        assert_eq!(Operation::decode(4), Err(NeuralError::UnknownOperation));
        assert_eq!(Operation::decode(1).unwrap(), Operation::Open);
    }

    #[test]
    fn value_decoding_checks_alignment_and_capacity() {
        let mut out = [0i64; 2];
        assert!(decode_values_into(&[0u8; 15], &mut out).is_err());
        assert!(decode_values_into(&[0u8; 24], &mut out).is_err());
        assert_eq!(decode_values_into(&[0u8; 16], &mut out).unwrap(), 2);
    }
}
