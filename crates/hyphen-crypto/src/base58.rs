//! Base58 encoder and decoder for address display forms.
//!
//! Bitcoin's alphabet, big-endian arithmetic on a `[u8; 58]` digit buffer, and
//! leading-zero preservation. Decoding rejects any character outside the
//! alphabet instead of silently truncating.

use std::fmt;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base58Error {
    InvalidCharacter(u8),
    Overflow,
}

impl fmt::Display for Base58Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter(byte) => {
                write!(
                    formatter,
                    "base58 input contains invalid character {byte:#04x}"
                )
            }
            Self::Overflow => write!(formatter, "base58 input exceeds the supported length"),
        }
    }
}

impl std::error::Error for Base58Error {}

pub fn encode(input: &[u8]) -> String {
    let leading_zeros = input.iter().take_while(|byte| **byte == 0).count();
    let mut digits = vec![0u8; (input.len() - leading_zeros) * 138 / 100 + 1];

    for byte in &input[leading_zeros..] {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut().rev() {
            carry += 256 * u32::from(*digit);
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
    }

    let first_significant = digits
        .iter()
        .position(|digit| *digit != 0)
        .unwrap_or(digits.len());
    let mut output = String::with_capacity(leading_zeros + digits.len() - first_significant);
    for _ in 0..leading_zeros {
        output.push(ALPHABET[0] as char);
    }
    for digit in &digits[first_significant..] {
        output.push(ALPHABET[*digit as usize] as char);
    }
    output
}

pub fn decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, Base58Error> {
    let input = input.as_ref();
    let max_encoded = ALPHABET.len();
    let leading_ones = input
        .iter()
        .take_while(|byte| **byte == ALPHABET[0])
        .count();
    let mut bytes = vec![0u8; (input.len() - leading_ones) * 733 / 1000 + 1];

    for character in &input[leading_ones..] {
        let value = ALPHABET
            .iter()
            .position(|candidate| candidate == character)
            .ok_or(Base58Error::InvalidCharacter(*character))? as u32;

        let mut carry = value;
        for byte in bytes.iter_mut().rev() {
            carry += max_encoded as u32 * u32::from(*byte);
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        if carry != 0 {
            return Err(Base58Error::Overflow);
        }
    }

    let first_significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    let mut output = Vec::with_capacity(leading_ones + bytes.len() - first_significant);
    output.resize(leading_ones, 0);
    output.extend_from_slice(&bytes[first_significant..]);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors_match_the_reference_implementation() {
        let cases: &[(&[u8], &str)] = &[
            (&[], ""),
            (&[0x00], "1"),
            (&[0x00, 0x00, 0x01], "112"),
            (b"Hello World!", "2NEpo7TZRRrLZSi2U"),
            (&[0xff; 5], "VtB5VXc"),
            (&[0xff; 32], "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG"),
        ];
        for (bytes, encoded) in cases {
            assert_eq!(&encode(bytes), encoded);
            assert_eq!(&decode(encoded.as_bytes()).unwrap(), bytes);
        }
    }

    #[test]
    fn round_trips_arbitrary_payloads() {
        let payload: Vec<u8> = (0..64u8).map(|index| index.wrapping_mul(37)).collect();
        assert_eq!(decode(encode(&payload)).unwrap(), payload);

        let with_zeroes = [0u8, 0, 0, 9, 0, 4, 0];
        assert_eq!(decode(encode(&with_zeroes)).unwrap(), with_zeroes);
    }

    #[test]
    fn ambiguous_characters_are_rejected() {
        // 0, O, I and l are excluded from the alphabet precisely so that they
        // cannot be confused with 1 and o in transcription.
        for invalid in *b"0OIl " {
            assert_eq!(
                decode([invalid]),
                Err(Base58Error::InvalidCharacter(invalid))
            );
        }
    }
}
