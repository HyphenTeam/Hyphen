//! Lowercase hex codec used for the textual forms of hashes, keys and
//! identifiers. Deliberately minimal: encoding, decoding and nothing else.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    OddLength,
    InvalidCharacter(u8),
}

impl fmt::Display for HexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength => write!(formatter, "hex input has an odd number of characters"),
            Self::InvalidCharacter(byte) => {
                write!(
                    formatter,
                    "hex input contains invalid character {byte:#04x}"
                )
            }
        }
    }
}

impl std::error::Error for HexError {}

const LOWER: &[u8; 16] = b"0123456789abcdef";

pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(LOWER[(byte >> 4) as usize] as char);
        output.push(LOWER[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Decodes a hex string, accepting both letter cases.
pub fn decode(input: impl AsRef<str>) -> Result<Vec<u8>, HexError> {
    let bytes = input.as_ref().as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = nibble(pair[0])?;
        let low = nibble(pair[1])?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn nibble(byte: u8) -> Result<u8, HexError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(HexError::InvalidCharacter(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_byte_value() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode(encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn decodes_upper_case_and_rejects_malformed_input() {
        assert_eq!(decode("DEADbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode("abc"), Err(HexError::OddLength));
        assert_eq!(decode("zz"), Err(HexError::InvalidCharacter(b'z')));
    }
}
