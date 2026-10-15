//! Encrypted wallet container.
//!
//! Layout of the current container (version 2):
//!
//! ```text
//! magic      8   b"HYPHWLT2"
//! iterations 4   little-endian u32, key-stretching rounds
//! salt       32  fresh system randomness per save
//! mac        32  keyed BLAKE3 over magic ‖ iterations ‖ salt ‖ ciphertext
//! ciphertext ..  wallet bytes XORed with the keyed BLAKE3 XOF keystream
//! ```
//!
//! Properties this file format is built to hold:
//!
//! - **Distinct keys per purpose.** The password is stretched into a root, and
//!   three domain-separated subkeys are derived from it: one for the keystream,
//!   one for the MAC. No key is used for two primitives.
//! - **Encrypt-then-MAC over the whole header.** Changing the iteration count,
//!   the salt or any ciphertext byte invalidates the tag, so a downgrade of the
//!   work factor is a forgery rather than a silent weakening.
//! - **Versioned work factor.** `iterations` is stored per file, so the cost can
//!   be raised for new saves without breaking old ones.
//! - **Constant-time tag comparison.** A file-based MAC comparison is a weak
//!   oracle, but there is no reason to leave it early-exiting.
//! - **Read-only legacy path.** Version 1 containers (salt ‖ mac ‖ ciphertext
//!   with the original key schedule) still open, so existing wallets survive.
//!
//! Honest limitation: this is a *stretched* KDF, not a memory-hard one. A
//! million BLAKE3 rounds raise the cost of guessing a weak password by the same
//! factor for an attacker and an honest user, but a GPU cluster still evaluates
//! this far faster than a human chooses passwords. Replacing it with Argon2id
//! (or any memory-hard KDF) is the tracked fix; the container is versioned
//! precisely so that change is a format bump rather than a migration crisis.

use std::fmt;
use std::path::Path;

use zeroize::Zeroize;

/// Version 2 magic. Chosen so that a version 1 file cannot be mistaken for it:
/// legacy files begin with 32 random salt bytes.
const MAGIC: &[u8; 8] = b"HYPHWLT2";
const MAGIC_LEN: usize = MAGIC.len();
const ITERATIONS_LEN: usize = 4;
const SALT_LEN: usize = 32;
const MAC_LEN: usize = 32;
const HEADER_LEN: usize = MAGIC_LEN + ITERATIONS_LEN + SALT_LEN + MAC_LEN;
const LEGACY_HEADER_LEN: usize = SALT_LEN + MAC_LEN;

/// Key-stretching rounds for new containers. Roughly 100 ms on a current
/// desktop core; the value is stored in the file so it can be raised later.
pub const DEFAULT_ITERATIONS: u32 = 1_000_000;
const MIN_ITERATIONS: u32 = 10_000;
const MAX_ITERATIONS: u32 = 100_000_000;

const KDF_CONTEXT: &str = "Hyphen wallet KDF v2";
const STREAM_KEY_CONTEXT: &str = "Hyphen wallet stream key v2";
const MAC_KEY_CONTEXT: &str = "Hyphen wallet mac key v2";
const STREAM_DOMAIN: &[u8] = b"Hyphen wallet stream v2";

#[derive(Debug, PartialEq, Eq)]
pub enum KeystoreError {
    Io(String),
    TooShort {
        length: usize,
    },
    /// The container parses but the tag does not verify: wrong password or
    /// tampered file. The two cases are deliberately indistinguishable.
    Authentication,
    /// Well-formed header with a work factor outside the accepted range.
    InvalidIterations(u32),
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => write!(formatter, "keystore io: {message}"),
            Self::TooShort { length } => {
                write!(
                    formatter,
                    "keystore container is truncated ({length} bytes)"
                )
            }
            Self::Authentication => write!(formatter, "wrong password or corrupted wallet file"),
            Self::InvalidIterations(iterations) => {
                write!(formatter, "wallet work factor {iterations} is implausible")
            }
        }
    }
}

impl std::error::Error for KeystoreError {}

/// Encrypts and authenticates a wallet snapshot.
pub fn seal(plaintext: &[u8], password: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; SALT_LEN];
    hyphen_crypto::rng::fill_system_random(&mut salt);
    seal_with(plaintext, password, &salt, DEFAULT_ITERATIONS)
}

/// Deterministic variant used by tests and by callers that must control the
/// salt. Production code uses [`seal`].
pub(crate) fn seal_with(
    plaintext: &[u8],
    password: &[u8],
    salt: &[u8; SALT_LEN],
    iterations: u32,
) -> Vec<u8> {
    let keys = derive_keys(password, salt, iterations);
    let ciphertext = apply_stream(&keys.stream, salt, iterations, plaintext);

    let mut signed_header = Vec::with_capacity(MAGIC_LEN + ITERATIONS_LEN + SALT_LEN);
    signed_header.extend_from_slice(MAGIC);
    signed_header.extend_from_slice(&iterations.to_le_bytes());
    signed_header.extend_from_slice(salt);

    let tag = tag_of(&keys.mac, &signed_header, &ciphertext);

    let mut container = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    container.extend_from_slice(&signed_header);
    container.extend_from_slice(tag.as_bytes());
    container.extend_from_slice(&ciphertext);
    container
}

/// Decrypts and authenticates a wallet snapshot, accepting version 2 and the
/// legacy version 1 layout.
pub fn open(container: &[u8], password: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if container.starts_with(MAGIC) {
        open_current(container, password)
    } else {
        open_legacy(container, password)
    }
}

pub fn seal_to_path(path: &Path, plaintext: &[u8], password: &[u8]) -> Result<(), KeystoreError> {
    let container = seal(plaintext, password);
    std::fs::write(path, container).map_err(|error| KeystoreError::Io(error.to_string()))
}

pub fn open_from_path(path: &Path, password: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let container = std::fs::read(path).map_err(|error| KeystoreError::Io(error.to_string()))?;
    open(&container, password)
}

fn open_current(container: &[u8], password: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if container.len() < HEADER_LEN {
        return Err(KeystoreError::TooShort {
            length: container.len(),
        });
    }
    let iterations = u32::from_le_bytes(
        container[MAGIC_LEN..MAGIC_LEN + ITERATIONS_LEN]
            .try_into()
            .expect("four-byte iteration field"),
    );
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(KeystoreError::InvalidIterations(iterations));
    }
    let salt: [u8; SALT_LEN] = container
        [MAGIC_LEN + ITERATIONS_LEN..MAGIC_LEN + ITERATIONS_LEN + SALT_LEN]
        .try_into()
        .expect("32-byte salt field");

    let keys = derive_keys(password, &salt, iterations);
    let signed_header = &container[..MAGIC_LEN + ITERATIONS_LEN + SALT_LEN];
    let ciphertext = &container[HEADER_LEN..];
    let stored_mac = &container[MAGIC_LEN + ITERATIONS_LEN + SALT_LEN..HEADER_LEN];
    let expected = tag_of(&keys.mac, signed_header, ciphertext);
    if !constant_time_eq(stored_mac, expected.as_bytes()) {
        return Err(KeystoreError::Authentication);
    }

    Ok(apply_stream(&keys.stream, &salt, iterations, ciphertext))
}

fn open_legacy(container: &[u8], password: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if container.len() < LEGACY_HEADER_LEN {
        return Err(KeystoreError::TooShort {
            length: container.len(),
        });
    }
    let salt: [u8; SALT_LEN] = container[..SALT_LEN]
        .try_into()
        .expect("32-byte salt field");
    let stored_mac = &container[SALT_LEN..LEGACY_HEADER_LEN];
    let ciphertext = &container[LEGACY_HEADER_LEN..];

    let mut key = legacy_root_key(password, &salt);
    let expected = blake3::keyed_hash(&key, ciphertext);
    if !constant_time_eq(stored_mac, expected.as_bytes()) {
        key.zeroize();
        return Err(KeystoreError::Authentication);
    }

    let mut stream = legacy_keystream(&key, ciphertext.len());
    key.zeroize();
    let mut plaintext = ciphertext.to_vec();
    for (byte, mask) in plaintext.iter_mut().zip(stream.iter()) {
        *byte ^= mask;
    }
    stream.zeroize();
    Ok(plaintext)
}

struct Keys {
    stream: [u8; 32],
    mac: [u8; 32],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.stream.zeroize();
        self.mac.zeroize();
    }
}

fn derive_keys(password: &[u8], salt: &[u8; SALT_LEN], iterations: u32) -> Keys {
    let material = [password, salt.as_slice()].concat();
    let mut state = blake3::derive_key(KDF_CONTEXT, &material);

    // Each round is salted and indexed, so a precomputed chain for one salt is
    // worthless for another and the rounds cannot be merged across saves.
    for round in 0..iterations {
        let mut hasher = blake3::Hasher::new_keyed(&state);
        hasher.update(salt);
        hasher.update(&round.to_le_bytes());
        state = *hasher.finalize().as_bytes();
    }

    let mut stream = blake3::derive_key(STREAM_KEY_CONTEXT, &state);
    let mut mac = blake3::derive_key(MAC_KEY_CONTEXT, &state);
    state.zeroize();
    let keys = Keys { stream, mac };
    stream.zeroize();
    mac.zeroize();
    keys
}

fn tag_of(mac_key: &[u8; 32], header: &[u8], ciphertext: &[u8]) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(STREAM_DOMAIN);
    hasher.update(header);
    hasher.update(ciphertext);
    hasher.finalize()
}

fn apply_stream(
    stream_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    iterations: u32,
    input: &[u8],
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_keyed(stream_key);
    hasher.update(STREAM_DOMAIN);
    hasher.update(salt);
    hasher.update(&iterations.to_le_bytes());
    let mut xof = hasher.finalize_xof();

    // The keystream is generated in bounded blocks so that a large wallet does
    // not require a second allocation the size of the file.
    let mut output = Vec::with_capacity(input.len());
    let mut block = [0u8; 4096];
    let mut cursor = 0usize;
    while cursor < input.len() {
        let take = block.len().min(input.len() - cursor);
        xof.fill(&mut block[..take]);
        for (byte, mask) in input[cursor..cursor + take]
            .iter()
            .zip(block[..take].iter())
        {
            output.push(byte ^ mask);
        }
        block.zeroize();
        cursor += take;
    }
    output
}

/// Original key schedule, retained so that existing version 1 files open.
fn legacy_root_key(password: &[u8], salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let mut state = hyphen_crypto::hash::blake3_hash(&[salt.as_slice(), password].concat());
    for _ in 0..100_000 {
        state = hyphen_crypto::hash::blake3_hash(state.as_bytes());
    }
    *state.as_bytes()
}

fn legacy_keystream(key: &[u8; 32], length: usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"Hyphen_wallet_stream");
    let mut xof = hasher.finalize_xof();
    let mut keystream = vec![0u8; length];
    xof.fill(&mut keystream);
    keystream
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const SECRET: &[u8] = b"serialised wallet contents";

    fn fast_salt() -> [u8; SALT_LEN] {
        [7u8; SALT_LEN]
    }

    #[test]
    fn round_trip_recovers_the_plaintext() {
        let container = seal_with(SECRET, PASSWORD, &fast_salt(), MIN_ITERATIONS);
        assert_eq!(open(&container, PASSWORD).unwrap(), SECRET);
    }

    #[test]
    fn wrong_password_is_indistinguishable_from_tampering() {
        let container = seal_with(SECRET, PASSWORD, &fast_salt(), MIN_ITERATIONS);
        assert_eq!(
            open(&container, b"wrong password").unwrap_err(),
            KeystoreError::Authentication
        );

        let mut tampered = container.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            open(&tampered, PASSWORD).unwrap_err(),
            KeystoreError::Authentication
        );
    }

    #[test]
    fn every_header_field_is_authenticated() {
        let baseline = seal_with(SECRET, PASSWORD, &fast_salt(), MIN_ITERATIONS);

        let mut raised_iterations = baseline.clone();
        raised_iterations[MAGIC_LEN..MAGIC_LEN + ITERATIONS_LEN]
            .copy_from_slice(&(MIN_ITERATIONS + 1).to_le_bytes());
        assert_eq!(
            open(&raised_iterations, PASSWORD).unwrap_err(),
            KeystoreError::Authentication
        );

        let mut replayed_salt = baseline.clone();
        replayed_salt[MAGIC_LEN + ITERATIONS_LEN] ^= 0xff;
        assert_eq!(
            open(&replayed_salt, PASSWORD).unwrap_err(),
            KeystoreError::Authentication
        );

        let mut downgraded_work_factor = baseline;
        downgraded_work_factor[MAGIC_LEN..MAGIC_LEN + ITERATIONS_LEN]
            .copy_from_slice(&(MIN_ITERATIONS - 1).to_le_bytes());
        assert_eq!(
            open(&downgraded_work_factor, PASSWORD).unwrap_err(),
            KeystoreError::InvalidIterations(MIN_ITERATIONS - 1)
        );
    }

    #[test]
    fn implausible_work_factors_are_rejected_before_stretching() {
        let container = seal_with(SECRET, PASSWORD, &fast_salt(), MIN_ITERATIONS);
        let mut too_many = container.clone();
        too_many[MAGIC_LEN..MAGIC_LEN + ITERATIONS_LEN]
            .copy_from_slice(&(MAX_ITERATIONS + 1).to_le_bytes());
        assert_eq!(
            open(&too_many, PASSWORD).unwrap_err(),
            KeystoreError::InvalidIterations(MAX_ITERATIONS + 1)
        );
    }

    #[test]
    fn truncated_containers_are_rejected() {
        assert_eq!(
            open(&[], PASSWORD).unwrap_err(),
            KeystoreError::TooShort { length: 0 }
        );
        assert_eq!(
            open(MAGIC, PASSWORD).unwrap_err(),
            KeystoreError::TooShort { length: MAGIC_LEN }
        );
        assert_eq!(
            open(&[0u8; 16], PASSWORD).unwrap_err(),
            KeystoreError::TooShort { length: 16 }
        );
    }

    #[test]
    fn separate_saves_use_independent_randomness() {
        let first = seal(SECRET, PASSWORD);
        let second = seal(SECRET, PASSWORD);
        assert_ne!(first, second, "each save must draw a fresh salt");
        assert_eq!(open(&first, PASSWORD).unwrap(), SECRET);
        assert_eq!(open(&second, PASSWORD).unwrap(), SECRET);
    }

    #[test]
    fn legacy_version_one_containers_still_open() {
        let salt = fast_salt();
        let key = legacy_root_key(PASSWORD, &salt);
        let stream = legacy_keystream(&key, SECRET.len());
        let ciphertext: Vec<u8> = SECRET
            .iter()
            .zip(stream.iter())
            .map(|(byte, mask)| byte ^ mask)
            .collect();
        let mac = blake3::keyed_hash(&key, &ciphertext);

        let mut legacy = Vec::new();
        legacy.extend_from_slice(&salt);
        legacy.extend_from_slice(mac.as_bytes());
        legacy.extend_from_slice(&ciphertext);

        assert_eq!(open(&legacy, PASSWORD).unwrap(), SECRET);
        assert_eq!(
            open(&legacy, b"wrong password").unwrap_err(),
            KeystoreError::Authentication
        );
    }

    #[test]
    fn derived_keys_are_domain_separated() {
        let keys = derive_keys(PASSWORD, &fast_salt(), MIN_ITERATIONS);
        assert_ne!(keys.stream, keys.mac, "stream and mac keys must differ");
        let again = derive_keys(PASSWORD, &fast_salt(), MIN_ITERATIONS);
        assert_eq!(keys.stream, again.stream);
        assert_eq!(keys.mac, again.mac);

        let other_salt = derive_keys(PASSWORD, &[9u8; SALT_LEN], MIN_ITERATIONS);
        assert_ne!(keys.stream, other_salt.stream);
    }

    #[test]
    fn constant_time_comparison_matches_semantics() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn large_plaintext_round_trips_across_stream_block_boundaries() {
        let plaintext: Vec<u8> = (0..(4096 * 3 + 17))
            .map(|index| (index % 251) as u8)
            .collect();
        let container = seal_with(&plaintext, PASSWORD, &fast_salt(), MIN_ITERATIONS);
        assert_eq!(open(&container, PASSWORD).unwrap(), plaintext);
    }
}
