//! Verifiable mathematical search: Cunningham chains of the first kind.
//!
//! The consensus workload is a search for witnesses to a number-theoretic
//! predicate that is cheap to verify and expensive to find:
//!
//! ```text
//! witness n  <=>  n, 2n+1, 4n+3, ... (length L) are all prime and all < 2^64
//! ```
//!
//! Verification is `L` deterministic primality tests: a verifier pays
//! microseconds where a solver pays seconds. Every accepted witness is real,
//! independently checkable number-theoretic data, so the chain's witness set
//! is a publishable dataset instead of a burned digest.
//!
//! Determinism is not assumed, it is proven: [`is_prime_u64`] uses Miller-Rabin
//! with the seven-base set that Jaeschke, Sorenson and Webster proved correct
//! for every `n < 2^64`, so there is no probabilistic error bound in the
//! consensus path and no big-integer dependency.
//!
//! # Why witnesses are single-use
//!
//! Any scheme that binds a witness to a header with a derived filter or residue
//! class is unsound. A solver who builds a pool of `m / p` chains can satisfy
//! every future header: the filter is evaluated independently per header, the
//! pool persists, and the marginal cost of each additional block is a handful
//! of hashes. Residue binding of width `b` fails the same way, because covering
//! every class costs exactly one block's worth of work.
//!
//! Single-use witnesses close the loop: a precomputed pool can be spent once,
//! so total work is conserved and precomputation degenerates into mining in
//! advance. Uniqueness is the caller's job ([`search`] takes an `is_claimed`
//! predicate), because it is a consensus-state question: the block builder and
//! the validator must agree on the set of witnesses already recorded on chain.

use alloc::vec::Vec;
use core::fmt;

use hyphen_crypto::Hash256;

use crate::POUW_PROTOCOL_VERSION;

/// Longest chain the protocol accepts. Each link multiplies the search cost by
/// roughly `ln(n) / 2`, so length is the coarse difficulty axis and the number
/// of required witnesses is the fine one.
pub const MAX_CHAIN_LENGTH: u32 = 6;

/// Smallest allowed chain length. Length 1 would be plain primality search.
pub const MIN_CHAIN_LENGTH: u32 = 2;

/// Largest witness the deterministic primality proof covers.
pub const MAX_WITNESS: u64 = u64::MAX;

/// Primes below this bound drive the cheap sieve that rejects most candidates
/// before any Miller-Rabin round runs.
///
/// The CUDA/HIP accelerator implements exactly this predicate, so the value is
/// part of the cross-language test contract and is exported.
pub const SMALL_PRIME_SIEVE_LIMIT: usize = 4096;
const SIEVE_LIMIT: usize = SMALL_PRIME_SIEVE_LIMIT;

/// Miller-Rabin bases proven sufficient for every `n < 2^64`.
const MR_BASES: [u64; 7] = [2, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022];

/// Domain prefix of the parent-relative witness commitment.
const COMMITMENT_DOMAIN: &[u8] = b"Hyphen/PoW/witness-commitment/v1";

const SIEVE_CAPACITY: usize = 600;

const fn build_sieve() -> ([u64; SIEVE_CAPACITY], usize) {
    let mut composite = [false; SIEVE_LIMIT];
    let mut primes = [0u64; SIEVE_CAPACITY];
    let mut count = 0usize;
    let mut candidate = 2usize;
    while candidate < SIEVE_LIMIT {
        if !composite[candidate] {
            primes[count] = candidate as u64;
            count += 1;
            let mut multiple = candidate * candidate;
            while multiple < SIEVE_LIMIT {
                composite[multiple] = true;
                multiple += candidate;
            }
        }
        candidate += 1;
    }
    (primes, count)
}

const SIEVE_TABLE: ([u64; SIEVE_CAPACITY], usize) = build_sieve();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmsError {
    ChainLengthOutOfRange(u32),
    InvalidWitness(u64),
    WitnessAlreadyClaimed(u64),
    WitnessesNotAscending,
    WitnessCountOutOfRange(u64),
}

impl fmt::Display for VmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChainLengthOutOfRange(length) => write!(
                f,
                "chain length {length} is outside {MIN_CHAIN_LENGTH}..={MAX_CHAIN_LENGTH}"
            ),
            Self::InvalidWitness(witness) => {
                write!(f, "witness {witness} is not a valid chain origin")
            }
            Self::WitnessAlreadyClaimed(witness) => {
                write!(f, "witness {witness} was already claimed")
            }
            Self::WitnessesNotAscending => {
                f.write_str("witnesses must be supplied in strictly ascending order")
            }
            Self::WitnessCountOutOfRange(count) => write!(
                f,
                "witness count {count} is outside 1..={MAX_WITNESSES_PER_BLOCK}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VmsError {}

/// Upper bound on witnesses per block. The validator refuses larger claims so
/// that a block can never buy unbounded verification work.
pub const MAX_WITNESSES_PER_BLOCK: u64 = 4096;

/// Deterministic primality for every `u64`.
pub fn is_prime_u64(candidate: u64) -> bool {
    if candidate < 2 {
        return false;
    }
    for small in SIEVE_TABLE.0[..SIEVE_TABLE.1].iter().copied() {
        if candidate == small {
            return true;
        }
        if candidate.is_multiple_of(small) {
            return false;
        }
    }
    is_prime_miller_rabin(candidate)
}

/// Miller-Rabin only. Callers must already have excluded small factors.
#[inline]
fn is_prime_miller_rabin(candidate: u64) -> bool {
    // n - 1 = d * 2^s with d odd.
    let d = candidate - 1;
    let s = d.trailing_zeros();
    let odd_part = d >> s;

    'bases: for base in MR_BASES {
        let base = base % candidate;
        if base == 0 {
            continue;
        }
        let mut x = mod_pow(base, odd_part, candidate);
        if x == 1 || x == d {
            continue;
        }
        for _ in 1..s {
            x = mul_mod(x, x, candidate);
            if x == d {
                continue 'bases;
            }
        }
        return false;
    }
    true
}

fn mul_mod(left: u64, right: u64, modulus: u64) -> u64 {
    ((left as u128 * right as u128) % modulus as u128) as u64
}

fn mod_pow(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base, modulus);
        }
        base = mul_mod(base, base, modulus);
        exponent >>= 1;
    }
    result
}

/// The `index`-th element of the chain rooted at `n`: `2^index * (n + 1) - 1`.
pub fn chain_element(n: u64, index: u32) -> Option<u64> {
    if index >= 64 {
        return None;
    }
    let scaled = (n.checked_add(1)? as u128) << index;
    u64::try_from(scaled.checked_sub(1)?).ok()
}

/// True when every element of the chain is prime and fits in `u64`.
pub fn chain_is_valid(n: u64, length: u32) -> bool {
    passes_small_prime_sieve(n, length) && chain_is_valid_after_sieve(n, length)
}

/// Chain validation without the small-prime pass.
///
/// Only call this after [`passes_small_prime_sieve`] has returned `true` for
/// the same `(n, length)` pair. The accelerator path uses it to avoid running
/// the same division wheel twice.
pub fn chain_is_valid_after_sieve(n: u64, length: u32) -> bool {
    if !(MIN_CHAIN_LENGTH..=MAX_CHAIN_LENGTH).contains(&length) || n < 3 || n.is_multiple_of(2) {
        return false;
    }
    for index in 0..length {
        match chain_element(n, index) {
            Some(element) if is_prime_miller_rabin(element) => {}
            _ => return false,
        }
    }
    true
}

/// Validates a witness list exactly as a verifier would: every entry must be a
/// valid chain origin, entries must ascend, and none may repeat.
pub fn verify_witnesses(
    witnesses: &[u64],
    length: u32,
    expected_count: u64,
) -> Result<(), VmsError> {
    if !(MIN_CHAIN_LENGTH..=MAX_CHAIN_LENGTH).contains(&length) {
        return Err(VmsError::ChainLengthOutOfRange(length));
    }
    if !(1..=MAX_WITNESSES_PER_BLOCK).contains(&expected_count) {
        return Err(VmsError::WitnessCountOutOfRange(expected_count));
    }
    if witnesses.len() as u64 != expected_count {
        return Err(VmsError::WitnessCountOutOfRange(witnesses.len() as u64));
    }
    let mut previous: Option<u64> = None;
    for witness in witnesses {
        if !chain_is_valid(*witness, length) {
            return Err(VmsError::InvalidWitness(*witness));
        }
        if let Some(previous) = previous {
            if *witness <= previous {
                return Err(VmsError::WitnessesNotAscending);
            }
        }
        previous = Some(*witness);
    }
    Ok(())
}

/// Search workload description. The caller owns the nonce space partitioning
/// and the uniqueness policy, so parallel workers need no coordination and the
/// routine stays independent of consensus state.
pub struct SearchParams<'a> {
    pub length: u32,
    /// First candidate in this worker's residue class.
    pub offset: u64,
    /// Distance between candidates. Use `stride = workers` and distinct odd
    /// offsets to partition the space exactly.
    pub stride: u64,
    /// Witnesses still required.
    pub count: u64,
    /// Candidate budget for this call.
    pub max_candidates: u64,
    /// Rejects witnesses that are already recorded on chain.
    pub is_claimed: &'a dyn Fn(u64) -> bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchOutcome {
    pub witnesses: Vec<u64>,
    pub candidates_tested: u64,
    pub chains_found: u64,
}

/// Scans `offset + k * stride` for unclaimed witnesses.
///
/// Candidates are pre-filtered with the small-prime sieve: a chain of length `L`
/// is impossible as soon as any element is divisible by a prime below
/// `SIEVE_LIMIT`, which discards the overwhelming majority of candidates for
/// the price of a `u64` remainder each.
pub fn search(params: &SearchParams<'_>) -> Result<SearchOutcome, VmsError> {
    if !(MIN_CHAIN_LENGTH..=MAX_CHAIN_LENGTH).contains(&params.length) {
        return Err(VmsError::ChainLengthOutOfRange(params.length));
    }
    if !(1..=MAX_WITNESSES_PER_BLOCK).contains(&params.count) {
        return Err(VmsError::WitnessCountOutOfRange(params.count));
    }

    let mut witnesses = Vec::with_capacity(params.count as usize);
    let mut candidates_tested = 0u64;
    let mut chains_found = 0u64;
    let mut candidate = params.offset;
    let mut remaining = params.max_candidates;

    while remaining > 0 {
        candidates_tested += 1;
        remaining -= 1;

        if !passes_small_prime_sieve(candidate, params.length) {
            candidate = candidate.wrapping_add(params.stride);
            continue;
        }
        if chain_is_valid_after_sieve(candidate, params.length) {
            chains_found += 1;
            if !(params.is_claimed)(candidate) {
                witnesses.push(candidate);
                if witnesses.len() as u64 == params.count {
                    break;
                }
            }
        }
        candidate = candidate.wrapping_add(params.stride);
    }

    Ok(SearchOutcome {
        witnesses,
        candidates_tested,
        chains_found,
    })
}

/// Small-prime sieve shared by the CPU search and the device accelerators.
///
/// Returns `true` when no prime below [`SMALL_PRIME_SIEVE_LIMIT`] divides any
/// chain element. An exact small prime is not a rejection: it is prime and may
/// be a valid chain element.
pub fn passes_small_prime_sieve(candidate: u64, length: u32) -> bool {
    if candidate < 3 || candidate.is_multiple_of(2) {
        return false;
    }
    for small in SIEVE_TABLE.0[..SIEVE_TABLE.1].iter().copied() {
        if candidate == small {
            continue;
        }
        if candidate.is_multiple_of(small) {
            return false;
        }
    }

    for index in 1..length {
        match chain_element(candidate, index) {
            Some(element) => {
                for small in SIEVE_TABLE.0[..SIEVE_TABLE.1].iter().copied() {
                    if element == small {
                        break;
                    }
                    if element.is_multiple_of(small) {
                        return false;
                    }
                }
            }
            None => return false,
        }
    }
    true
}

/// Chained commitment to a block's witness list.
///
/// `pow_commitment(n) = BLAKE3(domain ‖ pow_commitment(parent) ‖ n ‖ witnesses)`
///
/// The commitment is parent-relative on purpose. A set root would depend on the
/// whole claimed set, so a miner building on a non-canonical branch would need
/// that branch's set state to produce a valid commitment — an unmaintainable
/// coupling. A chained commitment needs only the parent header, while witness
/// single-use is still enforced by the node's claimed set.
pub fn witness_commitment(parent_commitment: &Hash256, height: u64, witnesses: &[u64]) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(&POUW_PROTOCOL_VERSION.to_le_bytes());
    hasher.update(&height.to_le_bytes());
    hasher.update(parent_commitment.as_bytes());
    hasher.update(&(witnesses.len() as u64).to_le_bytes());
    for witness in witnesses {
        hasher.update(&witness.to_le_bytes());
    }
    Hash256::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primality_matches_known_small_primes_and_composites() {
        let primes = [
            2u64,
            3,
            5,
            7,
            11,
            13,
            97,
            541,
            7919,
            104_729,
            1_299_709,
            2_147_483_647,
        ];
        for prime in primes {
            assert!(is_prime_u64(prime), "{prime} is prime");
        }
        let composites = [
            0u64,
            1,
            4,
            9,
            15,
            21,
            100,
            7918,
            1_299_711,
            2_147_483_649,
            4_294_967_297,
        ];
        for composite in composites {
            assert!(!is_prime_u64(composite), "{composite} is composite");
        }
    }

    #[test]
    fn carmichael_numbers_do_not_fool_the_test() {
        for carmichael in [
            561u64, 1105, 1729, 2465, 2821, 6601, 8911, 10_585, 15_841, 29_341, 41_041, 46_657,
            52_633, 62_745, 63_973, 75_361,
        ] {
            assert!(!is_prime_u64(carmichael), "{carmichael} is composite");
        }
    }

    #[test]
    fn primality_holds_at_the_top_of_the_domain() {
        // Largest prime below 2^64 and its neighbours.
        assert!(is_prime_u64(18_446_744_073_709_551_557));
        assert!(!is_prime_u64(u64::MAX));
        assert!(!is_prime_u64(u64::MAX - 1));
        assert!(is_prime_u64((1 << 61) - 1));
    }

    #[test]
    fn chain_elements_follow_the_cunningham_recurrence() {
        assert_eq!(chain_element(2, 0), Some(2));
        assert_eq!(chain_element(2, 1), Some(5));
        assert_eq!(chain_element(2, 2), Some(11));
        assert_eq!(chain_element(2, 3), Some(23));
        assert_eq!(chain_element(2, 4), Some(47));
        assert_eq!(chain_element(2, 5), Some(95));
        // Overflow must surface as None rather than wrapping.
        assert_eq!(chain_element(u64::MAX, 0), None);
        assert_eq!(chain_element(u64::MAX / 2, 1), Some(u64::MAX));
        assert_eq!(chain_element(u64::MAX / 2 + 1, 1), None);
        assert_eq!(chain_element(3, 64), None);
    }

    #[test]
    fn known_cunningham_chains_validate() {
        // 89 -> 179 -> 359 -> 719 -> 1439 -> 2879 is a known length-6 chain.
        assert!(chain_is_valid(89, 6));
        assert!(chain_is_valid(89, 2));
        assert!(!chain_is_valid(89, 7));
        assert!(!chain_is_valid(2, 5));
        assert!(!chain_is_valid(4, 2));
        assert!(!chain_is_valid(9, 2));
        assert!(!chain_is_valid(1, 2));
        assert!(!chain_is_valid(0, 2));
    }

    #[test]
    fn chain_length_bounds_are_enforced() {
        assert!(!chain_is_valid(2, 1));
        assert!(!chain_is_valid(2, MAX_CHAIN_LENGTH + 1));
        assert!(matches!(
            verify_witnesses(&[2], 1, 1),
            Err(VmsError::ChainLengthOutOfRange(1))
        ));
    }

    #[test]
    fn witness_lists_must_ascend_and_match_the_count() {
        let ascending = [3u64, 5, 11];
        assert!(verify_witnesses(&ascending, 2, 3).is_ok());

        assert_eq!(
            verify_witnesses(&[5, 3], 2, 2),
            Err(VmsError::WitnessesNotAscending)
        );
        assert_eq!(
            verify_witnesses(&[3, 3], 2, 2),
            Err(VmsError::WitnessesNotAscending)
        );
        assert!(matches!(
            verify_witnesses(&[3], 2, 2),
            Err(VmsError::WitnessCountOutOfRange(1))
        ));
        assert_eq!(
            verify_witnesses(&[9], 2, 1),
            Err(VmsError::InvalidWitness(9))
        );
        assert_eq!(
            verify_witnesses(&[2], 2, 1),
            Err(VmsError::InvalidWitness(2))
        );
    }

    #[test]
    fn search_finds_valid_unclaimed_witnesses() {
        let claimed_never = |_: u64| false;
        let params = SearchParams {
            length: 3,
            offset: 3,
            stride: 2,
            count: 4,
            max_candidates: 2_000_000,
            is_claimed: &claimed_never,
        };
        let outcome = search(&params).expect("valid search parameters");
        assert_eq!(outcome.witnesses.len(), 4, "outcome: {outcome:?}");
        assert!(outcome.candidates_tested > 0);
        assert!(outcome.chains_found >= 4);
        for witness in &outcome.witnesses {
            assert!(chain_is_valid(*witness, 3));
        }
        assert!(verify_witnesses(&outcome.witnesses, 3, 4).is_ok());
    }

    #[test]
    fn search_honours_the_claimed_predicate() {
        let first_round = |_: u64| false;
        let baseline = search(&SearchParams {
            length: 3,
            offset: 3,
            stride: 2,
            count: 2,
            max_candidates: 1_000_000,
            is_claimed: &first_round,
        })
        .unwrap();
        let claimed = baseline.witnesses[0];
        let skip_first = move |candidate: u64| candidate == claimed;

        let second_round = search(&SearchParams {
            length: 3,
            offset: 3,
            stride: 2,
            count: 2,
            max_candidates: 1_000_000,
            is_claimed: &skip_first,
        })
        .unwrap();
        assert!(!second_round.witnesses.contains(&claimed));
        assert!(!second_round.witnesses.is_empty());
    }

    #[test]
    fn search_respects_the_candidate_budget() {
        let claimed_never = |_: u64| false;
        let outcome = search(&SearchParams {
            length: 6,
            offset: 3,
            stride: 2,
            count: 4,
            max_candidates: 64,
            is_claimed: &claimed_never,
        })
        .unwrap();
        assert_eq!(outcome.candidates_tested, 64);
        assert!(outcome.witnesses.len() < 4);
    }

    #[test]
    fn search_rejects_out_of_range_parameters() {
        let claimed_never = |_: u64| false;
        assert!(matches!(
            search(&SearchParams {
                length: 1,
                offset: 3,
                stride: 2,
                count: 1,
                max_candidates: 10,
                is_claimed: &claimed_never,
            }),
            Err(VmsError::ChainLengthOutOfRange(1))
        ));
        assert!(matches!(
            search(&SearchParams {
                length: 3,
                offset: 3,
                stride: 2,
                count: 0,
                max_candidates: 10,
                is_claimed: &claimed_never,
            }),
            Err(VmsError::WitnessCountOutOfRange(0))
        ));
    }

    #[test]
    fn stride_partitioning_visits_disjoint_candidates() {
        let claimed_never = |_: u64| false;
        let even_offset = search(&SearchParams {
            length: 2,
            offset: 0,
            stride: 2,
            count: 1,
            max_candidates: 1,
            is_claimed: &claimed_never,
        })
        .unwrap();
        let odd_offset = search(&SearchParams {
            length: 2,
            offset: 1,
            stride: 2,
            count: 1,
            max_candidates: 1,
            is_claimed: &claimed_never,
        })
        .unwrap();
        assert_eq!(
            even_offset.candidates_tested + odd_offset.candidates_tested,
            2
        );

        let wide = search(&SearchParams {
            length: 2,
            offset: 3,
            stride: 4,
            count: 1,
            max_candidates: 500_000,
            is_claimed: &claimed_never,
        })
        .unwrap();
        for witness in wide.witnesses {
            assert_eq!(witness % 4, 3);
        }
    }

    #[test]
    fn witness_commitment_binds_parent_height_and_the_exact_list() {
        let parent = Hash256::from_bytes([4u8; 32]);
        let witnesses = [3u64, 5, 11];
        let baseline = witness_commitment(&parent, 9, &witnesses);

        assert_eq!(baseline, witness_commitment(&parent, 9, &witnesses));
        assert_ne!(baseline, witness_commitment(&parent, 10, &witnesses));
        assert_ne!(
            baseline,
            witness_commitment(&Hash256::from_bytes([5u8; 32]), 9, &witnesses)
        );
        assert_ne!(baseline, witness_commitment(&parent, 9, &[3, 5, 23]));
        assert_ne!(
            baseline,
            witness_commitment(&parent, 9, &[11, 5, 3]),
            "list order is committed, so permutation is rejected"
        );
        assert_ne!(
            baseline,
            witness_commitment(&parent, 9, &[3, 5]),
            "the count is committed, so truncation is rejected"
        );
    }

    #[test]
    fn search_is_deterministic_for_identical_parameters() {
        let claimed_never = |_: u64| false;
        let params = SearchParams {
            length: 3,
            offset: 5,
            stride: 2,
            count: 3,
            max_candidates: 500_000,
            is_claimed: &claimed_never,
        };
        let first = search(&params).unwrap();
        let second = search(&params).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.witnesses.len(), 3);
    }
}
