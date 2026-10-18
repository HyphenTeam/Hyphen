//! Neural block work: the consensus predicate and its difficulty retarget.
//!
//! # The rule
//!
//! A post-genesis block must carry one accepted solution to the epoch's
//! one-way work challenge. The challenge is fully determined by public data:
//!
//! ```text
//! seed        = parent block hash
//! epoch       = this block's height
//! weights     = PRF(seed, epoch)                 // hyphen-neural::work
//! solution    = x in [-1, 1]^input_dim, encoded as the header's witness list
//! accept      <=> score(A_weights(x)) < threshold
//! ```
//!
//! The seed fixes the network, never the answer, so a solution can only be
//! found by running forward passes. Because the seed is the parent hash, no
//! work found for one block is useful for any other, and because the header
//! commits to the threshold, a miner cannot relax it after searching.
//!
//! # Difficulty
//!
//! [`retarget_threshold`] adjusts the acceptance threshold so that the expected
//! number of forward passes per block tracks [`WORK_TARGET_SECS`]. The expected
//! attempts for threshold `t` are `2^64 / t`, so keeping the block rate constant
//! requires `t` to stay proportional to `elapsed / target`. The adjustment is
//! integer-only, floored, and clamped to a factor of four per window so a single
//! timestamp outlier cannot swing the chain.
//!
//! Every rule here is a pure function of public data: no clocks, no floating
//! point, no host-dependent rounding.

use hyphen_core::block::{Block, BlockHeader};
use hyphen_crypto::Hash256;
use hyphen_neural::{MlpSpec, WorkDescriptor};

/// Domain tag of the header commitment.
pub const WORK_COMMITMENT_DOMAIN: &[u8] = b"Hyphen/neural-work-commitment/v1";

/// Domain tag of the per-miner seed derivation.
pub const WORK_SEED_DOMAIN: &[u8] = b"Hyphen/neural-work-seed/v1";

/// Number of intervals one retarget covers. The window is `WORK_RETARGET_WINDOW`
/// intervals, which needs `WORK_RETARGET_WINDOW + 1` headers.
pub const WORK_RETARGET_WINDOW: u64 = 16;

/// Target seconds per block.
pub const WORK_TARGET_SECS: u64 = 30;

/// Target milliseconds per block.
///
/// Header timestamps are milliseconds, so every retarget comparison has to
/// happen in milliseconds. Comparing a millisecond `elapsed` against a
/// second-denominated expectation reads a 3-second window as six times the
/// target and drives the threshold to its ceiling — which is exactly how an
/// early build of this profile ended up accepting ~1 candidate in 1 and mining
/// blocks at 5 Hz.
pub const WORK_TARGET_MS: u64 = WORK_TARGET_SECS * 1_000;

/// Largest factor the threshold may move per retarget.
pub const WORK_MAX_ADJUST: u64 = 4;

/// Highest threshold any block may declare.
///
/// `2^62` means one accepted candidate in four trials: still work, never free.
/// Without the cap a chain whose hashrate collapses would walk its threshold to
/// `u64::MAX`, where the acceptance test `score < threshold` passes with
/// probability `1 - 2^-64` and the proof of work stops proving anything.
pub const NEURAL_WORK_MAX_THRESHOLD: u64 = 1 << 62;

/// A ceiling that reached `u64::MAX` would accept every candidate, so the
/// constant itself is checked at compile time rather than in a test.
const _: () = assert!(NEURAL_WORK_MAX_THRESHOLD < u64::MAX);

/// How many parent headers the median-time rule looks at.
pub const WORK_MEDIAN_WINDOW: usize = 11;

/// Network shape of the compiled-in neural-work profile.
///
/// Re-exported from the challenge crate so the node, the pool and the miner
/// cannot drift apart.
pub const NEURAL_WORK_SPEC: MlpSpec = hyphen_neural::PROFILE_SPEC;

/// Threshold of the first [`WORK_RETARGET_WINDOW`] intervals.
///
/// `2^56` is one accepted candidate in 256 trials — a deliberately soft start,
/// because the operator's hashrate is unknown when the chain is created. It only
/// carries the chain until the first full window exists; from there
/// [`expected_threshold`] walks the threshold toward the configured block time
/// at no more than a factor of [`WORK_MAX_ADJUST`] per window.
pub const NEURAL_WORK_INITIAL_THRESHOLD: u64 = 1 << 56;

/// Parameters of the compiled-in neural-work profile.
pub fn neural_work_params(cfg: &hyphen_core::ChainConfig) -> NeuralWorkParams {
    NeuralWorkParams {
        spec: NEURAL_WORK_SPEC,
        initial_threshold: cfg.neural_work_initial_threshold,
        max_threshold: cfg.neural_work_max_threshold,
    }
}

/// Work parameters of a chain profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeuralWorkParams {
    /// Network shape. Every block of the profile uses the same shape.
    pub spec: MlpSpec,
    /// Threshold used until a full retarget window exists.
    pub initial_threshold: u64,
    /// Ceiling every retarget is clamped to.
    pub max_threshold: u64,
}

impl NeuralWorkParams {
    /// Rejects parameters no block could ever satisfy, or that would let a
    /// block through without meaningful work.
    pub fn validate(&self) -> Result<(), NeuralWorkError> {
        self.spec
            .validate()
            .map_err(|_| NeuralWorkError::InvalidParams)?;
        if self.initial_threshold == 0
            || self.max_threshold == 0
            || self.initial_threshold > self.max_threshold
            || self.max_threshold > NEURAL_WORK_MAX_THRESHOLD
        {
            return Err(NeuralWorkError::InvalidParams);
        }
        Ok(())
    }
}

/// Why a block fails the neural work rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeuralWorkError {
    /// Profile parameters are unusable.
    InvalidParams,
    /// The header does not carry the threshold the chain requires.
    WrongThreshold { expected: u64, got: u64 },
    /// The witness list is not exactly one solution vector.
    WrongSolutionWidth { expected: usize, got: usize },
    /// The solution is not inside `[-ONE, ONE]` in every component.
    SolutionOutOfRange,
    /// The committed work does not match the header's solution and threshold.
    CommitmentMismatch,
    /// The solution does not score below the threshold.
    InsufficientWork,
    /// The timestamp does not advance past the median of recent history.
    TimestampNotAfterMedian { median: u64, got: u64 },
}

/// Seed the block's network is derived from.
///
/// It mixes in the miner's public key, not just the parent hash. Without that,
/// a solution found by one miner is a valid solution for *any* miner's block at
/// the same height — a bystander could copy it from the mempool and claim the
/// block. Binding the seed to the miner makes every solution worthless to
/// everyone else, while staying fully public and reproducible.
pub fn work_seed(parent_hash: &Hash256, height: u64, miner_pubkey: &[u8; 32]) -> Hash256 {
    hyphen_core::neural_work_seed(parent_hash, height, miner_pubkey)
}

/// Commitment the header stores in `pow_commitment`.
///
/// It binds the parent hash, the height, the threshold, the miner and the exact
/// solution, so none of them can change after a solution is found.
pub fn work_commitment(
    parent_hash: &Hash256,
    height: u64,
    threshold: u64,
    miner_pubkey: &[u8; 32],
    solution: &[u64],
) -> Hash256 {
    hyphen_core::neural_work_commitment(parent_hash, height, threshold, miner_pubkey, solution)
}

/// Threshold for the next block.
///
/// `elapsed` is the wall time in **milliseconds** covered by
/// [`WORK_RETARGET_WINDOW`] intervals and `expected` is
/// `WORK_RETARGET_WINDOW * WORK_TARGET_MS`. Faster blocks mean the threshold
/// must shrink; the ratio is clamped to `1/WORK_MAX_ADJUST .. WORK_MAX_ADJUST`
/// and the result is floored at 1 and capped at [`NEURAL_WORK_MAX_THRESHOLD`],
/// so the function is monotone and cannot overflow.
pub fn retarget_threshold(current: u64, elapsed: u64) -> u64 {
    let expected = WORK_RETARGET_WINDOW.saturating_mul(WORK_TARGET_MS);
    let floor = expected / WORK_MAX_ADJUST;
    let ceiling = expected.saturating_mul(WORK_MAX_ADJUST);
    let clamped = elapsed.clamp(floor, ceiling);

    let scaled = (current as u128) * (clamped as u128) / (expected as u128);
    let bounded = scaled.min(NEURAL_WORK_MAX_THRESHOLD as u128) as u64;
    bounded.max(1)
}

/// Median timestamp of the last [`WORK_MEDIAN_WINDOW`] parent headers.
///
/// `None` when there is no history, i.e. for the first post-genesis block.
pub fn median_time_past(history: &[BlockHeader]) -> Option<u64> {
    if history.is_empty() {
        return None;
    }
    let start = history.len().saturating_sub(WORK_MEDIAN_WINDOW);
    let mut times: Vec<u64> = history[start..].iter().map(|h| h.timestamp).collect();
    times.sort_unstable();
    Some(times[times.len() / 2])
}

/// Rejects a block whose timestamp does not advance past the median.
///
/// This is the deterministic half of the timestamp rule: it stops a miner from
/// dragging the retarget window backwards to make the next threshold easier.
/// The other half — refusing timestamps far in the future — compares against a
/// clock, so the node applies it with its NTP-adjusted time before calling this
/// function.
pub fn validate_timestamp(timestamp: u64, history: &[BlockHeader]) -> Result<(), NeuralWorkError> {
    match median_time_past(history) {
        Some(median) if timestamp <= median => Err(NeuralWorkError::TimestampNotAfterMedian {
            median,
            got: timestamp,
        }),
        _ => Ok(()),
    }
}

/// Threshold the block at `history.len()` must declare.
///
/// `history` holds headers from oldest to newest and **ends at the parent**, so
/// `history.len()` is the height of the block being validated. Fewer than
/// `WORK_RETARGET_WINDOW + 1` headers means the window is not full yet and the
/// profile's initial threshold applies, which keeps the first blocks after
/// genesis deterministic.
pub fn expected_threshold(history: &[BlockHeader], params: &NeuralWorkParams) -> u64 {
    let window = WORK_RETARGET_WINDOW as usize;
    if history.len() < window + 1 {
        return params.initial_threshold;
    }
    let newest = history[history.len() - 1].timestamp;
    let oldest = history[history.len() - 1 - window].timestamp;
    let elapsed = newest.saturating_sub(oldest);
    let current = history[history.len() - 1].difficulty;
    retarget_threshold(current, elapsed).min(params.max_threshold)
}

/// Fork-choice weight contributed by one block with acceptance threshold
/// `threshold`.
///
/// The neural profile stores a *threshold* in the header's `difficulty` field,
/// and a smaller threshold is harder. Fork choice must therefore rank blocks by
/// the expected number of attempts `2^64 / threshold`. Summing the raw field, as
/// the witness-count profiles do, would rank the *easiest* branch as the
/// heaviest and hand the chain to whoever refuses to work.
///
/// A zero threshold is unreachable — [`NeuralWorkParams::validate`] and the
/// descriptor reject it — and saturates to the maximum weight so a malformed
/// value can never be read as "no work".
pub fn block_weight(threshold: u64) -> u128 {
    if threshold == 0 {
        return u128::MAX;
    }
    u128::from(u64::MAX) / u128::from(threshold)
}

/// Encodes one solution component. `as u64` is a bit-preserving two's
/// complement reinterpretation, and the inverse is `as i64`.
pub fn encode_component(value: i64) -> u64 {
    value as u64
}

/// Decodes one solution component.
pub fn decode_component(value: u64) -> i64 {
    value as i64
}

/// Verifies the neural work carried by `block`.
///
/// `history` ends at the parent, exactly as for [`expected_threshold`].
pub fn verify(
    block: &Block,
    parent_hash: &Hash256,
    history: &[BlockHeader],
    params: &NeuralWorkParams,
) -> Result<(), NeuralWorkError> {
    params.validate()?;
    validate_timestamp(block.header.timestamp, history)?;
    let expected = expected_threshold(history, params);
    let header = &block.header;
    if header.difficulty != expected {
        return Err(NeuralWorkError::WrongThreshold {
            expected,
            got: header.difficulty,
        });
    }
    let input_dim = params.spec.input_dim as usize;
    if block.pow_witnesses.len() != input_dim {
        return Err(NeuralWorkError::WrongSolutionWidth {
            expected: input_dim,
            got: block.pow_witnesses.len(),
        });
    }
    let commitment = work_commitment(
        parent_hash,
        header.height,
        header.difficulty,
        &header.miner_pubkey,
        &block.pow_witnesses,
    );
    if commitment != header.pow_commitment {
        return Err(NeuralWorkError::CommitmentMismatch);
    }

    let seed = work_seed(parent_hash, header.height, &header.miner_pubkey);
    let descriptor = WorkDescriptor {
        epoch: header.height,
        spec: params.spec,
        threshold: header.difficulty,
        chain_seed: *seed.as_bytes(),
    };
    let mut solution = Vec::with_capacity(input_dim);
    for value in &block.pow_witnesses {
        let decoded = decode_component(*value);
        if !(-hyphen_neural::fixed::ONE..=hyphen_neural::fixed::ONE).contains(&decoded) {
            return Err(NeuralWorkError::SolutionOutOfRange);
        }
        solution.push(decoded);
    }

    let mut weights = vec![0_i64; params.spec.weight_count()];
    descriptor
        .derive_weights(&mut weights)
        .map_err(|_| NeuralWorkError::InvalidParams)?;
    let mut hidden = vec![0_i64; params.spec.hidden_dim as usize];
    let mut output = vec![0_i64; params.spec.output_dim as usize];
    let accepted = descriptor
        .verify(&weights, &solution, &mut hidden, &mut output)
        .map_err(|_| NeuralWorkError::InvalidParams)?;
    if !accepted {
        return Err(NeuralWorkError::InsufficientWork);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_neural::search_work;

    const SPEC: MlpSpec = MlpSpec {
        input_dim: 8,
        hidden_dim: 12,
        output_dim: 8,
    };

    fn params() -> NeuralWorkParams {
        NeuralWorkParams {
            spec: SPEC,
            initial_threshold: 1 << 56,
            max_threshold: 1 << 62,
        }
    }

    fn header(height: u64, timestamp: u64, difficulty: u64) -> BlockHeader {
        BlockHeader {
            version: hyphen_core::FROZEN_BLOCK_VERSION,
            height,
            timestamp,
            prev_hash: Hash256::ZERO,
            tx_root: Hash256::ZERO,
            commitment_root: Hash256::ZERO,
            nullifier_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipt_root: Hash256::ZERO,
            uncle_root: Hash256::ZERO,
            pow_commitment: Hash256::ZERO,
            epoch_seed: Hash256::ZERO,
            difficulty,
            nonce: 0,
            extra_nonce: [0; 32],
            miner_pubkey: [1; 32],
            total_fee: 0,
            reward: 0,
            view_tag: 0,
            block_size: 0,
        }
    }

    /// Builds a block that satisfies the rule for `parent_hash` and `miner`.
    fn mined_block_for(
        parent_hash: &Hash256,
        height: u64,
        params: &NeuralWorkParams,
        miner: [u8; 32],
    ) -> Block {
        let threshold = params.initial_threshold;
        let seed = work_seed(parent_hash, height, &miner);
        let descriptor = WorkDescriptor {
            epoch: height,
            spec: params.spec,
            threshold,
            chain_seed: *seed.as_bytes(),
        };
        let mut weights = vec![0_i64; params.spec.weight_count()];
        descriptor.derive_weights(&mut weights).unwrap();
        let mut solution = vec![0_i64; params.spec.input_dim as usize];
        let mut hidden = vec![0_i64; params.spec.hidden_dim as usize];
        let mut output = vec![0_i64; params.spec.output_dim as usize];
        let mut scratch = vec![0_i64; params.spec.input_dim as usize];
        let outcome = search_work(
            &descriptor,
            &weights,
            0,
            1,
            65_536,
            &mut solution,
            &mut hidden,
            &mut output,
            &mut scratch,
        )
        .unwrap();
        assert!(outcome.found, "the test threshold must be reachable");

        let witnesses: Vec<u64> = solution.iter().copied().map(encode_component).collect();
        let mut header = header(height, 1_000 + height * 30, threshold);
        header.prev_hash = *parent_hash;
        header.miner_pubkey = miner;
        header.difficulty = threshold;
        header.pow_commitment = work_commitment(parent_hash, height, threshold, &miner, &witnesses);
        Block {
            header,
            pow_witnesses: witnesses,
            transactions: Vec::new(),
            uncle_headers: Vec::new(),
            block_authorization: Vec::new(),
        }
    }

    fn mined_block(parent_hash: &Hash256, height: u64, params: &NeuralWorkParams) -> Block {
        mined_block_for(parent_hash, height, params, [1; 32])
    }

    fn parent() -> Hash256 {
        Hash256::from_bytes([7; 32])
    }

    #[test]
    fn a_mined_block_verifies() {
        let params = params();
        let block = mined_block(&parent(), 1, &params);
        assert_eq!(verify(&block, &parent(), &[], &params), Ok(()));
    }

    #[test]
    fn the_threshold_is_part_of_the_commitment() {
        let params = params();
        let mut block = mined_block(&parent(), 1, &params);
        block.header.difficulty = params.initial_threshold / 2;
        assert_eq!(
            verify(&block, &parent(), &[], &params),
            Err(NeuralWorkError::WrongThreshold {
                expected: params.initial_threshold,
                got: params.initial_threshold / 2,
            })
        );
    }

    #[test]
    fn a_tampered_solution_is_rejected() {
        let params = params();
        let mut block = mined_block(&parent(), 1, &params);
        block.pow_witnesses[0] = encode_component(0);
        assert_eq!(
            verify(&block, &parent(), &[], &params),
            Err(NeuralWorkError::CommitmentMismatch)
        );
    }

    /// The central anti-theft property: a solution is bound to one miner key, so
    /// copying it out of the mempool into another miner's block is worthless.
    #[test]
    fn a_solution_mined_by_another_miner_is_rejected() {
        let params = params();
        let mut block = mined_block_for(&parent(), 1, &params, [2; 32]);
        block.header.miner_pubkey = [3; 32];
        block.header.pow_commitment = work_commitment(
            &parent(),
            1,
            block.header.difficulty,
            &block.header.miner_pubkey,
            &block.pow_witnesses,
        );
        assert_eq!(
            verify(&block, &parent(), &[], &params),
            Err(NeuralWorkError::InsufficientWork)
        );
    }

    #[test]
    fn the_seed_depends_on_the_miner() {
        assert_ne!(
            work_seed(&parent(), 1, &[1; 32]),
            work_seed(&parent(), 1, &[2; 32])
        );
    }

    #[test]
    fn a_solution_for_another_parent_is_rejected() {
        let params = params();
        let block = mined_block(&Hash256::from_bytes([9; 32]), 1, &params);
        assert_eq!(
            verify(&block, &parent(), &[], &params),
            Err(NeuralWorkError::CommitmentMismatch)
        );
    }

    #[test]
    fn an_out_of_range_component_is_rejected() {
        let params = params();
        let mut block = mined_block(&parent(), 1, &params);
        block.pow_witnesses[0] = encode_component(hyphen_neural::fixed::ONE + 1);
        block.header.pow_commitment = work_commitment(
            &parent(),
            1,
            block.header.difficulty,
            &block.header.miner_pubkey,
            &block.pow_witnesses,
        );
        assert_eq!(
            verify(&block, &parent(), &[], &params),
            Err(NeuralWorkError::SolutionOutOfRange)
        );
    }

    #[test]
    fn a_short_solution_is_rejected() {
        let params = params();
        let mut block = mined_block(&parent(), 1, &params);
        block.pow_witnesses.pop();
        assert!(matches!(
            verify(&block, &parent(), &[], &params),
            Err(NeuralWorkError::WrongSolutionWidth { .. })
        ));
    }

    /// The whole reason `block_weight` exists: the raw field is inverted in the
    /// neural profile, so ranking branches by it hands the chain to the easiest
    /// one.
    #[test]
    fn a_smaller_threshold_carries_more_weight() {
        let hard = 1_000_000_u64;
        let easy = 4_000_000_u64;
        assert!(block_weight(hard) > block_weight(easy));
        assert_eq!(block_weight(easy), block_weight(hard) / 4);
    }

    #[test]
    fn block_weight_stays_positive_at_the_extremes() {
        assert_eq!(block_weight(u64::MAX), 1);
        assert_eq!(block_weight(1), u128::from(u64::MAX));
        assert_eq!(block_weight(0), u128::MAX);
    }

    #[test]
    fn retarget_is_identity_at_the_target_rate() {
        let current = 1_000_000_000_u64;
        assert_eq!(
            retarget_threshold(current, WORK_RETARGET_WINDOW * WORK_TARGET_MS),
            current
        );
    }

    #[test]
    fn retarget_hardens_when_blocks_are_fast() {
        let current = 1_000_000_u64;
        let expected = WORK_RETARGET_WINDOW * WORK_TARGET_MS;
        assert_eq!(retarget_threshold(current, expected / 2), current / 2);
        assert_eq!(retarget_threshold(current, expected / 4), current / 4);
    }

    /// Regression: header timestamps are milliseconds, and an early build
    /// compared them against a second-denominated expectation. A window of
    /// 16 × 200 ms blocks then looked "slow" and *eased* the threshold until it
    /// hit the ceiling, which is how the devnet mined at 5 blocks per second.
    #[test]
    fn a_window_of_sub_second_blocks_hardens_instead_of_easing() {
        let current = 1 << 56;
        let sixteen_blocks_at_200ms = 16 * 200;
        assert!(sixteen_blocks_at_200ms < WORK_RETARGET_WINDOW * WORK_TARGET_MS);
        assert_eq!(
            retarget_threshold(current, sixteen_blocks_at_200ms),
            current / WORK_MAX_ADJUST
        );
    }

    #[test]
    fn retarget_eases_when_blocks_are_slow() {
        let current = 1_000_000_u64;
        let expected = WORK_RETARGET_WINDOW * WORK_TARGET_MS;
        assert_eq!(retarget_threshold(current, expected * 2), current * 2);
        assert_eq!(retarget_threshold(current, expected * 4), current * 4);
    }

    #[test]
    fn retarget_clamps_a_single_outlier() {
        let current = 1_000_000_u64;
        assert_eq!(retarget_threshold(current, 1), current / WORK_MAX_ADJUST);
        assert_eq!(
            retarget_threshold(current, u64::MAX),
            current.saturating_mul(WORK_MAX_ADJUST)
        );
    }

    #[test]
    fn retarget_never_returns_zero_and_is_capped() {
        assert_eq!(retarget_threshold(1, 1), 1);
        assert_eq!(
            retarget_threshold(u64::MAX, u64::MAX),
            NEURAL_WORK_MAX_THRESHOLD
        );
        assert!(retarget_threshold(3, 1) >= 1);
    }

    /// The ceiling is the difference between "hard to find" and "free": at
    /// `u64::MAX` a single candidate passes with overwhelming probability.
    #[test]
    fn the_threshold_ceiling_keeps_a_candidate_from_being_free() {
        // `2^64 / 2^62` is 4 attempts in exact arithmetic; `block_weight` uses
        // `u64::MAX` as the numerator, so the integer result is 3.
        assert!(block_weight(NEURAL_WORK_MAX_THRESHOLD) >= 3);
        let params = params();
        for _ in 0..8 {
            let eased = params.max_threshold.saturating_mul(WORK_MAX_ADJUST);
            let history: Vec<BlockHeader> = (0..=WORK_RETARGET_WINDOW)
                .map(|height| header(height, height * 10 * WORK_TARGET_MS, eased))
                .collect();
            assert_eq!(expected_threshold(&history, &params), params.max_threshold);
        }
    }

    #[test]
    fn the_profile_rejects_parameters_above_the_ceiling() {
        let mut params = params();
        params.max_threshold = u64::MAX;
        assert_eq!(params.validate(), Err(NeuralWorkError::InvalidParams));
        params.max_threshold = params.initial_threshold - 1;
        assert_eq!(params.validate(), Err(NeuralWorkError::InvalidParams));
    }

    #[test]
    fn a_partial_window_keeps_the_initial_threshold() {
        let params = params();
        let history: Vec<BlockHeader> = (0..WORK_RETARGET_WINDOW)
            .map(|height| header(height, height, params.initial_threshold))
            .collect();
        assert_eq!(
            expected_threshold(&history, &params),
            params.initial_threshold
        );
    }

    #[test]
    fn a_full_fast_window_hardens_the_next_block() {
        let params = params();
        let history: Vec<BlockHeader> = (0..=WORK_RETARGET_WINDOW)
            .map(|height| header(height, 1_000 + height, params.initial_threshold))
            .collect();
        assert_eq!(
            expected_threshold(&history, &params),
            retarget_threshold(params.initial_threshold, WORK_RETARGET_WINDOW)
        );
    }

    /// Retargeting must compound from the parent's threshold, not from the
    /// profile's initial value.
    #[test]
    fn retargeting_compounds_across_windows() {
        let params = params();
        let eased = params.initial_threshold * 2;
        let history: Vec<BlockHeader> = (0..=WORK_RETARGET_WINDOW)
            .map(|height| header(height, height * WORK_TARGET_MS, eased))
            .collect();
        // Exactly on target, so the parent's threshold carries forward.
        assert_eq!(expected_threshold(&history, &params), eased);
    }

    #[test]
    fn the_median_rule_rejects_a_timestamp_that_does_not_advance() {
        let history: Vec<BlockHeader> = (0..=4)
            .map(|height| header(height, 1_000 + height * 10, 1))
            .collect();
        // Median of 1000,1010,1020,1030,1040 is 1020.
        assert_eq!(median_time_past(&history), Some(1_020));
        assert!(validate_timestamp(1_020, &history).is_err());
        assert_eq!(validate_timestamp(1_021, &history), Ok(()));
        assert!(validate_timestamp(1_000, &history).is_err());
    }

    #[test]
    fn the_median_rule_uses_only_the_last_eleven_headers() {
        let mut history: Vec<BlockHeader> = (0..40)
            .map(|height| header(height, 100 + height, 1))
            .collect();
        // A very old header must not influence the median once it is out of the
        // window.
        history[0].timestamp = 0;
        assert_eq!(median_time_past(&history), Some(100 + 34));
    }

    #[test]
    fn the_first_post_genesis_block_has_no_median_constraint() {
        assert_eq!(median_time_past(&[]), None);
        assert_eq!(validate_timestamp(0, &[]), Ok(()));
    }

    #[test]
    fn a_block_that_is_not_newer_than_the_median_is_rejected() {
        let params = params();
        let mut history: Vec<BlockHeader> = (0..=4)
            .map(|height| header(height, 2_000, params.initial_threshold))
            .collect();
        history[0].timestamp = 1_000;
        let mut block = mined_block(&parent(), 5, &params);
        block.header.timestamp = 2_000;
        assert_eq!(
            verify(&block, &parent(), &history, &params),
            Err(NeuralWorkError::TimestampNotAfterMedian {
                median: 2_000,
                got: 2_000,
            })
        );
    }

    #[test]
    fn a_non_monotonic_window_is_treated_as_zero_elapsed() {
        let params = params();
        let mut history: Vec<BlockHeader> = (0..=WORK_RETARGET_WINDOW)
            .map(|height| header(height, 1_000, params.initial_threshold))
            .collect();
        history[0].timestamp = 5_000;
        assert_eq!(
            expected_threshold(&history, &params),
            retarget_threshold(params.initial_threshold, 0)
        );
    }
}
