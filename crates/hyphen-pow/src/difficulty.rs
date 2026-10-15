//! Difficulty control in the work domain.
//!
//! `difficulty` is the expected number of field evaluations a solver performs
//! before it finds a claim that meets the target, and cumulative difficulty is
//! the fork-choice weight. The controller therefore estimates a work magnitude:
//! it scales the previous value by the ratio of target block time to observed
//! solve time.
//!
//! Everything on the consensus path is integer-only by construction. A
//! difficulty value decides which branch wins, so a `libm` result that differs
//! between platforms, compiler flags or library versions would split the chain.
//! The floating-point material at the bottom of this file is an offline
//! ablation harness for research only and is never consulted for consensus.

use hyphen_core::config::{ChainConfig, DifficultyAlgorithm};

const BPS: i128 = 10_000;
/// Observed solve times inside this band count as no measurable change.
const GATE_DEAD_BAND_BPS: i128 = 1_000;
/// Fraction of the raw correction that momentum may add or remove.
const MOMENTUM_WEIGHT_BPS: i128 = 3_000;

/// Primary difficulty entry point.
///
/// Returns the genesis difficulty when the caller supplies fewer than two
/// samples or mismatched slice lengths, so that no consensus call site can
/// panic on malformed history.
pub fn next_difficulty(timestamps: &[u64], difficulties: &[u64], cfg: &ChainConfig) -> u64 {
    if timestamps.len() != difficulties.len() || timestamps.len() < 2 {
        return cfg.genesis_difficulty;
    }
    match cfg.difficulty_algorithm {
        DifficultyAlgorithm::LwmaV1 => next_difficulty_lwma(timestamps, difficulties, cfg),
        DifficultyAlgorithm::MomentumDampedLwmaV2 => controller(
            timestamps,
            difficulties,
            cfg,
            Gate::Enabled,
            MOMENTUM_WEIGHT_BPS,
            Dampener::Enabled,
        ),
    }
}

/// Frozen integer LWMA used by devnet. Behaviour is unchanged since it was
/// pinned: only the meaning of the returned magnitude changed, not its algebra.
pub fn next_difficulty_lwma(timestamps: &[u64], difficulties: &[u64], cfg: &ChainConfig) -> u64 {
    let prev = match difficulties.last() {
        Some(&value) => value,
        None => return cfg.genesis_difficulty,
    };
    bounded(lwma_base(timestamps, difficulties, cfg), prev, cfg)
}

// --- Work estimate ---------------------------------------------------------

/// Integer linear weighted moving average of the observed work rate.
fn lwma_base(timestamps: &[u64], difficulties: &[u64], cfg: &ChainConfig) -> u64 {
    let n = timestamps.len();
    let window = (n - 1) as u128;
    let target_ms = cfg.block_time_ms() as i128;

    let mut weighted_solve_time: i128 = 0;
    let mut weight_sum: i128 = 0;
    let mut difficulty_sum: u128 = 0;

    for i in 1..n {
        let raw = timestamps[i] as i128 - timestamps[i - 1] as i128;
        let solve_time_ms = raw.max(target_ms / 10).min(6 * target_ms);
        let weight = i as i128;
        weighted_solve_time += solve_time_ms * weight;
        weight_sum += weight;
        difficulty_sum += difficulties[i] as u128;
    }

    if weight_sum == 0 || difficulty_sum == 0 {
        return cfg.genesis_difficulty;
    }

    let target_total = target_ms * weight_sum;
    let average = (difficulty_sum / window) as i128;
    let estimate = average * target_total / weighted_solve_time.max(1);
    u64::try_from(estimate).unwrap_or(u64::MAX)
}

/// Solve times in milliseconds, clamped to `[target/10, 6*target]`.
///
/// Clamping bounds what a miner can achieve by lying about block timestamps:
/// even a fully controlled clock can move one sample by at most a factor of 60.
fn solve_times(timestamps: &[u64], target_ms: u64) -> Vec<i128> {
    let target = target_ms.max(1) as i128;
    timestamps
        .windows(2)
        .map(|pair| (pair[1] as i128 - pair[0] as i128).clamp(target / 10, 6 * target))
        .collect()
}

// --- Controller ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Gate {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dampener {
    Enabled,
    Disabled,
}

fn controller(
    timestamps: &[u64],
    difficulties: &[u64],
    cfg: &ChainConfig,
    gate: Gate,
    momentum_weight_bps: i128,
    dampener: Dampener,
) -> u64 {
    let prev = *difficulties
        .last()
        .expect("caller guarantees non-empty history");
    let times = solve_times(timestamps, cfg.block_time_ms());
    let ratio = correction_bps(
        timestamps,
        difficulties,
        cfg,
        &times,
        gate,
        momentum_weight_bps,
    );
    let proposed = scale(prev, ratio);
    let proposed = match dampener {
        Dampener::Enabled => dampen_change(proposed, prev, &times),
        Dampener::Disabled => proposed,
    };
    anti_51_dampening(timestamps, bounded(proposed, prev, cfg), prev, cfg)
}

/// Correction ratio in basis points.
///
/// The gate is the significance filter: while the LWMA estimate sits inside the
/// dead band the controller only applies a bounded micro-correction, because a
/// solve-time series with no measurable drift must not move difficulty.
fn correction_bps(
    timestamps: &[u64],
    difficulties: &[u64],
    cfg: &ChainConfig,
    times: &[i128],
    gate: Gate,
    momentum_weight_bps: i128,
) -> i128 {
    let prev = (*difficulties
        .last()
        .expect("caller guarantees non-empty history"))
    .max(1) as i128;
    let implied = lwma_base(timestamps, difficulties, cfg) as i128 * BPS / prev;

    if gate == Gate::Enabled && (implied - BPS).abs() <= GATE_DEAD_BAND_BPS {
        return implied.clamp(BPS - BPS / 50, BPS + BPS / 50);
    }

    let target_ms = cfg.block_time_ms().max(1) as i128;
    let observed = (times.iter().sum::<i128>() / times.len().max(1) as i128).max(1);
    let base_ratio = target_ms * BPS / observed;
    let factor =
        (BPS + momentum_bps(times) * momentum_weight_bps / BPS).clamp(BPS / 2, 3 * BPS / 2);
    BPS + (base_ratio - BPS) * factor / BPS
}

/// Momentum in basis points: positive while solve times are shrinking, which is
/// the signature of a rising work rate.
fn momentum_bps(times: &[i128]) -> i128 {
    let n = times.len();
    if n < 6 {
        return 0;
    }
    let recent = (n / 3).max(2);
    let fast = times[n - recent..].iter().sum::<i128>() / recent as i128;
    let slow = times.iter().sum::<i128>() / n as i128;
    if slow <= 0 {
        return 0;
    }
    ((slow - fast) * BPS / slow).clamp(-BPS, BPS)
}

/// Attenuates a correction when the solve-time series alternates fast/slow.
///
/// Alternating patterns signal an oscillating work rate (pool hopping or a
/// deliberately pulsing miner) rather than a step change, and a controller that
/// chases them hands the attacker a predictable difficulty schedule.
fn dampen_change(proposed: u64, prev: u64, times: &[i128]) -> u64 {
    let strength = manipulation_strength_bps(times);
    if strength == 0 {
        return proposed;
    }
    let factor_bps = 7_000 - strength * 5_000 / BPS;
    let delta = proposed as i128 - prev as i128;
    let dampened = prev as i128 + delta.saturating_mul(factor_bps) / BPS;
    u64::try_from(dampened.max(1)).unwrap_or(u64::MAX)
}

/// Strength of a significant negative lag-1 autocorrelation, in basis points.
///
/// The textbook estimator is `ac1 = n*S1 / ((n-1)*V)`, significant when
/// `ac1 < -2/sqrt(n)`. Both the significance test and the strength use integer
/// arithmetic only: the test squares both sides instead of taking a square
/// root, and `isqrt` supplies the threshold.
fn manipulation_strength_bps(times: &[i128]) -> i128 {
    let n = times.len() as i128;
    if n < 6 {
        return 0;
    }
    let mean = times.iter().sum::<i128>() / n;
    let centred: Vec<i128> = times.iter().map(|time| time - mean).collect();
    let variance: i128 = centred.iter().map(|c| c.saturating_mul(*c)).sum();
    if variance < n {
        return 0;
    }
    let cross: i128 = centred
        .windows(2)
        .map(|pair| pair[0].saturating_mul(pair[1]))
        .sum();
    if cross >= 0 {
        return 0;
    }

    // ac1 = n*S1 / ((n-1)*V) < -2/sqrt(n)  <=>  n^(3/2)*(-S1) > 2*(n-1)*V
    // <=>  n^3*S1^2 > 4*(n-1)^2*V^2 once both positive sides are squared.
    let lhs = n
        .saturating_mul(n)
        .saturating_mul(n)
        .saturating_mul(cross)
        .saturating_mul(cross);
    let denominator = (n - 1).saturating_mul(n - 1);
    let rhs = 4i128
        .saturating_mul(denominator)
        .saturating_mul(variance)
        .saturating_mul(variance);
    if lhs <= rhs {
        return 0;
    }

    let magnitude =
        n.saturating_mul(-cross).saturating_mul(BPS) / (n - 1).saturating_mul(variance).max(1);
    let threshold = 2 * BPS / isqrt(n as u64).max(1) as i128;
    (magnitude - threshold).clamp(0, BPS)
}

// --- Guards ----------------------------------------------------------------

/// Applies the configured per-block clamps. Both bounds are inclusive and the
/// floor never exceeds the ceiling even for degenerate configurations.
fn bounded(proposed: u64, prev: u64, cfg: &ChainConfig) -> u64 {
    let floor = (prev / cfg.difficulty_clamp_down.max(1)).max(1);
    let ceiling = prev
        .saturating_mul(cfg.difficulty_clamp_up.max(1))
        .max(floor);
    proposed.clamp(floor, ceiling)
}

fn anti_51_dampening(timestamps: &[u64], proposed: u64, prev: u64, cfg: &ChainConfig) -> u64 {
    if timestamps.len() < 4 {
        return proposed;
    }

    let recent_count = timestamps.len().min(6);
    let recent_span = timestamps[timestamps.len() - 1] as i128
        - timestamps[timestamps.len() - recent_count] as i128;
    let expected_span = (recent_count - 1) as i128 * cfg.block_time_ms() as i128;
    if expected_span == 0 {
        return proposed;
    }

    if recent_span * 100 / expected_span < 25 {
        return proposed.max(prev.saturating_mul(cfg.difficulty_clamp_up.max(1)));
    }
    proposed
}

fn scale(prev: u64, ratio_bps: i128) -> u64 {
    let scaled = (prev as i128).saturating_mul(ratio_bps) / BPS;
    u64::try_from(scaled.max(1)).unwrap_or(u64::MAX)
}

/// Integer square root by Newton iteration. Deterministic and dependency-free.
fn isqrt(value: u64) -> u64 {
    if value < 2 {
        return value;
    }
    let mut x = 1u64 << ((64 - value.leading_zeros()) / 2);
    loop {
        let next = (x + value / x) / 2;
        if next >= x {
            return x;
        }
        x = next;
    }
}

// --- Offline research harness ----------------------------------------------
//
// Ablation experiments compare the gate, the momentum term and the dampener
// against pure LWMA on synthetic work-rate profiles. Floating point is used
// here for metrics only; no value from this section reaches consensus.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AblationVariant {
    /// Gate, momentum and dampener.
    Full,
    /// No significance gate: every sample moves difficulty.
    NoGate,
    /// No momentum term.
    NoMomentum,
    /// No manipulation dampener.
    NoDampener,
    /// Frozen LWMA baseline.
    PureLwma,
}

#[derive(Debug, Clone)]
pub struct AblationMetrics {
    pub variant: AblationVariant,
    pub profile: &'static str,
    pub difficulty_variance: f64,
    pub convergence_blocks: u64,
    pub oscillation_amplitude: f64,
    pub tracking_error: f64,
}

fn next_difficulty_variant(
    timestamps: &[u64],
    difficulties: &[u64],
    cfg: &ChainConfig,
    variant: AblationVariant,
) -> u64 {
    match variant {
        AblationVariant::PureLwma => next_difficulty_lwma(timestamps, difficulties, cfg),
        AblationVariant::Full => controller(
            timestamps,
            difficulties,
            cfg,
            Gate::Enabled,
            MOMENTUM_WEIGHT_BPS,
            Dampener::Enabled,
        ),
        AblationVariant::NoGate => controller(
            timestamps,
            difficulties,
            cfg,
            Gate::Disabled,
            MOMENTUM_WEIGHT_BPS,
            Dampener::Enabled,
        ),
        AblationVariant::NoMomentum => controller(
            timestamps,
            difficulties,
            cfg,
            Gate::Enabled,
            0,
            Dampener::Enabled,
        ),
        AblationVariant::NoDampener => controller(
            timestamps,
            difficulties,
            cfg,
            Gate::Enabled,
            MOMENTUM_WEIGHT_BPS,
            Dampener::Disabled,
        ),
    }
}

/// Simulates block production for a work-rate profile and measures how the
/// controller tracks it. Solve times are derived deterministically from the
/// profile, so the experiment is reproducible.
pub fn run_ablation_simulation(
    variant: AblationVariant,
    profile_name: &'static str,
    work_rate_at_block: &dyn Fn(u64) -> f64,
    num_blocks: u64,
    cfg: &ChainConfig,
) -> AblationMetrics {
    let target_ms = cfg.block_time_ms();
    let window = cfg.difficulty_window.min(30) as usize;

    let mut timestamps: Vec<u64> = vec![0];
    let mut difficulties: Vec<u64> = vec![cfg.genesis_difficulty];
    let mut history: Vec<f64> = vec![cfg.genesis_difficulty as f64];
    let genesis = cfg.genesis_difficulty as f64;

    for height in 1..=num_blocks {
        let rate = work_rate_at_block(height).max(0.01);
        let current = *difficulties.last().expect("seeded history");

        // At equilibrium `genesis_difficulty` units of work take exactly the
        // target block time; a higher work rate solves the same target sooner.
        let solve_time = ((current as f64 / genesis) * target_ms as f64 / rate) as u64;
        let previous = *timestamps.last().expect("seeded history");
        timestamps.push(previous + solve_time.max(1));
        difficulties.push(current);

        let start = timestamps.len().saturating_sub(window + 1);
        let next =
            next_difficulty_variant(&timestamps[start..], &difficulties[start..], cfg, variant);
        *difficulties.last_mut().expect("seeded history") = next;
        history.push(next as f64);
    }

    let mean = history.iter().sum::<f64>() / history.len() as f64;
    let variance = history
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / history.len() as f64;
    let normalised_variance = (variance.sqrt() / mean.max(1.0)) * 100.0;

    let ideal_at = |height: u64| -> f64 { genesis * work_rate_at_block(height) };
    let mut convergence = num_blocks;
    if profile_name == "step" {
        for height in 100..=num_blocks {
            let ideal = ideal_at(height);
            let actual = history[height as usize];
            if (actual - ideal).abs() / ideal.max(1.0) < 0.20 {
                convergence = height - 100;
                break;
            }
        }
    }

    let tail = &history[history.len().saturating_sub(50)..];
    let tail_max = tail.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let tail_min = tail.iter().cloned().fold(f64::INFINITY, f64::min);
    let tail_mean = tail.iter().sum::<f64>() / tail.len() as f64;
    let oscillation_amplitude = if tail_mean > 0.0 {
        (tail_max - tail_min) / tail_mean * 100.0
    } else {
        0.0
    };

    let mut tracking_sq_sum = 0.0f64;
    for height in 1..=num_blocks {
        let ideal = ideal_at(height);
        let actual = history[height as usize];
        let error = (actual - ideal) / ideal.max(1.0);
        tracking_sq_sum += error * error;
    }
    let tracking_error = (tracking_sq_sum / num_blocks as f64).sqrt() * 100.0;

    AblationMetrics {
        variant,
        profile: profile_name,
        difficulty_variance: normalised_variance,
        convergence_blocks: convergence,
        oscillation_amplitude,
        tracking_error,
    }
}

/// Runs the full 5-variant by 4-profile experiment suite.
pub fn run_full_ablation(cfg: &ChainConfig) -> Vec<AblationMetrics> {
    let variants = [
        AblationVariant::Full,
        AblationVariant::NoGate,
        AblationVariant::NoMomentum,
        AblationVariant::NoDampener,
        AblationVariant::PureLwma,
    ];

    type WorkRateProfile = (&'static str, Box<dyn Fn(u64) -> f64>);
    let profiles: Vec<WorkRateProfile> = vec![
        ("stable", Box::new(|_| 1.0)),
        ("step", Box::new(|h| if h < 100 { 1.0 } else { 2.0 })),
        (
            "oscillating",
            Box::new(|h| if (h / 20) % 2 == 0 { 1.0 } else { 3.0 }),
        ),
        ("ramp", Box::new(|h| 1.0 + (h as f64 / 200.0).min(2.0))),
    ];

    let num_blocks = 200u64;
    let mut results = Vec::new();
    for variant in variants {
        for (name, work_rate) in &profiles {
            results.push(run_ablation_simulation(
                variant, name, work_rate, num_blocks, cfg,
            ));
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn steady(blocks: usize, step_ms: u64, difficulty: u64) -> (Vec<u64>, Vec<u64>) {
        (
            (0..blocks).map(|i| i as u64 * step_ms).collect(),
            vec![difficulty; blocks],
        )
    }

    #[test]
    fn stable_solve_times_hold_difficulty() {
        let cfg = ChainConfig::testnet();
        let (timestamps, difficulties) = steady(10, cfg.block_time_ms(), cfg.genesis_difficulty);
        let next = next_difficulty(&timestamps, &difficulties, &cfg);
        assert_eq!(next, cfg.genesis_difficulty);
    }

    #[test]
    fn fast_blocks_raise_difficulty_and_slow_blocks_lower_it() {
        let cfg = ChainConfig::testnet();
        let target = cfg.block_time_ms();
        let difficulty = cfg.genesis_difficulty;

        let (fast, diffs) = steady(10, target / 2, difficulty);
        assert!(next_difficulty(&fast, &diffs, &cfg) > difficulty);

        let (slow, diffs) = steady(10, target * 2, difficulty);
        assert!(next_difficulty(&slow, &diffs, &cfg) < difficulty);
    }

    #[test]
    fn frozen_lwma_clamps_timestamp_reversal_attack() {
        let cfg = ChainConfig::devnet();
        let previous = 9_000u64;
        let timestamps = vec![0, 30_000, 60_000, 1_000, 2_000, 3_000];
        let difficulties = vec![previous; timestamps.len()];

        let next = next_difficulty(&timestamps, &difficulties, &cfg);
        assert_eq!(cfg.difficulty_algorithm, DifficultyAlgorithm::LwmaV1);
        assert!(next >= previous / cfg.difficulty_clamp_down);
        assert!(next <= previous.saturating_mul(cfg.difficulty_clamp_up));
    }

    #[test]
    fn research_profile_never_drops_below_the_clamp_on_timestamp_reversal() {
        let cfg = ChainConfig::testnet();
        let previous = 4_000u64;
        let timestamps = vec![0, 30_000, 60_000, 1_000, 2_000, 3_000, 4_000];
        let difficulties = vec![previous; timestamps.len()];

        let next = next_difficulty(&timestamps, &difficulties, &cfg);
        assert!(next >= previous / cfg.difficulty_clamp_down);
        assert!(next <= previous.saturating_mul(cfg.difficulty_clamp_up));
    }

    #[test]
    fn every_result_respects_the_configured_clamps() {
        let cfg = ChainConfig::testnet();
        let target = cfg.block_time_ms();
        let difficulty = 5_000u64;

        for step in [target / 8, target / 2, target, target * 3, target * 6] {
            let (timestamps, difficulties) = steady(12, step, difficulty);
            let next = next_difficulty(&timestamps, &difficulties, &cfg);
            assert!(next >= 1);
            assert!(next >= difficulty / cfg.difficulty_clamp_down);
            assert!(next <= difficulty.saturating_mul(cfg.difficulty_clamp_up));
        }
    }

    #[test]
    fn malformed_history_falls_back_to_genesis_difficulty() {
        let cfg = ChainConfig::testnet();
        assert_eq!(next_difficulty(&[], &[], &cfg), cfg.genesis_difficulty);
        assert_eq!(
            next_difficulty(&[0, 1, 2], &[7, 7], &cfg),
            cfg.genesis_difficulty
        );
    }

    #[test]
    fn momentum_sign_follows_the_direction_of_the_work_rate() {
        let shrinking = vec![60_000, 50_000, 40_000, 30_000, 20_000, 10_000];
        assert!(momentum_bps(&shrinking) > 0);
        let growing = vec![10_000, 20_000, 30_000, 40_000, 50_000, 60_000];
        assert!(momentum_bps(&growing) < 0);
        let flat = vec![30_000; 12];
        assert_eq!(momentum_bps(&flat), 0);
    }

    #[test]
    fn dampener_marks_periodic_patterns_and_ignores_trends() {
        let alternating: Vec<i128> = (0..20)
            .map(|i| if i % 2 == 0 { 15_000 } else { 45_000 })
            .collect();
        let strength = manipulation_strength_bps(&alternating);
        assert!(strength > 0, "alternating pattern must be significant");
        assert!(dampen_change(1_500, 1_000, &alternating) < 1_500);

        let trend: Vec<i128> = (0..20).map(|i| 20_000 + i * 1_000).collect();
        assert_eq!(manipulation_strength_bps(&trend), 0);
        assert_eq!(dampen_change(1_200, 1_000, &trend), 1_200);
    }

    #[test]
    fn anti_51_refuses_to_lower_difficulty_after_a_speed_burst() {
        let cfg = ChainConfig::testnet();
        let previous = 1_000u64;
        let (timestamps, difficulties) = steady(10, cfg.block_time_ms() / 10, previous);
        let next = next_difficulty(&timestamps, &difficulties, &cfg);
        assert!(next >= previous);
    }

    #[test]
    fn integer_square_root_is_exact() {
        for value in [0u64, 1, 2, 3, 4, 8, 9, 10, 15, 16, 17, 1_000_000, u64::MAX] {
            let root = isqrt(value) as u128;
            let value = value as u128;
            assert!(root * root <= value);
            assert!((root + 1) * (root + 1) > value);
        }
    }

    #[test]
    fn ablation_gate_reduces_variance_under_a_stable_work_rate() {
        let cfg = ChainConfig::testnet();
        let full = run_ablation_simulation(AblationVariant::Full, "stable", &|_| 1.0, 200, &cfg);
        let ungated =
            run_ablation_simulation(AblationVariant::NoGate, "stable", &|_| 1.0, 200, &cfg);
        assert!(full.difficulty_variance <= ungated.difficulty_variance);
    }

    #[test]
    fn ablation_full_suite_reports_finite_metrics() {
        let cfg = ChainConfig::testnet();
        let results = run_full_ablation(&cfg);
        assert_eq!(results.len(), 20);
        for result in &results {
            assert!(result.difficulty_variance.is_finite());
            assert!(result.tracking_error.is_finite());
            assert!(result.oscillation_amplitude.is_finite());
        }
    }

    #[test]
    fn ablation_print_results() {
        let cfg = ChainConfig::testnet();
        println!(
            "\n{:<12} {:<12} {:>10} {:>10} {:>10} {:>10}",
            "Variant", "Profile", "Var(%)", "Conv(blk)", "Osc(%)", "Track(%)"
        );
        for result in run_full_ablation(&cfg) {
            println!(
                "{:<12} {:<12} {:>10.2} {:>10} {:>10.2} {:>10.2}",
                format!("{:?}", result.variant),
                result.profile,
                result.difficulty_variance,
                result.convergence_blocks,
                result.oscillation_amplitude,
                result.tracking_error
            );
        }
    }
}
