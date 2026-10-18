//! Difficulty control for the neural challenge.
//!
//! The hidden width is the difficulty axis: cost per epoch grows with
//! `input_dim * hidden_dim + hidden_dim * output_dim`, and the training
//! landscape grows with it too. The controller is a bounded integer
//! proportional controller with hysteresis, so it cannot oscillate between two
//! adjacent widths on every epoch and cannot move more than one doubling step
//! per epoch.
//!
//! The rule is deliberately simple enough to reimplement independently: the
//! contract, the miner and an auditor must agree on the next width given the
//! same observation.

use crate::challenge::{MAX_HIDDEN_DIM, MIN_HIDDEN_DIM};

/// Target wall-clock time between challenge settlements, in seconds.
pub const TARGET_EPOCH_SECONDS: u64 = 600;

/// The controller only reacts once the observed solve time leaves this band.
pub const HYSTERESIS_FACTOR: u64 = 2;

/// Selects the next hidden width from the observed solve time.
///
/// - observed faster than `target / 2`: double the width;
/// - observed slower than `target * 2`: halve the width;
/// - otherwise keep it.
///
/// The result is clamped to `[MIN_HIDDEN_DIM, MAX_HIDDEN_DIM]`. A zero
/// observation is treated as "too fast", which is the safe direction: a broken
/// clock cannot silently make the chain cheaper.
pub fn next_hidden_dim(current: u16, observed_seconds: u64, target_seconds: u64) -> u16 {
    let current = current.clamp(MIN_HIDDEN_DIM, MAX_HIDDEN_DIM);
    let target = target_seconds.max(1);
    if observed_seconds.saturating_mul(HYSTERESIS_FACTOR) < target {
        current.saturating_mul(2).min(MAX_HIDDEN_DIM)
    } else if observed_seconds > target.saturating_mul(HYSTERESIS_FACTOR) {
        (current / 2).max(MIN_HIDDEN_DIM)
    } else {
        current
    }
}

/// Maps a Unix timestamp to its challenge epoch.
pub fn epoch_of(timestamp_secs: u64) -> u64 {
    timestamp_secs / TARGET_EPOCH_SECONDS
}

/// Start timestamp of an epoch.
pub fn epoch_start(epoch: u64) -> u64 {
    epoch.saturating_mul(TARGET_EPOCH_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fast_epoch_doubles_the_width() {
        assert_eq!(next_hidden_dim(16, 60, 600), 32);
        assert_eq!(next_hidden_dim(256, 299, 600), 512);
        assert_eq!(next_hidden_dim(512, 1, 600), 512);
    }

    #[test]
    fn a_slow_epoch_halves_the_width() {
        assert_eq!(next_hidden_dim(64, 1_201, 600), 32);
        assert_eq!(next_hidden_dim(16, 10_000, 600), 16);
        assert_eq!(next_hidden_dim(512, u64::MAX, 600), 256);
    }

    #[test]
    fn the_hysteresis_band_keeps_the_width() {
        assert_eq!(next_hidden_dim(64, 300, 600), 64);
        assert_eq!(next_hidden_dim(64, 1_200, 600), 64);
        assert_eq!(next_hidden_dim(64, 600, 600), 64);
    }

    #[test]
    fn a_zero_observation_is_treated_as_too_fast() {
        assert_eq!(next_hidden_dim(32, 0, 600), 64);
        // A zero target is coerced to one second rather than dividing by zero.
        assert_eq!(next_hidden_dim(32, 5, 0), 16);
    }

    #[test]
    fn epochs_are_ten_minutes() {
        assert_eq!(epoch_of(0), 0);
        assert_eq!(epoch_of(599), 0);
        assert_eq!(epoch_of(600), 1);
        assert_eq!(epoch_start(3), 1_800);
    }
}
