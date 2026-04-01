// Lorentzian Continuous Decay (LCD) Emission Model
//
// R(h) = R_tail + (R_0 - R_tail) · c² / (h² + c²)
//
// where:
//   R_0    = initial block reward (100 HPN = 100_000_000_000_000 atomic units)
//   R_tail = perpetual tail emission (0.6 HPN = 600_000_000_000 atomic units)
//   c      = emission_decay_constant (2²⁰ = 1_048_576 blocks ≈ 2 years at 60s/block)
//
// Properties:
//   - Smooth, continuous, infinitely differentiable — NO discrete halvings
//   - R(0)  = R_0 (full initial reward at genesis)
//   - R(c)  = (R_0 + R_tail) / 2 ≈ 50.3 HPN (midpoint at ~2 years)
//   - R(∞) → R_tail (long-term convergence to tail emission)
//   - Total finite emission ≈ (R_0 - R_tail) · c · π / 2 ≈ 164 million HPN
//   - Tail emission provides perpetual miner incentive (≈ 315 k HPN / year)
//
// All arithmetic uses u128 to prevent overflow. Maximum product is
// (R_0 - R_tail) · c² ≈ 10²⁶, well within u128 range (≈ 3.4 × 10³⁸).

use hyphen_core::config::ChainConfig;

/// Compute the block reward at a given height using the Lorentzian decay model.
pub fn block_reward(height: u64, cfg: &ChainConfig) -> u64 {
    // Emergency override: if tail_emission_height is set, force tail after that height
    if cfg.tail_emission_height > 0 && height >= cfg.tail_emission_height {
        return cfg.tail_emission;
    }

    let r0 = cfg.initial_reward as u128;
    let r_tail = cfg.tail_emission as u128;
    let c = cfg.emission_decay_constant as u128;
    let h = height as u128;

    // A = R_0 - R_tail (the decaying component)
    let a = r0.saturating_sub(r_tail);

    // c² and h² in u128
    let c_sq = c.saturating_mul(c);
    let h_sq = h.saturating_mul(h);

    // denominator = h² + c²  (always > 0 since c ≥ 1)
    let denom = h_sq.saturating_add(c_sq);

    // decay = A · c² / (h² + c²)
    let decay = a.saturating_mul(c_sq) / denom;

    // When the decay is negligible (< 1 atomic unit per HPN), snap to tail
    if decay == 0 {
        return cfg.tail_emission;
    }

    // R(h) = R_tail + decay
    let reward = r_tail + decay;

    reward as u64
}

/// Approximate cumulative supply emitted from genesis to `height` (inclusive).
///
/// Uses the trapezoidal rule over 1024-block segments for accuracy
/// without requiring floating-point or transcendental functions.
pub fn total_supply_at_height(height: u64, cfg: &ChainConfig) -> u128 {
    let mut total: u128 = 0;
    let step = 1024u64;
    let mut h = 0u64;

    while h <= height {
        let end = (h + step - 1).min(height);
        let r_start = block_reward(h, cfg) as u128;
        let r_end = block_reward(end, cfg) as u128;
        let blocks = (end - h + 1) as u128;

        // Trapezoidal rule: (r_start + r_end) / 2 * blocks
        total += (r_start + r_end) * blocks / 2;

        h = end + 1;
    }

    total
}

/// Estimate the height at which the reward first reaches the tail emission floor.
/// Returns the height where the decay component drops below 1 atomic unit.
pub fn tail_emission_height_estimate(cfg: &ChainConfig) -> u64 {
    let a = (cfg.initial_reward - cfg.tail_emission) as u128;
    let c = cfg.emission_decay_constant as u128;

    // We want: A · c² / (h² + c²) < 1
    // => A · c² < h² + c²
    // => h² > A · c² - c²
    // => h > c · sqrt(A - 1)
    // Approximate: h ≈ c · A^(1/2)  (for large A)
    let a_sqrt = integer_sqrt(a);
    let h = c.saturating_mul(a_sqrt);

    h.min(u64::MAX as u128) as u64
}

/// Integer square root via Newton's method.
fn integer_sqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_core::config::ChainConfig;

    #[test]
    fn genesis_reward() {
        let cfg = ChainConfig::mainnet();
        let r = block_reward(0, &cfg);
        assert_eq!(r, cfg.initial_reward);
    }

    #[test]
    fn midpoint_reward() {
        // At h = c, reward should be approximately (R_0 + R_tail) / 2
        let cfg = ChainConfig::mainnet();
        let r = block_reward(cfg.emission_decay_constant, &cfg);
        let expected = (cfg.initial_reward + cfg.tail_emission) / 2;
        // Allow 1 atomic unit rounding tolerance
        assert!(
            (r as i128 - expected as i128).unsigned_abs() <= 1,
            "at h=c: got {r}, expected ~{expected}"
        );
    }

    #[test]
    fn reward_decreases_monotonically() {
        let cfg = ChainConfig::mainnet();
        let mut prev = block_reward(0, &cfg);
        for h in [1, 100, 1000, 10_000, 100_000, 1_000_000, 10_000_000] {
            let r = block_reward(h, &cfg);
            assert!(r <= prev, "reward increased at height {h}: {prev} -> {r}");
            prev = r;
        }
    }

    #[test]
    fn tail_emission_floor() {
        let cfg = ChainConfig::mainnet();
        // At very late heights, reward should converge very close to tail
        let very_late = 1_000_000_000;
        let r = block_reward(very_late, &cfg);
        // Must be at or very close to tail emission (within 0.001% of initial reward)
        let tolerance = cfg.initial_reward / 100_000;
        assert!(
            r <= cfg.tail_emission + tolerance,
            "reward {r} too far above tail {} at height {very_late}",
            cfg.tail_emission
        );
        assert!(r >= cfg.tail_emission);
    }

    #[test]
    fn never_below_tail() {
        let cfg = ChainConfig::mainnet();
        for h in [0, 1, 1000, 1_000_000, 100_000_000, u64::MAX / 2] {
            let r = block_reward(h, &cfg);
            assert!(
                r >= cfg.tail_emission,
                "reward {r} below tail {} at height {h}",
                cfg.tail_emission
            );
        }
    }

    #[test]
    fn total_supply_increases() {
        let cfg = ChainConfig::testnet();
        let s1 = total_supply_at_height(100, &cfg);
        let s2 = total_supply_at_height(1000, &cfg);
        let s3 = total_supply_at_height(10_000, &cfg);
        assert!(s2 > s1);
        assert!(s3 > s2);
    }

    #[test]
    fn emission_milestones() {
        let cfg = ChainConfig::mainnet();
        let c = cfg.emission_decay_constant;
        let r0 = block_reward(0, &cfg);
        let r1 = block_reward(c, &cfg); // ~2 years
        let r2 = block_reward(2 * c, &cfg); // ~4 years
        let r5 = block_reward(5 * c, &cfg); // ~10 years
        let r10 = block_reward(10 * c, &cfg); // ~20 years

        assert_eq!(r0, 100_000_000_000_000); // 100 HPN
        assert!(r1 > 49_000_000_000_000 && r1 < 51_000_000_000_000); // ~50 HPN
        assert!(r2 > 19_000_000_000_000 && r2 < 21_000_000_000_000); // ~20 HPN
        assert!(r5 > 3_000_000_000_000 && r5 < 5_000_000_000_000); // ~4 HPN
        assert!(r10 > 500_000_000_000 && r10 < 2_000_000_000_000); // ~1.6 HPN
    }

    #[test]
    fn integer_sqrt_correct() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(4), 2);
        assert_eq!(integer_sqrt(100), 10);
        assert_eq!(integer_sqrt(1_000_000), 1000);
    }
}
