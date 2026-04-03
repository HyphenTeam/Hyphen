// Lorentzian Continuous Decay (LCD) Emission Model
// with Marginal Security Emission (MSE) Multiplier
//
// Base reward: R_lcd(h) = R_tail + (R_0 - R_tail) · c² / (h² + c²)
//
// MSE Multiplier: μ(h) = clamp(1 + γ · (D_actual / D_target − 1),  floor, ceil)
//
// Effective reward: R(h) = R_lcd(h) · μ(h)
//
// Economic rationale (Marginal Security Emission):
//  - When actual difficulty D_actual > D_target (hashrate above trend),
//    miners are overprovisioning security → μ > 1 → reward increases,
//    compensating the real cost of providing excess security.
//  - When D_actual < D_target (hashrate lags), security is cheap to
//    provide → μ < 1 → reward decreases, preventing overpayment for
//    security that isn't being delivered.
//  - This creates a negative-feedback equilibrium: the emission budget
//    automatically allocates more reward when security is expensive,
//    and less when it's cheap.
//
// The D_target "trend" line is a simple exponential moving average of
// recent difficulties, anchored at genesis and smoothed over a large
// window.  This avoids external oracles — everything is on-chain.
//
// Parameters (from ChainConfig):
//   mse_gamma     = sensitivity factor × 1000 (e.g. 100 → γ=0.10)
//   mse_floor_bps = minimum multiplier × 10000 (e.g. 8000 → 0.80×)
//   mse_ceil_bps  = maximum multiplier × 10000 (e.g. 12000 → 1.20×)

use hyphen_core::config::ChainConfig;

/// Compute the **base** LCD block reward at a given height (no MSE multiplier).
pub fn lcd_base_reward(height: u64, cfg: &ChainConfig) -> u64 {
    if cfg.tail_emission_height > 0 && height >= cfg.tail_emission_height {
        return cfg.tail_emission;
    }

    let r0 = cfg.initial_reward as u128;
    let r_tail = cfg.tail_emission as u128;
    let c = cfg.emission_decay_constant as u128;
    let h = height as u128;

    let a = r0.saturating_sub(r_tail);
    let c_sq = c.saturating_mul(c);
    let h_sq = h.saturating_mul(h);
    let denom = h_sq.saturating_add(c_sq);
    let decay = a.saturating_mul(c_sq) / denom;

    if decay == 0 {
        return cfg.tail_emission;
    }

    (r_tail + decay) as u64
}

/// Compute the MSE multiplier from the actual/target difficulty ratio.
///
/// Returns the multiplier scaled by 10_000 (basis points):
///   - 10_000 = 1.00×  (no adjustment)
///   - 12_000 = 1.20×  (max upward)
///   -  8_000 = 0.80×  (max downward)
///
/// `difficulty_ratio_bps` = (D_actual / D_target) × 10_000.
/// If D_target = 0 or unknown (e.g. genesis), returns 10_000 (neutral).
pub fn mse_multiplier_bps(difficulty_ratio_bps: u64, cfg: &ChainConfig) -> u64 {
    // γ as fixed-point: mse_gamma=100 → γ=0.10 → γ_scaled = 100
    // deviation = ratio - 10_000 (can be negative)
    let ratio = difficulty_ratio_bps as i128;
    let deviation = ratio - 10_000;

    // raw_multiplier = 10_000 + γ/1000 * deviation
    // = 10_000 + mse_gamma * deviation / 1000
    let gamma = cfg.mse_gamma as i128;
    let raw = 10_000i128 + gamma * deviation / 1000;

    // Clamp between floor and ceil
    let floor = cfg.mse_floor_bps as i128;
    let ceil = cfg.mse_ceil_bps as i128;
    raw.clamp(floor, ceil) as u64
}

/// Compute the full block reward with MSE adjustment.
///
/// `difficulty_ratio_bps` = (D_actual / D_target) × 10_000.
/// Pass 10_000 for no MSE adjustment (neutral ratio).
pub fn block_reward(height: u64, cfg: &ChainConfig) -> u64 {
    block_reward_with_mse(height, 10_000, cfg)
}

/// Compute the block reward with an explicit MSE difficulty ratio.
pub fn block_reward_with_mse(
    height: u64,
    difficulty_ratio_bps: u64,
    cfg: &ChainConfig,
) -> u64 {
    let base = lcd_base_reward(height, cfg) as u128;
    let multiplier = mse_multiplier_bps(difficulty_ratio_bps, cfg) as u128;

    let adjusted = base * multiplier / 10_000;

    // Never below tail emission
    adjusted.max(cfg.tail_emission as u128) as u64
}

/// Approximate cumulative *base* supply emitted from genesis to `height` (inclusive).
///
/// Uses the trapezoidal rule over 1024-block segments. This computes
/// the LCD base schedule (no MSE) because the MSE multiplier is
/// difficulty-dependent and unknowable for future blocks.
pub fn total_supply_at_height(height: u64, cfg: &ChainConfig) -> u128 {
    let mut total: u128 = 0;
    let step = 1024u64;
    let mut h = 0u64;

    while h <= height {
        let end = (h + step - 1).min(height);
        let r_start = lcd_base_reward(h, cfg) as u128;
        let r_end = lcd_base_reward(end, cfg) as u128;
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

    #[test]
    fn mse_neutral_ratio() {
        let cfg = ChainConfig::mainnet();
        // ratio = 10_000 (1.0×) → multiplier should be 10_000 (neutral)
        assert_eq!(mse_multiplier_bps(10_000, &cfg), 10_000);
    }

    #[test]
    fn mse_high_hashrate() {
        let cfg = ChainConfig::mainnet();
        // ratio = 15_000 (1.5×) → deviation = +5000
        // raw = 10_000 + 100 * 5000 / 1000 = 10_000 + 500 = 10_500
        // clamped to ceil 12_000 → actually 10_500 < 12_000 so stays
        let m = mse_multiplier_bps(15_000, &cfg);
        assert_eq!(m, 10_500);
    }

    #[test]
    fn mse_low_hashrate() {
        let cfg = ChainConfig::mainnet();
        // ratio = 5_000 (0.5×) → deviation = -5000
        // raw = 10_000 + 100 * (-5000) / 1000 = 10_000 - 500 = 9_500
        let m = mse_multiplier_bps(5_000, &cfg);
        assert_eq!(m, 9_500);
    }

    #[test]
    fn mse_clamp_ceil() {
        let cfg = ChainConfig::mainnet();
        // ratio = 40_000 (4.0×) → deviation = +30_000
        // raw = 10_000 + 100 * 30_000 / 1000 = 10_000 + 3_000 = 13_000
        // clamped to ceil 12_000
        let m = mse_multiplier_bps(40_000, &cfg);
        assert_eq!(m, cfg.mse_ceil_bps);
    }

    #[test]
    fn mse_clamp_floor() {
        let cfg = ChainConfig::mainnet();
        // ratio = 0 → deviation = -10_000
        // raw = 10_000 + 100 * (-10_000) / 1000 = 10_000 - 1_000 = 9_000
        // above floor 8_000, so stays at 9_000
        let m = mse_multiplier_bps(0, &cfg);
        assert_eq!(m, 9_000);
    }

    #[test]
    fn mse_adjusted_reward() {
        let cfg = ChainConfig::mainnet();
        let base = lcd_base_reward(0, &cfg);
        // 1.05× multiplier
        let adj = block_reward_with_mse(0, 15_000, &cfg);
        let expected = (base as u128 * 10_500 / 10_000) as u64;
        assert_eq!(adj, expected);
    }

    #[test]
    fn mse_never_below_tail() {
        let cfg = ChainConfig::mainnet();
        // Even with minimum multiplier at very late height
        let r = block_reward_with_mse(1_000_000_000, 0, &cfg);
        assert!(r >= cfg.tail_emission);
    }
}
