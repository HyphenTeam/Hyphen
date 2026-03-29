use hyphen_core::config::ChainConfig;

pub fn next_difficulty(
    timestamps: &[u64],
    difficulties: &[u64],
    cfg: &ChainConfig,
) -> u64 {
    let n = timestamps.len();
    assert!(n >= 2, "need at least 2 blocks for difficulty adjustment");
    let window = n - 1; // number of intervals

    let target_secs = cfg.block_time.as_secs();

    let mut weighted_solve_time: i128 = 0;
    let mut weight_sum: i128 = 0;
    let mut difficulty_sum: u128 = 0;

    for i in 1..n {
        let solve_time = timestamps[i] as i128 - timestamps[i - 1] as i128;
        // Clamp solve time to [1, 6T]
        let clamped = solve_time
            .max(1)
            .min(6 * target_secs as i128);

        let weight = i as i128; // linear weight: more recent → heavier
        weighted_solve_time += clamped * weight;
        weight_sum += weight;
        difficulty_sum += difficulties[i] as u128;
    }

    if weight_sum == 0 || difficulty_sum == 0 {
        return cfg.genesis_difficulty;
    }

    // T_target = target_secs * weight_sum
    let t_target = target_secs as i128 * weight_sum;

    // next_diff = difficulty_avg * T_target / weighted_solve_time
    let difficulty_avg = difficulty_sum / window as u128;
    let next = (difficulty_avg as i128 * t_target / weighted_solve_time.max(1)) as u64;

    // Clamp to prevent extreme jumps (at most 3× change)
    let prev_diff = *difficulties.last().unwrap();
    let min_diff = prev_diff / 3;
    let max_diff = prev_diff.saturating_mul(3);
    next.max(min_diff.max(1)).min(max_diff.max(1))
}

// target = 2^256 / difficulty  (clamped so target ≤ 2^256 − 1)
pub fn difficulty_to_target(difficulty: u64) -> [u8; 32] {
    if difficulty <= 1 {
        return [0xFF; 32];
    }

    let diff = difficulty as u128;
    // (high * 2^128 + low) / diff
    let high = u128::MAX;
    let low = u128::MAX;

    let quot_high = high / diff;
    let rem_high = high % diff;
    let (quot_low, _) = div_wide(rem_high, low, diff);

    let mut target = [0u8; 32];
    let qh_bytes = quot_high.to_be_bytes();
    let ql_bytes = quot_low.to_be_bytes();
    target[..16].copy_from_slice(&qh_bytes);
    target[16..].copy_from_slice(&ql_bytes);
    target
}

// (high * 2^128 + low) / divisor -> (quotient, remainder)
fn div_wide(high: u128, low: u128, divisor: u128) -> (u128, u128) {
    if high == 0 {
        return (low / divisor, low % divisor);
    }
    // (h / d) * 2^128 + ((h % d) * 2^128 + l) / d
    let mut rem = high % divisor;
    let mut quot: u128 = 0;
    for bit in (0..128).rev() {
        rem = rem.checked_shl(1).unwrap_or(0);
        if (low >> bit) & 1 == 1 {
            rem += 1;
        }
        if rem >= divisor {
            rem -= divisor;
            quot |= 1u128 << bit;
        }
    }
    (quot, rem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_core::config::ChainConfig;

    #[test]
    fn stable_hashrate_keeps_difficulty() {
        let cfg = ChainConfig::testnet();
        let t = cfg.block_time.as_secs();
        let n = 10;
        let timestamps: Vec<u64> = (0..n).map(|i| i * t).collect();
        let difficulties: Vec<u64> = vec![1000; n as usize];
        let next = next_difficulty(&timestamps, &difficulties, &cfg);
        assert!(next >= 800 && next <= 1200, "got {next}");
    }

    #[test]
    fn fast_blocks_increase_difficulty() {
        let cfg = ChainConfig::testnet();
        let t = cfg.block_time.as_secs();
        let n = 10;
        let timestamps: Vec<u64> = (0..n).map(|i| i * (t / 2)).collect();
        let difficulties: Vec<u64> = vec![1000; n as usize];
        let next = next_difficulty(&timestamps, &difficulties, &cfg);
        assert!(next > 1000, "expected increase, got {next}");
    }

    #[test]
    fn difficulty_to_target_basic() {
        let t1 = difficulty_to_target(1);
        assert_eq!(t1, [0xFF; 32]);
        let t2 = difficulty_to_target(2);
        assert!(t2[0] == 0x7F);
    }
}
