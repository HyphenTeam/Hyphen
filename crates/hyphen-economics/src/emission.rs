// reward(h) = max(initial_reward · 2^{−h / half_life}, tail_emission)

use hyphen_core::config::ChainConfig;

pub fn block_reward(height: u64, cfg: &ChainConfig) -> u64 {
    if cfg.tail_emission_height > 0 && height >= cfg.tail_emission_height {
        return cfg.tail_emission;
    }

    // R(h) = R₀ · 2^{-h/H}
    let full_halvings = height / cfg.emission_half_life;
    let remainder = height % cfg.emission_half_life;

    if full_halvings >= 64 {
        return cfg.tail_emission;
    }

    let base = cfg.initial_reward >> full_halvings;

    // base - base * remainder / (2 * half_life)
    let interp = base.saturating_sub(
        (base as u128 * remainder as u128 / (2 * cfg.emission_half_life) as u128) as u64,
    );

    interp.max(cfg.tail_emission)
}

pub fn total_supply_at_height(height: u64, cfg: &ChainConfig) -> u128 {
    // S(h) ≈ R₀ · H · 2 · (1 − 2^{−h/H}) / ln(2)
    let mut total: u128 = 0;
    let mut h = 0u64;
    while h <= height {
        let epoch_end = ((h / cfg.emission_half_life) + 1) * cfg.emission_half_life - 1;
        let end = epoch_end.min(height);
        let blocks_in_epoch = end - h + 1;

        let r_start = block_reward(h, cfg) as u128;
        let r_end = block_reward(end, cfg) as u128;

        total += (r_start + r_end) * blocks_in_epoch as u128 / 2;

        h = end + 1;
    }
    total
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
    fn reward_halves() {
        let cfg = ChainConfig::mainnet();
        let r0 = block_reward(0, &cfg);
        let r1 = block_reward(cfg.emission_half_life, &cfg);
        assert_eq!(r1, r0 / 2);
    }

    #[test]
    fn tail_emission_floor() {
        let cfg = ChainConfig::mainnet();
        let very_late = 100_000_000;
        let r = block_reward(very_late, &cfg);
        assert_eq!(r, cfg.tail_emission);
    }
}
