use hyphen_core::config::ChainConfig;

const FEE_PER_BYTE: u64 = 100;

pub fn minimum_fee(tx_size_bytes: usize, _cfg: &ChainConfig) -> u64 {
    let base = tx_size_bytes as u64 * FEE_PER_BYTE;
    base.max(10_000)
}

pub fn burned_fee(total_fee: u64, cfg: &ChainConfig) -> u64 {
    (total_fee as u128 * cfg.fee_burn_bps as u128 / 10_000) as u64
}

pub fn miner_fee_share(total_fee: u64, cfg: &ChainConfig) -> u64 {
    total_fee - burned_fee(total_fee, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyphen_core::config::ChainConfig;

    #[test]
    fn fee_split() {
        let cfg = ChainConfig::mainnet();
        let fee = 100_000u64;
        let burn = burned_fee(fee, &cfg);
        let miner = miner_fee_share(fee, &cfg);
        assert_eq!(burn + miner, fee);
        // 5000 bps = 50%
        assert_eq!(burn, 50_000);
    }
}
