use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainConfig {
    pub network_name: String,
    pub network_magic: [u8; 4],
    pub block_time: Duration,
    pub epoch_length: u64,
    pub arena_size: usize,
    pub scratchpad_size: usize,
    pub page_size: usize,
    pub pow_rounds: u32,
    pub writeback_interval: u32,
    pub kernel_count: u8,
    pub merkle_depth: usize,
    pub ring_size: usize,
    pub difficulty_window: u64,
    pub genesis_difficulty: u64,
    pub max_block_size: usize,
    pub initial_reward: u64,
    pub tail_emission: u64,
    pub fee_burn_bps: u16,
    pub tail_emission_height: u64,
    pub emission_half_life: u64,
}

impl ChainConfig {
    pub fn mainnet() -> Self {
        Self {
            network_name: "hyphen-mainnet".into(),
            network_magic: [0x48, 0x59, 0x50, 0x4E], // "HYPN"
            block_time: Duration::from_secs(12),
            epoch_length: 2048,
            arena_size: 2 * 1024 * 1024 * 1024, // 2 GiB
            scratchpad_size: 8 * 1024 * 1024,    // 8 MiB
            page_size: 4096,
            pow_rounds: 1024,
            writeback_interval: 32,
            kernel_count: 8,
            merkle_depth: 32,
            ring_size: 16,
            difficulty_window: 60,
            genesis_difficulty: 1_000_000,
            max_block_size: 2 * 1024 * 1024, // 2 MiB
            initial_reward: 17_592_186_044_416, // ~17.59 HYP
            tail_emission: 300_000_000_000,     // 0.3 HYP
            fee_burn_bps: 5000,
            tail_emission_height: 0,
            emission_half_life: 262_144,
        }
    }

    pub fn testnet() -> Self {
        Self {
            network_name: "hyphen-testnet".into(),
            network_magic: [0x48, 0x59, 0x54, 0x53], // "HYTS"
            block_time: Duration::from_secs(6),
            epoch_length: 128,
            arena_size: 64 * 1024 * 1024, // 64 MiB
            scratchpad_size: 256 * 1024,   // 256 KiB
            page_size: 4096,
            pow_rounds: 64,
            writeback_interval: 8,
            kernel_count: 8,
            merkle_depth: 32,
            ring_size: 4,
            difficulty_window: 30,
            genesis_difficulty: 1000,
            max_block_size: 2 * 1024 * 1024,
            initial_reward: 17_592_186_044_416,
            tail_emission: 300_000_000_000,
            fee_burn_bps: 5000,
            tail_emission_height: 0,
            emission_half_life: 1024,
        }
    }
}
