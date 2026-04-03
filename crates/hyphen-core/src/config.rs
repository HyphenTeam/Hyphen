use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const MAINNET_P2P_PORT: u16 = 18334;
pub const MAINNET_RPC_PORT: u16 = 18333;
pub const MAINNET_DISCOVERY_PORT: u16 = 20333;
pub const TESTNET_RPC_PORT: u16 = 38333;
pub const TESTNET_P2P_PORT: u16 = 38334;
pub const TESTNET_DISCOVERY_PORT: u16 = 20334;
pub const DEFAULT_TEMPLATE_PORT: u16 = 3350;
pub const DEFAULT_POOL_PORT: u16 = 3340;
pub const DEFAULT_STRATUM_PORT: u16 = 3333;
pub const DEFAULT_EXPLORER_PORT: u16 = 8080;
pub const DEFAULT_SEED_DOMAIN: &str = "bytesnap.tech";

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
    pub emission_decay_constant: u64,
    pub max_uncles: usize,
    pub max_uncle_depth: u64,
    pub uncle_reward_numerator: u64,
    pub uncle_reward_denominator: u64,
    pub nephew_reward_numerator: u64,
    pub nephew_reward_denominator: u64,
    pub difficulty_clamp_up: u64,
    pub difficulty_clamp_down: u64,
    pub timestamp_future_limit_ms: u64,
    pub min_ring_span: u64,
    pub tera_epoch_tolerance: u64,
    pub vre_min_age_bands: usize,
    pub vre_age_band_width: u64,
    pub vre_min_index_span_bps: u64,
    pub vre_activation_height: u64,
    pub mse_gamma: u64,
    pub mse_floor_bps: u64,
    pub mse_ceil_bps: u64,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub discovery_port: u16,
}

impl ChainConfig {
    pub fn block_time_ms(&self) -> u64 {
        self.block_time.as_millis() as u64
    }

    pub fn default_rpc_endpoint(&self) -> String {
        format!("{}:{}", DEFAULT_SEED_DOMAIN, self.rpc_port)
    }

    pub fn default_p2p_addr(&self) -> String {
        format!("/dns4/{}/tcp/{}", DEFAULT_SEED_DOMAIN, self.p2p_port)
    }

    pub fn effective_vre_age_band_width(&self, height: u64) -> u64 {
        if height == 0 || self.vre_min_age_bands == 0 {
            return self.vre_age_band_width;
        }
        let max_feasible = height / (self.vre_min_age_bands as u64);
        self.vre_age_band_width.min(max_feasible.max(1))
    }

    pub fn effective_min_ring_span(&self, height: u64) -> u64 {
        let max_feasible = height.saturating_sub(1);
        self.min_ring_span.min(max_feasible)
    }

    /// Progressive logistic ramp for index-span enforcement.
    ///
    /// Instead of a hard on/off threshold, enforcement follows a sigmoid
    /// curve:  `target_bps × n² / (n² + k²)`  where `k = ring_size × 64`.
    /// This gives smooth 0 → target growth as the output set expands:
    ///   • n = 0   → 0 bps (no requirement)
    ///   • n = k   → 50 % of target
    ///   • n = 2k  → 80 % of target
    ///   • n → ∞   → 100 % of target
    ///
    /// The result is additionally capped at the geometric maximum so the
    /// rule always remains satisfiable.
    pub fn effective_vre_min_index_span_bps(&self, total_outputs: u64) -> u64 {
        if total_outputs <= 1 {
            return 0;
        }
        let max_bps = (total_outputs - 1).saturating_mul(10_000) / total_outputs;

        // Logistic sigmoid via u128 to avoid overflow on large output sets.
        let k = (self.ring_size as u128).saturating_mul(64);
        let n = total_outputs as u128;
        let n2 = n.saturating_mul(n);
        let k2 = k.saturating_mul(k);
        let denom = n2.saturating_add(k2).max(1);
        let progressive_bps =
            ((self.vre_min_index_span_bps as u128).saturating_mul(n2) / denom) as u64;

        progressive_bps.min(max_bps)
    }

    /// Blake3 hash of all consensus-critical parameters.
    ///
    /// Used to verify that an existing chain database was created with the
    /// same consensus rules. Any mutation of these parameters after genesis
    /// will be detected and rejected.
    pub fn consensus_params_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&self.network_magic);
        buf.extend_from_slice(&(self.ring_size as u64).to_le_bytes());
        buf.extend_from_slice(&self.min_ring_span.to_le_bytes());
        buf.extend_from_slice(&(self.vre_min_age_bands as u64).to_le_bytes());
        buf.extend_from_slice(&self.vre_age_band_width.to_le_bytes());
        buf.extend_from_slice(&self.vre_min_index_span_bps.to_le_bytes());
        buf.extend_from_slice(&self.vre_activation_height.to_le_bytes());
        buf.extend_from_slice(&self.epoch_length.to_le_bytes());
        buf.extend_from_slice(&self.initial_reward.to_le_bytes());
        buf.extend_from_slice(&self.emission_decay_constant.to_le_bytes());
        buf.extend_from_slice(&self.tail_emission.to_le_bytes());
        buf.extend_from_slice(&self.fee_burn_bps.to_le_bytes());
        buf.extend_from_slice(&(self.max_uncles as u64).to_le_bytes());
        buf.extend_from_slice(&self.max_uncle_depth.to_le_bytes());
        buf.extend_from_slice(&self.genesis_difficulty.to_le_bytes());
        buf.extend_from_slice(&self.difficulty_window.to_le_bytes());
        *hyphen_crypto::blake3_hash(&buf).as_bytes()
    }

    pub fn mainnet() -> Self {
        Self {
            network_name: "hyphen-mainnet".into(),
            network_magic: [0x48, 0x59, 0x50, 0x4E],
            block_time: Duration::from_secs(60),
            epoch_length: 2048,
            arena_size: 2 * 1024 * 1024 * 1024,
            scratchpad_size: 8 * 1024 * 1024,
            page_size: 4096,
            pow_rounds: 1024,
            writeback_interval: 32,
            kernel_count: 12,
            merkle_depth: 32,
            ring_size: 16,
            difficulty_window: 60,
            genesis_difficulty: 1_000_000,
            max_block_size: 2 * 1024 * 1024,
            initial_reward: 100_000_000_000_000,
            tail_emission: 600_000_000_000,
            fee_burn_bps: 5000,
            tail_emission_height: 0,
            emission_decay_constant: 1_048_576,
            max_uncles: 2,
            max_uncle_depth: 7,
            uncle_reward_numerator: 7,
            uncle_reward_denominator: 8,
            nephew_reward_numerator: 1,
            nephew_reward_denominator: 32,
            difficulty_clamp_up: 3,
            difficulty_clamp_down: 3,
            timestamp_future_limit_ms: 120_000,
            min_ring_span: 100,
            tera_epoch_tolerance: 2,
            vre_min_age_bands: 3,
            vre_age_band_width: 2048,
            vre_min_index_span_bps: 500,
            vre_activation_height: 128,
            mse_gamma: 100,
            mse_floor_bps: 8000,
            mse_ceil_bps: 12000,
            p2p_port: MAINNET_P2P_PORT,
            rpc_port: MAINNET_RPC_PORT,
            discovery_port: MAINNET_DISCOVERY_PORT,
        }
    }

    pub fn testnet() -> Self {
        Self {
            network_name: "hyphen-testnet".into(),
            network_magic: [0x48, 0x59, 0x54, 0x53],
            block_time: Duration::from_secs(30),
            epoch_length: 128,
            arena_size: 64 * 1024 * 1024,
            scratchpad_size: 256 * 1024,
            page_size: 4096,
            pow_rounds: 64,
            writeback_interval: 8,
            kernel_count: 12,
            merkle_depth: 32,
            ring_size: 4,
            difficulty_window: 30,
            genesis_difficulty: 1000,
            max_block_size: 2 * 1024 * 1024,
            initial_reward: 100_000_000_000_000,
            tail_emission: 600_000_000_000,
            fee_burn_bps: 5000,
            tail_emission_height: 0,
            emission_decay_constant: 4_096,
            max_uncles: 2,
            max_uncle_depth: 7,
            uncle_reward_numerator: 7,
            uncle_reward_denominator: 8,
            nephew_reward_numerator: 1,
            nephew_reward_denominator: 32,
            difficulty_clamp_up: 3,
            difficulty_clamp_down: 3,
            timestamp_future_limit_ms: 60_000,
            min_ring_span: 20,
            tera_epoch_tolerance: 4,
            vre_min_age_bands: 2,
            vre_age_band_width: 128,
            vre_min_index_span_bps: 300,
            vre_activation_height: 32,
            mse_gamma: 100,
            mse_floor_bps: 8000,
            mse_ceil_bps: 12000,
            p2p_port: TESTNET_P2P_PORT,
            rpc_port: TESTNET_RPC_PORT,
            discovery_port: TESTNET_DISCOVERY_PORT,
        }
    }
}
