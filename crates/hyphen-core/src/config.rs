use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::authorization::FROZEN_BLOCK_VERSION;

pub const MAINNET_P2P_PORT: u16 = 18334;
pub const MAINNET_RPC_PORT: u16 = 18333;
pub const MAINNET_DISCOVERY_PORT: u16 = 20333;
pub const TESTNET_RPC_PORT: u16 = 38333;
pub const TESTNET_P2P_PORT: u16 = 38334;
pub const TESTNET_DISCOVERY_PORT: u16 = 20334;
pub const DEVNET_RPC_PORT: u16 = 48333;
pub const DEVNET_P2P_PORT: u16 = 48334;
pub const DEVNET_DISCOVERY_PORT: u16 = 20335;
pub const DEFAULT_TEMPLATE_PORT: u16 = 3350;
pub const DEFAULT_POOL_PORT: u16 = 3340;
pub const DEFAULT_STRATUM_PORT: u16 = 3333;
pub const DEFAULT_EXPLORER_PORT: u16 = 8080;
pub const DEFAULT_SEED_DOMAIN: &str = "bytesnap.tech";

/// Consensus launch timestamp shared by every node, in Unix milliseconds.
///
/// A genesis timestamp must never depend on the local clock: doing so creates
/// a different chain for every fresh database.
pub const GENESIS_TIMESTAMP_MS: u64 = 1_767_225_600_000; // 2026-01-01T00:00:00Z

pub const FEATURE_UNCLES: u32 = 1 << 0;
pub const FEATURE_TERA: u32 = 1 << 1;
pub const FEATURE_VRE: u32 = 1 << 2;
pub const FEATURE_MSE: u32 = 1 << 3;
pub const FEATURE_CANONICAL_TX_ORDER: u32 = 1 << 4;
pub const FEATURE_USEFUL_WORK: u32 = 1 << 5;
pub const FEATURE_WASM: u32 = 1 << 6;
pub const FEATURE_H_WES: u32 = 1 << 7;
pub const RESEARCH_CONSENSUS_FEATURES: u32 = FEATURE_UNCLES
    | FEATURE_TERA
    | FEATURE_VRE
    | FEATURE_MSE
    | FEATURE_CANONICAL_TX_ORDER
    | FEATURE_USEFUL_WORK
    | FEATURE_WASM
    | FEATURE_H_WES;
/// Version 2 replaces node-local random coinbase construction with a
/// deterministic, block-bound state transition.
pub const STATE_TRANSITION_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum DifficultyAlgorithm {
    /// Frozen, integer-only linear weighted moving average.
    LwmaV1 = 1,
    /// Experimental momentum/SPRT controller retained for research networks.
    MdadSprResearchV1 = 2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainConfig {
    pub network_name: String,
    pub network_magic: [u8; 4],
    pub consensus_features: u32,
    pub difficulty_algorithm: DifficultyAlgorithm,
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
    pub fn feature_enabled(&self, feature: u32) -> bool {
        self.consensus_features & feature != 0
    }

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
        buf.extend_from_slice(b"HyphenConsensusParams/v6-scientific-pouw-v1");
        buf.extend_from_slice(&STATE_TRANSITION_VERSION.to_le_bytes());
        buf.extend_from_slice(&FROZEN_BLOCK_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.network_magic);
        buf.extend_from_slice(&self.consensus_features.to_le_bytes());
        buf.push(self.difficulty_algorithm as u8);
        buf.extend_from_slice(&self.block_time_ms().to_le_bytes());
        buf.extend_from_slice(&self.epoch_length.to_le_bytes());
        buf.extend_from_slice(&(self.arena_size as u64).to_le_bytes());
        buf.extend_from_slice(&(self.scratchpad_size as u64).to_le_bytes());
        buf.extend_from_slice(&(self.page_size as u64).to_le_bytes());
        buf.extend_from_slice(&self.pow_rounds.to_le_bytes());
        buf.extend_from_slice(&self.writeback_interval.to_le_bytes());
        buf.push(self.kernel_count);
        buf.extend_from_slice(&(self.merkle_depth as u64).to_le_bytes());
        buf.extend_from_slice(&(self.ring_size as u64).to_le_bytes());
        buf.extend_from_slice(&self.difficulty_window.to_le_bytes());
        buf.extend_from_slice(&self.genesis_difficulty.to_le_bytes());
        buf.extend_from_slice(&(self.max_block_size as u64).to_le_bytes());
        buf.extend_from_slice(&self.initial_reward.to_le_bytes());
        buf.extend_from_slice(&self.tail_emission.to_le_bytes());
        buf.extend_from_slice(&self.fee_burn_bps.to_le_bytes());
        buf.extend_from_slice(&self.tail_emission_height.to_le_bytes());
        buf.extend_from_slice(&self.emission_decay_constant.to_le_bytes());
        buf.extend_from_slice(&(self.max_uncles as u64).to_le_bytes());
        buf.extend_from_slice(&self.max_uncle_depth.to_le_bytes());
        buf.extend_from_slice(&self.uncle_reward_numerator.to_le_bytes());
        buf.extend_from_slice(&self.uncle_reward_denominator.to_le_bytes());
        buf.extend_from_slice(&self.nephew_reward_numerator.to_le_bytes());
        buf.extend_from_slice(&self.nephew_reward_denominator.to_le_bytes());
        buf.extend_from_slice(&self.difficulty_clamp_up.to_le_bytes());
        buf.extend_from_slice(&self.difficulty_clamp_down.to_le_bytes());
        buf.extend_from_slice(&self.timestamp_future_limit_ms.to_le_bytes());
        buf.extend_from_slice(&self.min_ring_span.to_le_bytes());
        buf.extend_from_slice(&self.tera_epoch_tolerance.to_le_bytes());
        buf.extend_from_slice(&(self.vre_min_age_bands as u64).to_le_bytes());
        buf.extend_from_slice(&self.vre_age_band_width.to_le_bytes());
        buf.extend_from_slice(&self.vre_min_index_span_bps.to_le_bytes());
        buf.extend_from_slice(&self.vre_activation_height.to_le_bytes());
        buf.extend_from_slice(&self.mse_gamma.to_le_bytes());
        buf.extend_from_slice(&self.mse_floor_bps.to_le_bytes());
        buf.extend_from_slice(&self.mse_ceil_bps.to_le_bytes());
        buf.extend_from_slice(&GENESIS_TIMESTAMP_MS.to_le_bytes());
        *hyphen_crypto::blake3_hash(&buf).as_bytes()
    }

    pub fn mainnet() -> Self {
        Self {
            network_name: "hyphen-mainnet".into(),
            network_magic: [0x48, 0x59, 0x50, 0x4E],
            consensus_features: RESEARCH_CONSENSUS_FEATURES,
            difficulty_algorithm: DifficultyAlgorithm::MdadSprResearchV1,
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
            // PoUW v1 difficulty is the exact number of Q12 diffusion steps.
            genesis_difficulty: 384,
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
            consensus_features: RESEARCH_CONSENSUS_FEATURES,
            difficulty_algorithm: DifficultyAlgorithm::MdadSprResearchV1,
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
            genesis_difficulty: 192,
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

    /// Development network v2 used for reproducible consensus testing.
    ///
    /// Unreviewed research mechanisms are disabled. Any future activation
    /// requires a new profile, test vectors and therefore a new chain ID.
    pub fn devnet() -> Self {
        Self {
            network_name: "hyphen-devnet-v2".into(),
            network_magic: [0x48, 0x59, 0x44, 0x56],
            consensus_features: 0,
            difficulty_algorithm: DifficultyAlgorithm::LwmaV1,
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
            genesis_difficulty: 64,
            max_block_size: 2 * 1024 * 1024,
            initial_reward: 100_000_000_000_000,
            tail_emission: 600_000_000_000,
            fee_burn_bps: 5_000,
            tail_emission_height: 0,
            emission_decay_constant: 4_096,
            max_uncles: 0,
            max_uncle_depth: 0,
            uncle_reward_numerator: 0,
            uncle_reward_denominator: 1,
            nephew_reward_numerator: 0,
            nephew_reward_denominator: 1,
            difficulty_clamp_up: 3,
            difficulty_clamp_down: 3,
            timestamp_future_limit_ms: 60_000,
            min_ring_span: 0,
            tera_epoch_tolerance: 0,
            vre_min_age_bands: 0,
            vre_age_band_width: 0,
            vre_min_index_span_bps: 0,
            vre_activation_height: u64::MAX,
            mse_gamma: 0,
            mse_floor_bps: 10_000,
            mse_ceil_bps: 10_000,
            p2p_port: DEVNET_P2P_PORT,
            rpc_port: DEVNET_RPC_PORT,
            discovery_port: DEVNET_DISCOVERY_PORT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_devnet_disables_research_consensus_features() {
        let cfg = ChainConfig::devnet();
        assert_eq!(cfg.consensus_features, 0);
        assert_eq!(cfg.difficulty_algorithm, DifficultyAlgorithm::LwmaV1);
        assert_eq!(cfg.max_uncles, 0);
        assert_eq!(cfg.vre_activation_height, u64::MAX);
        assert_eq!(cfg.mse_floor_bps, 10_000);
        assert_eq!(cfg.mse_ceil_bps, 10_000);
    }

    #[test]
    fn consensus_profile_changes_chain_identity() {
        let frozen = ChainConfig::devnet();
        let mut research = frozen.clone();
        research.consensus_features = FEATURE_VRE;
        assert_ne!(
            frozen.consensus_params_hash(),
            research.consensus_params_hash()
        );
    }
}
