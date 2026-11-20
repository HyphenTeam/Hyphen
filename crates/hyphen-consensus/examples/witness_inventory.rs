//! Offline measurements. Time in controller and inventory scenarios is simulated.
use hyphen_core::ChainConfig;
use hyphen_core::config::DifficultyAlgorithm;
use hyphen_pow::{MAX_WITNESSES_PER_BLOCK, chain_is_valid, next_difficulty};
use serde_json::{Value, json};

fn quantiles(values: &[u64]) -> [u64; 3] {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    [50, 95, 99].map(|p| sorted[(p * sorted.len()).div_ceil(100) - 1])
}

// Sample odd origins uniformly with replacement. The valid odd-origin space
// is a power of two if the single excluded origin 1 is included as a miss.
fn next_random(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn capacity(length: u32) -> Value {
    let slots = 1_u64 << (64 - length);
    let draws = 8_000_000_u64;
    let mut seed = 20261120;
    let mut hits = 0;
    for _ in 0..draws {
        let origin = 2 * (next_random(&mut seed) & (slots - 1)) + 1;
        hits += u64::from(chain_is_valid(origin, length));
    }
    let p = hits as f64 / draws as f64;
    let n = draws as f64;
    let z2 = 1.96_f64.powi(2);
    let center = p + z2 / (2.0 * n);
    let margin = 1.96 * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    let factor = slots as f64 / (1.0 + z2 / n);
    let bands = [3, 1_u64 << 24, 1_u64 << 40, 1_u64 << 58].map(|start| {
        let first = start | 1;
        let count = (0..1_000_000)
            .filter(|i| chain_is_valid(first + i * 2, length))
            .count();
        json!({"first":first,"odd_candidates":1_000_000,"hits":count})
    });
    // Two miners sample uniformly without replacement within the same known
    // low-origin region. Count overlap; neither miner sees the other's set.
    let population = bands[0]["hits"].as_u64().unwrap();
    let mut collision_total = 0;
    for _ in 0..1024 {
        let mut draw = || {
            let mut chosen = std::collections::BTreeSet::new();
            while chosen.len() < 64 {
                let v = next_random(&mut seed);
                if v < u64::MAX - u64::MAX % population {
                    chosen.insert(v % population);
                }
            }
            chosen
        };
        collision_total += draw().intersection(&draw()).count();
    }
    json!({"length":length,"odd_slots":slots,"draws":draws,"hits":hits,"estimated_origins":slots as f64*p,
        "wilson_95":[factor*(center-margin),factor*(center+margin)],"local_census":bands,
        "first_band_two_miners_64_each_mean_overlap":collision_total as f64 / 1024.0})
}

fn inventories() -> (Vec<u64>, Vec<Value>) {
    // Measure exact costs for the same sequence of 512 origins once. Apply
    // alternative release schedules to this paired trace, with no network I/O.
    let mut origin = 1_000_001;
    let mut costs = Vec::new();
    let mut origins = Vec::new();
    for _ in 0..64 {
        let mut attempts = 0;
        for _ in 0..8 {
            loop {
                attempts += 1;
                let candidate = origin;
                origin += 2;
                if chain_is_valid(candidate, 4) {
                    origins.push(candidate);
                    break;
                }
            }
        }
        costs.push(attempts);
    }
    let total: u64 = costs.iter().sum();
    let schedules = ["live", "prelaunch", "withhold", "sibling"].map(|schedule| {
        let mut intervals = Vec::new();
        let mut after_parent = 0;
        // The withheld second half is discovered while the parent of block 33
        // is current. Its first interval pays for the entire discovery batch.
        for (i, &cost) in costs.iter().enumerate() {
            let newly_searched = match schedule {
                "prelaunch" | "sibling" => 0,
                "withhold" if i == 32 => costs[32..].iter().sum(),
                "withhold" if i > 32 => 0,
                _ => cost,
            };
            after_parent += newly_searched;
            intervals.push(1 + newly_searched); // one candidate/ms, one ms publication
        }
        json!({"schedule":schedule,"validated_count_weight":512,"linear_index_payload_bytes":512*16,
            "prior_candidate_tests":total-after_parent,"phase_candidate_tests":after_parent,
            "zero_search_blocks":intervals.iter().filter(|&&v|v==1).count(),"interval_ms_p50_p95_p99":quantiles(&intervals),
            "max_interval_ms":intervals.iter().max(),"elapsed_ms":intervals.iter().sum::<u64>(),"intervals_ms":intervals,
            "same_512_origins_as_other_branch":schedule=="sibling"})
    }).to_vec();
    (origins, schedules)
}

fn controller(algorithm: DifficultyAlgorithm, scenario: &str) -> Value {
    let mut cfg = ChainConfig::mainnet();
    cfg.difficulty_algorithm = algorithm;
    let target = cfg.block_time_ms();
    let window = cfg.difficulty_window as usize;
    // Start with a mature steady-state window. D=80 leaves resolution at 10%.
    let mut timestamps: Vec<u64> = (0..window as u64).map(|i| i * target).collect();
    let mut difficulties = vec![80; window];
    let mut stock: u64 = if scenario == "release" { 1600 } else { 0 };
    let mut recovery_start = 0;
    let mut stable = 0;
    let mut recovery = None;
    let mut weight = 0;
    let mut fresh = 0;
    let mut intervals = Vec::new();
    let mut max_error = 0;
    let mut peer_cfg = cfg.clone();
    peer_cfg.difficulty_algorithm = match algorithm {
        DifficultyAlgorithm::LwmaV1 => DifficultyAlgorithm::MomentumDampedLwmaV2,
        DifficultyAlgorithm::MomentumDampedLwmaV2 => DifficultyAlgorithm::LwmaV1,
    };
    let mut equal_input_max_difference = 0;
    let mut equal_input_different_blocks = 0;
    let mut alternate_counts = Vec::new();
    for block in 0..360 {
        let index = timestamps.len() - window;
        let d = next_difficulty(&timestamps[index..], &difficulties[index..], &cfg)
            .clamp(1, MAX_WITNESSES_PER_BLOCK);
        let peer = next_difficulty(&timestamps[index..], &difficulties[index..], &peer_cfg)
            .clamp(1, MAX_WITNESSES_PER_BLOCK);
        alternate_counts.push(peer);
        equal_input_max_difference = equal_input_max_difference.max(d.abs_diff(peer));
        equal_input_different_blocks += u64::from(d != peer);
        let rate = match scenario {
            "loss" => 8,
            "surge" if block < 12 => 800,
            _ => 80,
        };
        let used = stock.min(d);
        stock -= used;
        let interval = ((d - used) * target / rate).max(1);
        let end = timestamps.last().unwrap() + interval;
        timestamps.push(end);
        difficulties.push(d);
        intervals.push(interval);
        max_error = max_error.max(d.abs_diff(rate));
        fresh += d - used;
        weight += d;
        if used > 0 || (scenario == "surge" && block < 12) {
            recovery_start = intervals.len();
        } else if (target * 9 / 10..=target * 11 / 10).contains(&interval) {
            stable += 1;
            if stable == 6 && recovery.is_none() {
                recovery = Some(
                    json!({"blocks":intervals.len()-recovery_start,"elapsed_ms":intervals[recovery_start..].iter().sum::<u64>()}),
                );
            }
        } else {
            stable = 0;
        }
    }
    json!({"algorithm":format!("{algorithm:?}"),"scenario":scenario,"blocks":360,"validated_weight":weight,
        "intervals_ms":intervals,"required_counts":difficulties[window..],"alternate_counts_same_parent_history":alternate_counts,
        "same_history_max_controller_difference":equal_input_max_difference,"same_history_different_blocks":equal_input_different_blocks,
        "fresh_witness_equivalents":fresh,"recovery":recovery,"max_abs_difficulty_minus_equilibrium":max_error,
        "interval_ms_p50_p95_p99":quantiles(&intervals),"elapsed_ms":intervals.iter().sum::<u64>()})
}

fn main() {
    let mut controllers = Vec::new();
    let (origins, schedules) = inventories();
    for algorithm in [
        DifficultyAlgorithm::LwmaV1,
        DifficultyAlgorithm::MomentumDampedLwmaV2,
    ] {
        for scenario in ["steady", "loss", "surge", "release"] {
            controllers.push(controller(algorithm, scenario));
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":1,"origin_sequence":origins,"inventory":schedules,
        "controller":controllers,"capacity":[capacity(3),capacity(4)]})
        )
        .unwrap()
    );
}
