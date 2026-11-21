use std::time::Instant;

use hyphen_core::ChainConfig;
use hyphen_neural::{PROFILE_SPEC, WorkDescriptor, block_work};

fn main() {
    let threshold = ChainConfig::neural_devnet().neural_work_initial_threshold;
    println!("sample,seed,nonces,memory_evaluations,accepted,setup_ns,search_ns,verify_ns");
    for sample in 0..16_u64 {
        let start = Instant::now();
        let parent = hyphen_crypto::blake3_hash(&sample.to_le_bytes());
        let seed = hyphen_core::neural_work_seed(&parent, sample + 1, &[1; 32]);
        let descriptor = WorkDescriptor {
            spec: PROFILE_SPEC,
            epoch: sample + 1,
            threshold,
            chain_seed: *seed.as_bytes(),
        };
        let mut weights = vec![0; PROFILE_SPEC.weight_count()];
        descriptor.derive_weights(&mut weights).unwrap();
        let setup_ns = start.elapsed().as_nanos();
        let start = Instant::now();
        let mut finalists = 0;
        let mut winners = Vec::new();
        for nonce in 0..1024 {
            let score = block_work::nonce_score(&descriptor, &weights, nonce).unwrap();
            let gate = block_work::gate_digest(&descriptor.chain_seed, nonce, score);
            if block_work::low_word(&gate) >= block_work::NEURAL_GATE {
                continue;
            }
            finalists += 1;
            if block_work::low_word(&block_work::memory_digest(gate)) < threshold {
                winners.push(nonce);
            }
        }
        let search_ns = start.elapsed().as_nanos();
        let start = Instant::now();
        for &nonce in &winners {
            assert!(block_work::verify_nonce(&descriptor, nonce).unwrap());
        }
        let verify_ns = start.elapsed().as_nanos();
        println!(
            "{sample},{seed},1024,{finalists},{},{setup_ns},{search_ns},{verify_ns}",
            winners.len()
        );
    }
}
