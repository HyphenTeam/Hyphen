use std::hint::black_box;
use std::time::Instant;

use hyphen_consensus::neural_work::{NEURAL_WORK_INITIAL_THRESHOLD, NEURAL_WORK_SPEC, work_seed};
use hyphen_crypto::Hash256;
use hyphen_neural::WorkDescriptor;

fn main() {
    println!("profile,sample,attempts,found,setup_ns,search_ns,verify_ns");
    for sample in 0..32u64 {
        for length in [3, 4] {
            let start = Instant::now();
            let result = hyphen_pow::search(&hyphen_pow::SearchParams {
                length,
                offset: 1_000_000_001 + sample * 4_000_000,
                stride: 2,
                count: 1,
                max_candidates: 2_000_000,
                is_claimed: &|_| false,
            })
            .unwrap();
            let search_ns = start.elapsed().as_nanos();
            let start = Instant::now();
            if !result.witnesses.is_empty() {
                hyphen_pow::verify_witnesses(black_box(&result.witnesses), length, 1).unwrap();
            }
            let verify_ns = start.elapsed().as_nanos();
            println!(
                "ordinary-{length},{sample},{},{},0,{search_ns},{verify_ns}",
                result.candidates_tested,
                result.witnesses.len()
            );
        }
        let start = Instant::now();
        let parent = hyphen_crypto::blake3_hash(&sample.to_le_bytes());
        let seed = work_seed(&parent, sample + 1, Hash256::ZERO.as_bytes());
        let descriptor = WorkDescriptor {
            spec: NEURAL_WORK_SPEC,
            epoch: sample + 1,
            threshold: NEURAL_WORK_INITIAL_THRESHOLD,
            chain_seed: *seed.as_bytes(),
        };
        let mut weights = vec![0; descriptor.spec.weight_count()];
        let mut solution = vec![0; usize::from(descriptor.spec.input_dim)];
        let mut scratch = solution.clone();
        let mut hidden = vec![0; usize::from(descriptor.spec.hidden_dim)];
        let mut output = vec![0; usize::from(descriptor.spec.output_dim)];
        descriptor.derive_weights(&mut weights).unwrap();
        let setup_ns = start.elapsed().as_nanos();
        let start = Instant::now();
        let result = hyphen_neural::search_work(
            &descriptor,
            &weights,
            0,
            1,
            1_000_000,
            &mut solution,
            &mut hidden,
            &mut output,
            &mut scratch,
        )
        .unwrap();
        let search_ns = start.elapsed().as_nanos();
        let start = Instant::now();
        if result.found {
            descriptor.derive_weights(&mut weights).unwrap();
            assert!(
                descriptor
                    .verify(&weights, black_box(&solution), &mut hidden, &mut output)
                    .unwrap()
            );
        }
        let verify_ns = start.elapsed().as_nanos();
        println!(
            "neural,{sample},{},{},{setup_ns},{search_ns},{verify_ns}",
            result.attempts,
            u8::from(result.found)
        );
    }
}
