use std::hint::black_box;
use std::time::Instant;

use curve25519_dalek::scalar::Scalar;
use hyphen_proof::{AggregatedRangeProof, batch::batch_verify_aggregated};

fn median_us(mut operation: impl FnMut()) -> u128 {
    let mut samples = [0; 11];
    for elapsed in &mut samples {
        let start = Instant::now();
        operation();
        *elapsed = start.elapsed().as_micros();
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn main() {
    println!("outputs,compact_proof_bytes,single_us,batch4_us,bad_first_us,bad_last_us");
    for n in [1, 2, 4, 8, 16] {
        let batch: Vec<_> = (0..4)
            .map(|i| {
                let values: Vec<_> = (0..n).map(|j| 100 + i * n + j).collect();
                let masks = values.iter().copied().map(Scalar::from).collect::<Vec<_>>();
                AggregatedRangeProof::prove(&values, &masks).unwrap()
            })
            .collect();
        let single = median_us(|| batch[0].0.verify(black_box(&batch[0].1)).unwrap());
        let bytes = hyphen_core::wire_config(100_000)
            .serialize(&batch[0].0)
            .unwrap()
            .len();
        let valid = median_us(|| batch_verify_aggregated(black_box(&batch)).unwrap());
        let failures = [0, 3].map(|i| {
            let mut changed = batch.clone();
            changed[i].1[0] = batch[(i + 1) % batch.len()].1[0];
            median_us(|| assert!(batch_verify_aggregated(black_box(&changed)).is_err()))
        });
        println!(
            "{n},{bytes},{single},{valid},{},{}",
            failures[0], failures[1]
        );
    }
}
