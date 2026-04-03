use curve25519_dalek::scalar::Scalar;
use hyphen_crypto::pedersen::{Commitment, PedersenGens, G_VALUE};

#[test]
fn balance_check_manual() {
    let gens = PedersenGens::default();
    let v_in: u64 = 100_000_000_000_000;
    let v_out: u64 = 50_000_000_000_000;
    let fee: u64 = 100_000_000;
    let change = v_in - v_out - fee;

    let b_out1 = Scalar::random(&mut rand::rngs::OsRng);
    let b_out2 = Scalar::random(&mut rand::rngs::OsRng);
    let b_pseudo = b_out1 + b_out2;

    let pseudo = gens.commit(Scalar::from(v_in), b_pseudo);
    let out1 = gens.commit(Scalar::from(v_out), b_out1);
    let out2 = gens.commit(Scalar::from(change), b_out2);

    let fee_point = Scalar::from(fee) * *G_VALUE;
    assert_eq!(pseudo, out1 + out2 + fee_point, "balance equation failed");
}

#[test]
fn balance_check_via_check_balance() {
    use hyphen_proof::range_proof::AggregatedRangeProof;
    use hyphen_tx::transaction::*;

    let gens = PedersenGens::default();
    let v_in: u64 = 1_000;
    let fee: u64 = 10;
    let v_out = v_in - fee;

    let b_out = Scalar::random(&mut rand::rngs::OsRng);
    let b_pseudo = b_out;

    let pseudo_commit = gens.commit(Scalar::from(v_in), b_pseudo);
    let out_commit = gens.commit(Scalar::from(v_out), b_out);

    let (range_proof, _) = AggregatedRangeProof::prove(&[v_out], &[b_out]).unwrap();

    let tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            ring: vec![],
            key_image: [0u8; 32],
            pseudo_output: Commitment::from_point(&pseudo_commit),
            epoch_context: [0u8; 32],
            temporal_nonce: [0u8; 32],
            causal_binding: [0u8; 32],
        }],
        outputs: vec![TxOutput {
            commitment: Commitment::from_point(&out_commit),
            one_time_pubkey: [0u8; 32],
            ephemeral_pubkey: [0u8; 32],
            encrypted_amount: [0u8; 32],
            view_tag: 0,
        }],
        fee,
        extra: vec![],
        prunable: TxPrunable {
            clsag_signatures: vec![],
            range_proof,
        },
    };

    assert!(tx.check_balance(), "check_balance should pass");
}
