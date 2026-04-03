use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

use hyphen_crypto::clsag;
use hyphen_crypto::pedersen::{Commitment, PedersenGens};
use hyphen_crypto::stealth::{self, StealthAddress};
use hyphen_tx::builder::{InputSpec, TransactionBuilder};
use hyphen_tx::note::{Note, OwnedNote};

// Simulate the full: builder.build() -> serialize -> deserialize -> validator.verify() pipeline
// This test requires a full chain store to resolve all ring member global indices.
// The simpler e2e_build_verify_with_known_decoys and e2e_wallet_hex_roundtrip_verify
// tests below prove the core signing/verification pipeline correctness.
#[test]
#[ignore]
fn e2e_build_serialize_verify() {
    let gens = PedersenGens::default();
    let ring_size = 4usize;

    // Generate a "real" owned output (as if from a previous TX or coinbase)
    let real_sk = Scalar::random(&mut OsRng);
    let real_pk = real_sk * G;
    let real_value: u64 = 1_000_000;
    let real_blind = Scalar::random(&mut OsRng);
    let real_commit = gens.commit(Scalar::from(real_value), real_blind);

    let owned = OwnedNote {
        note: Note {
            commitment: Commitment::from_point(&real_commit),
            one_time_pubkey: real_pk.compress().to_bytes(),
            ephemeral_pubkey: [0u8; 32],
            encrypted_amount: [0u8; 32],
            global_index: 42,
            block_height: 10,
        },
        value: real_value,
        blinding: real_blind.to_bytes(),
        spend_sk: real_sk.to_bytes(),
    };

    // Generate decoys
    let mut decoys = Vec::new();
    for _ in 0..(ring_size - 1) {
        let dk = Scalar::random(&mut OsRng) * G;
        let db = Scalar::random(&mut OsRng);
        let dc = gens.commit(Scalar::from(500u64), db);
        decoys.push((dk, dc, rand::random::<u64>() % 1000));
    }

    let real_index = 2;

    // Generate recipient stealth address
    let (_, _, recipient_addr) = stealth::generate_keys();
    let (_, _, change_addr) = stealth::generate_keys();

    let fee = 100u64;
    let send_amount = 500_000u64;
    let change_amount = real_value - send_amount - fee;

    let mut builder = TransactionBuilder::new();
    builder.set_fee(fee);
    builder.set_epoch_seed(&[0xABu8; 32]);

    builder.add_input(InputSpec {
        owned,
        decoys,
        real_index,
    });
    builder.add_output(recipient_addr, send_amount);
    builder.add_output(change_addr, change_amount);

    let tx = builder.build().expect("build should succeed");

    // Verify balance
    assert!(tx.check_balance(), "balance check must pass");

    // Verify CLSAG — mimick what the validator does
    let msg = tx.prefix_hash();

    for (i, (input, sig)) in tx
        .inputs
        .iter()
        .zip(tx.prunable.clsag_signatures.iter())
        .enumerate()
    {
        // Resolve ring members — for the real output we know the global_index
        let mut ring_keys = Vec::new();
        let mut ring_commits = Vec::new();

        for oref in &input.ring {
            if oref.global_index == 42 {
                // Real output — use compressed->decompressed (same as chain store would do)
                let pk = curve25519_dalek::ristretto::CompressedRistretto::from_slice(
                    &real_pk.compress().to_bytes(),
                )
                .unwrap()
                .decompress()
                .unwrap();
                let cm = curve25519_dalek::ristretto::CompressedRistretto::from_slice(
                    &real_commit.compress().to_bytes(),
                )
                .unwrap()
                .decompress()
                .unwrap();
                ring_keys.push(pk);
                ring_commits.push(cm);
            } else {
                // For the test, we need to recover the decoy data from the OutputRef
                // In real validator, this comes from resolve_ring_member
                panic!(
                    "input {} references unknown global_index {} — test data mismatch",
                    i, oref.global_index
                );
            }
        }

        let pseudo_out = input.pseudo_output.to_point().expect("decompress pseudo_out");

        clsag::clsag_verify(msg.as_bytes(), &ring_keys, &ring_commits, &pseudo_out, sig)
            .unwrap_or_else(|e| panic!("CLSAG verify failed for input {i}: {e}"));

        assert_eq!(sig.key_image, input.key_image, "key image mismatch");
    }
}

// Test with known decoy global indices to exercise the full ring resolution path
#[test]
fn e2e_build_verify_with_known_decoys() {
    let gens = PedersenGens::default();
    let ring_size = 4usize;

    // Simulate a set of outputs that exist in the chain's output_index
    struct FakeOutput {
        pk: curve25519_dalek::ristretto::RistrettoPoint,
        commit: curve25519_dalek::ristretto::RistrettoPoint,
        global_index: u64,
    }

    let mut fake_outputs: Vec<FakeOutput> = Vec::new();
    for gi in 0..20u64 {
        let sk = Scalar::random(&mut OsRng);
        let pk = sk * G;
        let b = Scalar::random(&mut OsRng);
        let c = gens.commit(Scalar::from(1000u64 + gi), b);
        fake_outputs.push(FakeOutput {
            pk,
            commit: c,
            global_index: gi,
        });
    }

    // Pick output 5 as the "real" output to spend
    let real_idx_in_chain = 5usize;
    let real_sk = Scalar::random(&mut OsRng);
    let real_pk = real_sk * G;
    let real_value = 10_000u64;
    let real_blind = Scalar::random(&mut OsRng);
    let real_commit = gens.commit(Scalar::from(real_value), real_blind);
    fake_outputs[real_idx_in_chain] = FakeOutput {
        pk: real_pk,
        commit: real_commit,
        global_index: real_idx_in_chain as u64,
    };

    // Pick decoys from fake outputs
    let decoy_indices = [2u64, 10, 17];
    let decoys: Vec<(
        curve25519_dalek::ristretto::RistrettoPoint,
        curve25519_dalek::ristretto::RistrettoPoint,
        u64,
    )> = decoy_indices
        .iter()
        .map(|&gi| {
            let fo = &fake_outputs[gi as usize];
            (fo.pk, fo.commit, fo.global_index)
        })
        .collect();

    let real_pos_in_ring = 1; // position of real output in the ring

    let owned = OwnedNote {
        note: Note {
            commitment: Commitment::from_point(&real_commit),
            one_time_pubkey: real_pk.compress().to_bytes(),
            ephemeral_pubkey: [0u8; 32],
            encrypted_amount: [0u8; 32],
            global_index: real_idx_in_chain as u64,
            block_height: 3,
        },
        value: real_value,
        blinding: real_blind.to_bytes(),
        spend_sk: real_sk.to_bytes(),
    };

    let (_, _, recipient_addr) = stealth::generate_keys();
    let fee = 50u64;
    let send_amount = real_value - fee;

    let mut builder = TransactionBuilder::new();
    builder.set_fee(fee);
    builder.set_epoch_seed(&[0xCDu8; 32]);
    builder.add_input(InputSpec {
        owned,
        decoys,
        real_index: real_pos_in_ring,
    });
    builder.add_output(recipient_addr, send_amount);

    let tx = builder.build().expect("build should succeed");
    assert!(tx.check_balance(), "balance check must pass");

    // Verify CLSAG using the fake_outputs "store"
    let msg = tx.prefix_hash();

    for (i, (input, sig)) in tx
        .inputs
        .iter()
        .zip(tx.prunable.clsag_signatures.iter())
        .enumerate()
    {
        let mut ring_keys = Vec::new();
        let mut ring_commits = Vec::new();

        for oref in &input.ring {
            let fo = &fake_outputs[oref.global_index as usize];
            // Simulate compress/decompress round-trip (like resolve_ring_member)
            let pk_bytes = fo.pk.compress().to_bytes();
            let cm_bytes = fo.commit.compress().to_bytes();
            let pk = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&pk_bytes)
                .unwrap()
                .decompress()
                .unwrap();
            let cm = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&cm_bytes)
                .unwrap()
                .decompress()
                .unwrap();
            ring_keys.push(pk);
            ring_commits.push(cm);
        }

        let pseudo_out = input.pseudo_output.to_point().expect("decompress pseudo_out");

        clsag::clsag_verify(msg.as_bytes(), &ring_keys, &ring_commits, &pseudo_out, sig)
            .unwrap_or_else(|e| panic!("CLSAG verify failed for input {i}: {e}"));

        assert_eq!(sig.key_image, input.key_image, "key image mismatch");
    }
}

// Simulate the wallet's exact data flow: hex-encode/decode blinding + spend_sk
#[test]
fn e2e_wallet_hex_roundtrip_verify() {
    let gens = PedersenGens::default();

    // Step 1: Simulate scanning — create output with stealth keys
    let (view_key, spend_key, addr) = stealth::generate_keys();
    let output_index = 0u64;
    let value = 5_000_000u64;

    let (eph, one_time_pk, ss) = stealth::derive_one_time_key(&addr, output_index).unwrap();

    let blinding = stealth::derive_commitment_blinding(&ss);
    let commitment = gens.commit(Scalar::from(value), blinding);
    let one_time_sk = ss + spend_key.as_scalar();

    // Verify: one_time_sk * G == one_time_pk
    assert_eq!(
        one_time_sk * G,
        one_time_pk,
        "one-time key derivation must be consistent"
    );

    // Simulate wallet storage (hex encoding, like WalletOutput)
    let blinding_hex = hex::encode(blinding.to_bytes());
    let spend_sk_hex = hex::encode(one_time_sk.to_bytes());
    let otp_hex = hex::encode(one_time_pk.compress().to_bytes());
    let cm_hex = hex::encode(Commitment::from_point(&commitment).as_bytes());

    // Step 2: Simulate transfer — reconstruct from hex (like transfer.rs does)
    let blinding_bytes: Vec<u8> = hex::decode(&blinding_hex).unwrap();
    let spend_sk_bytes: Vec<u8> = hex::decode(&spend_sk_hex).unwrap();
    let otp_bytes: Vec<u8> = hex::decode(&otp_hex).unwrap();
    let cm_bytes: Vec<u8> = hex::decode(&cm_hex).unwrap();

    let mut bl = [0u8; 32];
    bl.copy_from_slice(&blinding_bytes);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&spend_sk_bytes);
    let mut otp = [0u8; 32];
    otp.copy_from_slice(&otp_bytes);
    let mut cm = [0u8; 32];
    cm.copy_from_slice(&cm_bytes);

    let owned = OwnedNote {
        note: Note {
            commitment: Commitment(cm),
            one_time_pubkey: otp,
            ephemeral_pubkey: [0u8; 32],
            encrypted_amount: [0u8; 32],
            global_index: 100,
            block_height: 50,
        },
        value,
        blinding: bl,
        spend_sk: sk,
    };

    // Verify reconstructed spend_sk produces the same public key
    let reconstructed_sk = owned.spend_scalar();
    let reconstructed_pk = reconstructed_sk * G;
    let stored_pk = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&otp)
        .unwrap()
        .decompress()
        .unwrap();
    assert_eq!(reconstructed_pk, stored_pk, "spend key reconstruction failed");

    // Verify reconstructed blinding matches commitment
    let reconstructed_blind = owned.blinding_scalar();
    let reconstructed_commit = gens.commit(Scalar::from(value), reconstructed_blind);
    let stored_commit = owned.note.commitment.to_point().unwrap();
    assert_eq!(
        reconstructed_commit, stored_commit,
        "commitment reconstruction failed"
    );

    // Step 3: Build transaction with these reconstructed values
    let decoys: Vec<(
        curve25519_dalek::ristretto::RistrettoPoint,
        curve25519_dalek::ristretto::RistrettoPoint,
        u64,
    )> = (0..3)
        .map(|_| {
            let dk = Scalar::random(&mut OsRng) * G;
            let db = Scalar::random(&mut OsRng);
            let dc = gens.commit(Scalar::from(999u64), db);
            (dk, dc, rand::random::<u64>() % 1000 + 200)
        })
        .collect();

    let real_index = 0;
    let (_, _, recipient_addr) = stealth::generate_keys();
    let fee = 100u64;
    let send_amount = value - fee;

    let mut builder = TransactionBuilder::new();
    builder.set_fee(fee);
    builder.set_epoch_seed(&[0x77u8; 32]);
    builder.add_input(InputSpec {
        owned,
        decoys: decoys.clone(),
        real_index,
    });
    builder.add_output(recipient_addr, send_amount);

    let tx = builder.build().expect("build must succeed");
    assert!(tx.check_balance(), "balance check must pass");

    // Step 4: Serialize/Deserialize round-trip (like RPC transmission)
    let tx_bytes = tx.serialise();
    let tx2: hyphen_tx::transaction::Transaction =
        bincode::deserialize(&tx_bytes).expect("deserialize must succeed");

    // Step 5: Verify CLSAG on the deserialized transaction
    let msg = tx2.prefix_hash();

    for (i, (input, sig)) in tx2
        .inputs
        .iter()
        .zip(tx2.prunable.clsag_signatures.iter())
        .enumerate()
    {
        let mut ring_keys = Vec::new();
        let mut ring_commits = Vec::new();

        for oref in &input.ring {
            if oref.global_index == 100 {
                // Simulate chain looking up the STORED bytes
                // (stored_pk and stored_commit from the output_index)
                let pk = stored_pk;
                let cm = stored_commit;
                ring_keys.push(pk);
                ring_commits.push(cm);
            } else {
                // Find the decoy by global index
                let dinfo = decoys
                    .iter()
                    .find(|(_, _, gi)| *gi == oref.global_index)
                    .expect("decoy not found");
                // Simulate compress/decompress (as chain store does)
                let pk = curve25519_dalek::ristretto::CompressedRistretto::from_slice(
                    &dinfo.0.compress().to_bytes(),
                )
                .unwrap()
                .decompress()
                .unwrap();
                let cm = curve25519_dalek::ristretto::CompressedRistretto::from_slice(
                    &dinfo.1.compress().to_bytes(),
                )
                .unwrap()
                .decompress()
                .unwrap();
                ring_keys.push(pk);
                ring_commits.push(cm);
            }
        }

        let pseudo_out = input.pseudo_output.to_point().expect("decompress pseudo_out");

        clsag::clsag_verify(msg.as_bytes(), &ring_keys, &ring_commits, &pseudo_out, sig)
            .unwrap_or_else(|e| panic!("CLSAG verify failed for input {i}: {e}"));

        assert_eq!(sig.key_image, input.key_image, "key image mismatch");
    }
}
