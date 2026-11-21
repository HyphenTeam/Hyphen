use super::*;
use hyphen_core::{
    Block, BlockAuthorization, BlockHeader, authorization::reward_commitment,
    neural_work_commitment, neural_work_seed,
};
use hyphen_crypto::{Hash256, SecretKey, StealthAddress};
use hyphen_neural::{PROFILE_SPEC, WorkDescriptor, block_work};
use hyphen_tx::{
    Transaction, TransactionBuilder, builder::InputSpec, note::OwnedNote, transaction::TxOutput,
};
use hyphen_wallet::Wallet;
use std::collections::BTreeSet;

struct Network {
    chain: Arc<Blockchain>,
    pool: Arc<RwLock<Mempool>>,
    reward: StealthAddress,
}

impl Network {
    fn confirm(&self) -> Block {
        let cfg = &self.chain.cfg;
        let template = build_template(&self.chain, &self.pool, cfg).unwrap();
        let wire = wire_config(cfg.max_block_size);
        let mut header: BlockHeader = wire.deserialize(&template.header_data).unwrap();
        let miner = SecretKey([91; 32]);
        header.miner_pubkey = miner.public_key().0;
        header.extra_nonce = reward_commitment(&self.reward.view_public, &self.reward.spend_public);
        let work = WorkDescriptor {
            spec: PROFILE_SPEC,
            epoch: header.height,
            threshold: header.difficulty,
            chain_seed: neural_work_seed(&header.prev_hash, header.height, &header.miner_pubkey).0,
        };
        let mut weights = [0; PROFILE_SPEC.weight_count()];
        work.derive_weights(&mut weights).unwrap();
        let nonce = (0..u64::MAX)
            .find(|&n| {
                let score = block_work::nonce_score(&work, &weights, n).unwrap();
                block_work::qualifies(&work, n, score).unwrap()
            })
            .unwrap();
        header.pow_commitment = neural_work_commitment(
            &header.prev_hash,
            header.height,
            header.difficulty,
            &header.miner_pubkey,
            &[nonce],
        );
        let auth = BlockAuthorization::sign(
            &header,
            cfg.network_magic,
            cfg.consensus_params_hash(),
            self.chain.chain_id(),
            self.reward.view_public,
            self.reward.spend_public,
            &miner,
        )
        .unwrap();
        let block = Block {
            header,
            pow_witnesses: vec![nonce],
            transactions: template.transactions,
            uncle_headers: vec![],
            block_authorization: wire.serialize(&auth).unwrap(),
        };
        let bytes = wire.serialize(&block).unwrap();
        let (events, _) = tokio::sync::watch::channel(None);
        let result = handle_block_submission(&bytes, &self.chain, &self.pool, &events);
        assert!(result.accepted, "{}", result.error);
        block
    }

    fn transfer(
        &self,
        notes: &[OwnedNote],
        recipient: StealthAddress,
        outputs: usize,
    ) -> BTreeSet<Hash256> {
        let decoys: Vec<_> = (0..4)
            .map(|i| {
                let (pk, cm, _) = self.chain.blocks.resolve_ring_member(i).unwrap();
                (pk, cm, i)
            })
            .collect();
        let workers = std::thread::available_parallelism().unwrap().get().min(8);
        std::thread::scope(|scope| {
            let handles: Vec<_> = notes
                .chunks(notes.len().div_ceil(workers))
                .map(|chunk| {
                    let decoys = &decoys;
                    scope.spawn(move || {
                        chunk
                            .iter()
                            .map(|note| {
                                let mut builder = TransactionBuilder::new();
                                builder.add_input(InputSpec {
                                    owned: note.clone(),
                                    real_index: 0,
                                    decoys: decoys
                                        .iter()
                                        .copied()
                                        .filter(|d| d.2 != note.note.global_index)
                                        .take(3)
                                        .collect(),
                                });
                                let amount = note.value - FEE;
                                for i in 0..outputs {
                                    builder.add_output(
                                        recipient,
                                        amount / outputs as u64
                                            + u64::from((i as u64) < amount % outputs as u64),
                                    );
                                }
                                builder.set_fee(FEE);
                                let bytes = builder.build().unwrap().serialise();
                                hyphen_rpc::admission::admit_transaction(
                                    &self.chain,
                                    &self.pool,
                                    bytes,
                                    ntp_adjusted_timestamp_ms(),
                                )
                                .unwrap()
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect()
        })
    }
}

const FEE: u64 = 1_000_000;

#[test]
fn template_budget_covers_signed_wire_framing() {
    let cfg = ChainConfig::neural_devnet();
    let wire = wire_config(cfg.max_block_size);
    for len in [0, 250, 251, 65_535, 65_536, 1_000_000] {
        assert_eq!(
            framed_blob_size(len) as u64,
            wire.serialized_size(&vec![0u8; len]).unwrap()
        );
    }
    let mut block = build_genesis_block(&cfg);
    let h = &mut block.header;
    h.height = u64::MAX;
    h.timestamp = u64::MAX;
    h.difficulty = u64::MAX;
    h.nonce = u64::MAX;
    h.total_fee = u64::MAX;
    h.reward = u64::MAX;
    h.block_size = u32::MAX;
    block.pow_witnesses = vec![u64::MAX];
    block.block_authorization = vec![0; 256];
    let budget = template_transaction_budget(&cfg);
    let full = vec![0; 251];
    let cost = framed_blob_size(full.len());
    block.transactions = vec![full; budget / cost];
    assert!(wire.serialize(&block).unwrap().len() <= cfg.max_block_size);
}

fn receive(wallet: &mut Wallet, output: &TxOutput, index: u64, height: u64, ordinal: usize) {
    assert!(
        wallet
            .try_own_output(
                output.commitment.0,
                &output.one_time_pubkey,
                &output.ephemeral_pubkey,
                &output.encrypted_amount,
                index,
                height,
                ordinal as u64
            )
            .unwrap()
            .is_some()
    );
}

#[test]
#[ignore = "generates and verifies 4,096 funded CLSAG payments on HYN3"]
fn payments_roll_over_at_the_hyn3_wire_limit() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = ChainConfig::neural_devnet();
    let mut source = Wallet::from_seed([81; 32]);
    let network = Network {
        chain: Arc::new(Blockchain::open(dir.path().to_str().unwrap(), cfg.clone()).unwrap()),
        pool: Arc::new(RwLock::new(node_mempool())),
        reward: source.stealth_address(),
    };
    for _ in 0..4 {
        network.confirm();
    }
    let first_reward =
        Transaction::deserialise_limited(&network.chain.blocks.get_coinbase(1).unwrap()).unwrap();
    receive(&mut source, &first_reward.outputs[0], 0, 1, 0);
    // Split one actual reward into independently spendable notes on-chain.
    for (seed, outputs) in [(82, 16), (83, 16), (84, 16)] {
        let mut next = Wallet::from_seed([seed; 32]);
        let notes = source.unspent_notes();
        let funding = network.transfer(&notes, next.stealth_address(), outputs);
        let mut index = network.chain.commitment_tree.read().count();
        let block = network.confirm();
        assert_eq!(block.transactions.len(), funding.len());
        for bytes in &block.transactions {
            let tx = Transaction::deserialise_limited(bytes).unwrap();
            for (ordinal, output) in tx.outputs.iter().enumerate() {
                receive(&mut next, output, index, block.header.height, ordinal);
                index += 1;
            }
        }
        source = next;
    }
    let mut recipient = Wallet::from_seed([85; 32]);
    let notes = source.unspent_notes();
    assert_eq!(notes.len(), 4096);
    let expected_balance = source.balance() - notes.len() as u64 * FEE;
    let mut pending = network.transfer(&notes, recipient.stealth_address(), 1);
    assert_eq!(pending.len(), notes.len());
    assert!(network.pool.read().total_bytes() > cfg.max_block_size);
    let mut positions = Vec::new();
    let mut rounds = 0;
    while !pending.is_empty() {
        let first_index = network.chain.commitment_tree.read().count();
        let block = network.confirm();
        assert!(!block.transactions.is_empty());
        let encoded = wire_config(cfg.max_block_size)
            .serialized_size(&block)
            .unwrap();
        let hash = block.hash();
        for (position, bytes) in block.transactions.iter().enumerate() {
            let tx = Transaction::deserialise_limited(bytes).unwrap();
            assert!(pending.remove(&tx.hash()));
            positions.push((tx.hash(), (hash, position as u32)));
            receive(
                &mut recipient,
                &tx.outputs[0],
                first_index + position as u64,
                block.header.height,
                0,
            );
        }
        let pool = network.pool.read();
        assert_eq!(pool.len(), pending.len());
        assert!(pending.iter().all(|id| pool.contains(id)));
        eprintln!(
            "height={} payments={} encoded_bytes={encoded} pending={}",
            block.header.height,
            block.transactions.len(),
            pending.len()
        );
        rounds += 1;
    }
    assert!(rounds >= 3);
    assert_eq!(recipient.balance(), expected_balance);
    drop(network);
    let reopened = Blockchain::open(dir.path().to_str().unwrap(), cfg).unwrap();
    for (id, expected) in positions {
        assert_eq!(reopened.blocks.get_tx_location(&id).unwrap(), expected);
    }
    eprintln!(
        "reopened_payments={} received_atomic={expected_balance}",
        notes.len()
    );
}
