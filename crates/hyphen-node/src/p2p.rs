use super::{
    DEFAULT_WIRE_BYTES,
    peer_policy::{self, PeerPolicy},
    unix_time_ms, wire_config,
};
use hyphen_consensus::Blockchain;
use hyphen_crypto::Hash256;
use hyphen_mempool::Mempool;
use hyphen_network::{HyphenNetwork, SyncResponse};
use hyphen_rpc::admission::{AdmissionError, admit_transaction};
use libp2p::{gossipsub, identify, request_response};
use parking_lot::RwLock;
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
    time::Instant,
};
use tracing::{debug, error, info, warn};

pub(super) fn publish_block(chain: &Blockchain, network: &mut HyphenNetwork, hash: Hash256) {
    let result = (|| {
        let block = chain.blocks.get_block_by_hash(&hash)?;
        let bytes =
            wire_config(hyphen_network::protocol::MAX_GOSSIP_BLOCK_SIZE).serialize(&block)?;
        network.broadcast_block(bytes)
    })();
    if let Err(error) = result {
        debug!(%error, %hash, "Block gossip unavailable");
    }
}

pub(super) fn publish_transaction(
    pool: &RwLock<Mempool>,
    network: &mut HyphenNetwork,
    hash: Hash256,
) {
    let bytes = pooled_bytes(&pool.read(), &hash);
    if let Some(bytes) = bytes
        && let Err(error) = network.broadcast_transaction(bytes)
    {
        debug!(%error, %hash, "Transaction gossip unavailable");
    }
}

fn pooled_bytes(pool: &Mempool, hash: &Hash256) -> Option<Vec<u8>> {
    pool.get_protocol(hash)
        .map(<[u8]>::to_vec)
        .or_else(|| pool.get(hash).map(|tx| tx.serialise()))
}

fn revalidate_after_reorg(chain: &Blockchain, pool: &RwLock<Mempool>) {
    let hashes = pool.read().hashes();
    for hash in hashes {
        let Ok(_view) = chain.canonical_view() else {
            return;
        };
        let Some(bytes) = pooled_bytes(&pool.read(), &hash) else {
            continue;
        };
        let Ok(tip) = chain.tip() else { return };
        let Some(height) = tip.height.checked_add(1) else {
            return;
        };
        if let Err(error) = chain.validate_transaction_blobs_for_height(&[bytes], height) {
            use hyphen_core::error::CoreError;
            if matches!(
                error,
                CoreError::Storage(_) | CoreError::HeightMismatch { .. }
            ) {
                continue;
            }
            let mut pool = pool.write();
            pool.remove(&hash);
            pool.remove_protocol(&hash);
        }
    }
}

#[derive(Default)]
pub(super) struct PeerSync {
    pub(super) validation: tokio::task::JoinSet<ValidatedBatch>,
    pub(super) admissions: tokio::task::JoinSet<PeerAdmission>,
    pub(super) policy: PeerPolicy,
    waiting: VecDeque<(libp2p::PeerId, u64)>,
    pub(super) responses: tokio::task::JoinSet<(
        request_response::ResponseChannel<SyncResponse>,
        SyncResponse,
    )>,
    serving: HashSet<request_response::InboundRequestId>,
    fork_probe: Option<libp2p::PeerId>,
    fork: Option<PeerBranch>,
}

pub(super) struct PeerAdmission {
    author: libp2p::PeerId,
    source: libp2p::PeerId,
    result: Result<Hash256, AdmissionError>,
}

struct PeerBranch {
    peer: libp2p::PeerId,
    request: request_response::OutboundRequestId,
    expected: Hash256,
    height: u64,
    work: u128,
    bytes: usize,
    reversed: Vec<hyphen_core::Block>,
}

impl PeerSync {
    pub(super) fn on_admission(&mut self, admission: PeerAdmission, network: &mut HyphenNetwork) {
        let PeerAdmission {
            author,
            source,
            result,
        } = admission;
        match result {
            Ok(hash) => info!(%hash, %source, "Admitted peer transaction"),
            Err(AdmissionError::Malformed(error)) => {
                penalize(network, &mut self.policy, author, "undecodable transaction");
                debug!(%error, %source, "Malformed transaction");
            }
            Err(error) => debug!(%error, %source, "Peer transaction rejected"),
        }
    }

    fn queue(&mut self, peer: libp2p::PeerId, height: u64) {
        self.waiting.retain(|(id, _)| *id != peer);
        self.waiting.push_back((peer, height));
    }

    fn dispatch(&mut self, chain: &Blockchain, network: &mut HyphenNetwork) {
        if !self.validation.is_empty() || network.has_pending_range() || self.fork.is_some() {
            return;
        }
        let Ok(tip) = chain.tip() else { return };
        while let Some((peer, target)) = self.waiting.pop_front() {
            if target > tip.height
                && network.swarm.is_connected(&peer)
                && !network.is_blocked(&peer)
            {
                network.request_range(peer, tip.height, target);
                break;
            }
        }
    }

    pub(super) fn on_validated(
        &mut self,
        result: Result<ValidatedBatch, tokio::task::JoinError>,
        chain: &Blockchain,
        pool: &RwLock<Mempool>,
        network: &mut HyphenNetwork,
    ) {
        match result {
            Ok(batch) => {
                for hash in batch.readmitted {
                    publish_transaction(pool, network, hash);
                }
                if batch.diverged && self.fork.is_none() {
                    self.fork_probe = Some(batch.source);
                    network.send_sync_request(&batch.source, hyphen_network::SyncRequest::GetTip);
                }
                if batch.malformed {
                    penalize(
                        network,
                        &mut self.policy,
                        batch.source,
                        "malformed peer block or range",
                    );
                }
                if let Some(target) = batch.target {
                    info!(peer = %batch.source, accepted = batch.accepted, count = batch.count, "Processed sync batch");
                    if batch.accepted > 0 && batch.accepted == batch.count {
                        self.queue(batch.source, target);
                    }
                }
            }
            Err(error) => error!(%error, "Peer block validation task failed"),
        }
        self.dispatch(chain, network);
    }

    pub(super) fn handle_event(
        &mut self,
        event: libp2p::swarm::SwarmEvent<hyphen_network::behaviour::HyphenBehaviourEvent>,
        blockchain: &Arc<Blockchain>,
        mempool: &Arc<RwLock<Mempool>>,
        network: &mut hyphen_network::HyphenNetwork,
    ) {
        use libp2p::swarm::SwarmEvent;
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                let local_peer = *network.swarm.local_peer_id();
                info!("Listening on {address}/p2p/{local_peer}");
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                num_established,
                ..
            } => {
                info!("Connected to {peer_id} (total connections: {num_established})");
                if num_established.get() == 1 {
                    network.send_sync_request(&peer_id, hyphen_network::SyncRequest::GetTip);
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                cause,
                ..
            } => {
                if num_established == 0 {
                    if self.fork.as_ref().is_some_and(|fork| fork.peer == peer_id) {
                        self.fork = None;
                    }
                    if self.fork_probe == Some(peer_id) {
                        self.fork_probe = None;
                    }
                    self.waiting.retain(|(id, _)| *id != peer_id);
                    info!(
                        "Disconnected from {peer_id} (cause: {})",
                        cause
                            .as_ref()
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "none".into())
                    );
                }
            }
            SwarmEvent::Behaviour(behaviour_event) => {
                self.handle_behaviour_event(behaviour_event, blockchain, mempool, network);
            }
            _ => {}
        }
    }

    fn handle_behaviour_event(
        &mut self,
        event: hyphen_network::behaviour::HyphenBehaviourEvent,
        blockchain: &Arc<Blockchain>,
        mempool: &Arc<RwLock<Mempool>>,
        network: &mut hyphen_network::HyphenNetwork,
    ) {
        use hyphen_network::behaviour::HyphenBehaviourEvent;
        match event {
            HyphenBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                propagation_source,
                ..
            }) => {
                let Some(author) = message.source else { return };
                match hyphen_network::NetworkMessage::decode_proto(&message.data) {
                    Ok(msg) => match msg {
                        hyphen_network::NetworkMessage::NewBlock(block_bytes) => {
                            if self.validation.is_empty() {
                                let chain = Arc::clone(blockchain);
                                let pool = Arc::clone(mempool);
                                self.validation.spawn_blocking(move || {
                                    validate_batch(&chain, &pool, author, vec![block_bytes], None)
                                });
                            }
                        }
                        hyphen_network::NetworkMessage::NewTransaction(tx_bytes) => {
                            // Each job retains at most one gossip payload while waiting for a canonical view.
                            if self.admissions.len() >= 4 {
                                debug!(%propagation_source, "Peer transaction validation busy");
                                return;
                            }
                            let chain = Arc::clone(blockchain);
                            let pool = Arc::clone(mempool);
                            self.admissions.spawn_blocking(move || {
                                let result = chain
                                    .canonical_view()
                                    .map_err(|e| AdmissionError::State(e.to_string()))
                                    .and_then(|_view| {
                                        admit_transaction(&chain, &pool, tx_bytes, unix_time_ms())
                                    });
                                PeerAdmission {
                                    author,
                                    source: propagation_source,
                                    result,
                                }
                            });
                        }
                        hyphen_network::NetworkMessage::InclusionReceiptVote(receipt) => {
                            warn!(
                                target: "hyphen::fairness",
                                "Ignoring structurally valid receipt vote for slot {} transaction {} from {} because no active finalized committee profile is configured",
                                receipt.statement.slot,
                                receipt.statement.transaction_id,
                                propagation_source
                            );
                        }
                        hyphen_network::NetworkMessage::QuorumInclusionReceipt(receipt) => {
                            warn!(
                                target: "hyphen::fairness",
                                "Ignoring structurally valid quorum receipt for slot {} transaction {} from {} because no active finalized committee profile is configured",
                                receipt.receipt.statement.slot,
                                receipt.receipt.statement.transaction_id,
                                propagation_source
                            );
                        }
                    },
                    Err(error) => {
                        penalize(
                            network,
                            &mut self.policy,
                            author,
                            "undecodable gossip envelope",
                        );
                        debug!("Undecodable gossip envelope from {propagation_source}: {error}");
                    }
                }
            }
            HyphenBehaviourEvent::RequestResponse(request_response::Event::Message {
                peer,
                message,
                ..
            }) => match message {
                request_response::Message::Request {
                    request,
                    channel,
                    request_id,
                } => {
                    let response = if self.serving.len() >= 4 || self.responses.len() >= 4 {
                        SyncResponse::Error("sync server busy".into())
                    } else {
                        self.serving.insert(request_id);
                        let chain = Arc::clone(blockchain);
                        self.responses.spawn_blocking(move || {
                            (channel, handle_sync_request(&request, &chain))
                        });
                        return;
                    };
                    let _ = network
                        .swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, response);
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    let range = network.finish_range(peer, request_id);
                    let pending_branch = self
                        .fork
                        .take_if(|fork| fork.peer == peer && fork.request == request_id);
                    if response.validate().is_err() {
                        penalize(
                            network,
                            &mut self.policy,
                            peer,
                            "sync response violates its structural budget",
                        );
                    } else if let Some(branch) = pending_branch {
                        if let SyncResponse::Block(bytes) = response {
                            self.receive_branch_block(branch, bytes, blockchain, mempool, network);
                        }
                    } else {
                        match (range, response) {
                            (Some(range), SyncResponse::Blocks(blocks)) => {
                                let count = (range.end() - range.start() + 1)
                                    .min(u64::from(hyphen_network::SYNC_BATCH_SIZE));
                                if blocks.len() as u64 > count {
                                    penalize(
                                        network,
                                        &mut self.policy,
                                        peer,
                                        "too many blocks in sync response",
                                    );
                                } else {
                                    let chain = Arc::clone(blockchain);
                                    let pool = Arc::clone(mempool);
                                    self.validation.spawn_blocking(move || {
                                        validate_batch(&chain, &pool, peer, blocks, Some(range))
                                    });
                                }
                            }
                            (
                                None,
                                SyncResponse::Tip {
                                    height,
                                    cumulative_difficulty,
                                    hash,
                                },
                            ) => {
                                if let Ok(tip) = blockchain.tip()
                                    && cumulative_difficulty > tip.cumulative_difficulty
                                {
                                    let probe = self.fork_probe == Some(peer);
                                    if (height <= tip.height || probe) && height > 0 {
                                        if self.fork.is_none()
                                            && self.validation.is_empty()
                                            && !network.has_pending_range()
                                        {
                                            self.fork_probe = None;
                                            let request = network.send_sync_request(
                                                &peer,
                                                hyphen_network::SyncRequest::GetBlock { hash },
                                            );
                                            self.fork = Some(PeerBranch {
                                                peer,
                                                request,
                                                expected: Hash256::from_bytes(hash),
                                                height,
                                                work: cumulative_difficulty,
                                                bytes: 0,
                                                reversed: Vec::new(),
                                            });
                                        }
                                    } else {
                                        self.queue(peer, height);
                                    }
                                }
                            }
                            (_, SyncResponse::Error(error)) => {
                                debug!(%peer, %error, "Peer sync error")
                            }
                            _ => debug!(%peer, "Unexpected sync response type"),
                        }
                    }
                    self.dispatch(blockchain, network);
                }
            },
            HyphenBehaviourEvent::RequestResponse(
                request_response::Event::ResponseSent { request_id, .. }
                | request_response::Event::InboundFailure { request_id, .. },
            ) => {
                self.serving.remove(&request_id);
            }
            HyphenBehaviourEvent::RequestResponse(request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            }) => {
                network.finish_range(peer, request_id);
                self.fork
                    .take_if(|fork| fork.peer == peer && fork.request == request_id);
                self.dispatch(blockchain, network);
                debug!(%peer, %error, "Sync request failed");
            }
            HyphenBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                if !network.same_network(&info.protocol_version) {
                    info!(%peer_id, protocol = %info.protocol_version, "Disconnecting peer with incompatible network identity");
                    let _ = network.swarm.disconnect_peer_id(peer_id);
                    return;
                }
                for mut addr in info.listen_addrs.into_iter().take(16) {
                    use libp2p::multiaddr::Protocol;
                    if let Some(Protocol::P2p(id)) = addr.iter().last() {
                        if id != peer_id {
                            continue;
                        }
                        addr.pop();
                    }
                    let mut parts = addr.iter();
                    let dialable = match parts.next() {
                        Some(Protocol::Ip4(ip)) => {
                            !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
                        }
                        Some(Protocol::Ip6(ip)) => !ip.is_unspecified() && !ip.is_multicast(),
                        _ => false,
                    };
                    if dialable
                        && matches!(parts.next(), Some(Protocol::Tcp(port)) if port != 0)
                        && parts.next().is_none()
                    {
                        network.add_peer(peer_id, addr);
                    }
                }
            }
            _ => {}
        }
    }

    fn receive_branch_block(
        &mut self,
        mut branch: PeerBranch,
        bytes: Vec<u8>,
        chain: &Arc<Blockchain>,
        pool: &Arc<RwLock<Mempool>>,
        network: &mut HyphenNetwork,
    ) {
        branch.bytes = branch.bytes.saturating_add(bytes.len());
        if branch.bytes > hyphen_consensus::chain::MAX_PEER_BRANCH_BYTES
            || branch.reversed.len() >= hyphen_state::MAX_REORG_PATH_BLOCKS
        {
            return;
        }
        let Ok(block) = hyphen_core::Block::deserialise_limited(&bytes, chain.cfg.max_block_size)
        else {
            return;
        };
        if block.hash() != branch.expected
            || block.header.height != branch.height
            || branch.height == 0
        {
            return;
        }
        branch.expected = block.header.prev_hash;
        branch.height -= 1;
        branch.reversed.push(block);
        if chain.blocks.get_block_hash_at_height(branch.height).ok() == Some(branch.expected) {
            branch.reversed.reverse();
            let chain = Arc::clone(chain);
            let pool = Arc::clone(pool);
            self.validation.spawn_blocking(move || {
                let count = branch.reversed.len();
                let mut batch = ValidatedBatch {
                    source: branch.peer,
                    target: None,
                    count,
                    accepted: 0,
                    malformed: false,
                    diverged: false,
                    readmitted: Vec::new(),
                };
                match chain.accept_peer_branch(&branch.reversed, branch.work) {
                    Ok(detached) => {
                        for block in &branch.reversed {
                            purge_block_transactions(&chain, &pool, block);
                        }
                        revalidate_after_reorg(&chain, &pool);
                        for hash in detached.iter().rev() {
                            let Ok(block) = chain.blocks.get_block_by_hash(hash) else {
                                error!(%hash, "Unable to read detached block for transaction recovery");
                                continue;
                            };
                            for bytes in block.transactions {
                                let Ok(_view) = chain.canonical_view() else { break };
                                if let Ok(hash) = hyphen_rpc::admission::admit_transaction(&chain, &pool, bytes, unix_time_ms()) {
                                    batch.readmitted.push(hash);
                                }
                            }
                        }
                        batch.accepted = count;
                        info!(peer=%branch.peer, detached=detached.len(), attached=count,"Adopted heavier peer branch");
                    }
                    Err(error) => debug!(peer=%branch.peer,%error,"Peer branch rejected"),
                }
                batch
            });
        } else if branch.height > 0 {
            branch.request = network.send_sync_request(
                &branch.peer,
                hyphen_network::SyncRequest::GetBlock {
                    hash: *branch.expected.as_bytes(),
                },
            );
            self.fork = Some(branch);
        }
    }
}

pub(super) struct ValidatedBatch {
    source: libp2p::PeerId,
    target: Option<u64>,
    count: usize,
    accepted: usize,
    malformed: bool,
    diverged: bool,
    readmitted: Vec<Hash256>,
}

fn validate_batch(
    chain: &Blockchain,
    pool: &RwLock<Mempool>,
    source: libp2p::PeerId,
    blocks: Vec<Vec<u8>>,
    range: Option<std::ops::RangeInclusive<u64>>,
) -> ValidatedBatch {
    let mut result = ValidatedBatch {
        source,
        target: range.as_ref().map(|r| *r.end()),
        count: blocks.len(),
        accepted: 0,
        malformed: false,
        diverged: false,
        readmitted: Vec::new(),
    };
    for (offset, bytes) in blocks.into_iter().enumerate() {
        let Ok(block) = hyphen_core::Block::deserialise_limited(&bytes, chain.cfg.max_block_size)
        else {
            result.malformed = true;
            break;
        };
        if range
            .as_ref()
            .is_some_and(|r| r.start().checked_add(offset as u64) != Some(block.header.height))
        {
            result.malformed = true;
            break;
        }
        if let Err(error) = chain.accept_submitted_block(&block) {
            result.diverged = chain
                .tip()
                .is_ok_and(|tip| block.header.prev_hash != tip.hash && block.header.height > 0);
            debug!(%source, %error, height = block.header.height, "Peer block rejected");
            break;
        }
        purge_block_transactions(chain, pool, &block);
        result.accepted += 1;
    }
    result
}

pub(super) fn purge_block_transactions(
    chain: &Blockchain,
    pool: &RwLock<Mempool>,
    block: &hyphen_core::Block,
) {
    let Ok(_view) = chain.canonical_view() else {
        return;
    };
    if chain
        .blocks
        .get_block_hash_at_height(block.header.height)
        .ok()
        != Some(block.hash())
    {
        return;
    }
    for bytes in &block.transactions {
        let hash = hyphen_crypto::blake3_hash(bytes);
        if pool.write().remove_protocol(&hash).is_some() {
            continue;
        }
        if let Ok(tx) = hyphen_tx::Transaction::deserialise_limited(bytes) {
            let mut pool = pool.write();
            for input in tx.inputs {
                pool.purge_confirmed(std::slice::from_ref(&input.key_image));
            }
        }
    }
}

fn penalize(
    network: &mut hyphen_network::HyphenNetwork,
    policy: &mut PeerPolicy,
    peer: libp2p::PeerId,
    reason: &str,
) {
    if policy.record_offense(peer, Instant::now()) {
        if network.block_peer(peer) {
            warn!(
                "Blocked peer {peer} for {} seconds after proofed misbehavior: {reason}",
                peer_policy::BAN_DURATION.as_secs()
            );
        }
    } else {
        warn!("Proofed misbehavior from {peer}: {reason}");
    }
}

fn handle_sync_request(
    request: &hyphen_network::SyncRequest,
    blockchain: &Arc<Blockchain>,
) -> hyphen_network::SyncResponse {
    use hyphen_network::{SyncRequest, SyncResponse};
    let _view = match blockchain.canonical_view() {
        Ok(guard) => guard,
        Err(e) => return SyncResponse::Error(e.to_string()),
    };
    if let Err(error) = request.validate() {
        return SyncResponse::Error(error.to_string());
    }
    match request {
        SyncRequest::GetTip => match blockchain.tip() {
            Ok(tip) => SyncResponse::Tip {
                height: tip.height,
                hash: *tip.hash.as_bytes(),
                cumulative_difficulty: tip.cumulative_difficulty,
            },
            Err(e) => SyncResponse::Error(e.to_string()),
        },
        SyncRequest::GetBlocks {
            start_height,
            count,
        } => {
            let mut blocks = Vec::new();
            // A CBOR array of u8 can use two encoded bytes per payload byte.
            // Stay below the sync/2 codec's 10 MiB response limit.
            let mut remaining = 4 * 1024 * 1024;
            for h in (*start_height..=u64::MAX).take(*count as usize) {
                match blockchain.blocks.get_block_by_height(h) {
                    Ok(block) => {
                        let data =
                            match wire_config(hyphen_network::protocol::MAX_GOSSIP_BLOCK_SIZE)
                                .serialize(&block)
                            {
                                Ok(data) => data,
                                Err(error) => return SyncResponse::Error(error.to_string()),
                            };
                        if data.len() > remaining {
                            break;
                        }
                        remaining -= data.len();
                        blocks.push(data);
                    }
                    Err(hyphen_state::store::StoreError::NotFound(_)) => break,
                    Err(error) => return SyncResponse::Error(error.to_string()),
                }
            }
            SyncResponse::Blocks(blocks)
        }
        SyncRequest::GetBlock { hash } => {
            let h = hyphen_crypto::Hash256::from_bytes(*hash);
            match blockchain.blocks.get_block_by_hash(&h) {
                Ok(block) => match wire_config(DEFAULT_WIRE_BYTES).serialize(&block) {
                    Ok(data) => SyncResponse::Block(data),
                    Err(e) => SyncResponse::Error(e.to_string()),
                },
                Err(e) => SyncResponse::Error(e.to_string()),
            }
        }
        SyncRequest::GetStateProof {
            namespace,
            root,
            key,
        } => {
            let namespace = hyphen_crypto::Hash256::from_bytes(*namespace);
            let root = hyphen_crypto::Hash256::from_bytes(*root);
            if namespace != blockchain.wes_latest.namespace() {
                return SyncResponse::Error("unknown state-proof namespace".into());
            }
            match blockchain
                .wes_latest
                .prove_at_root(hyphen_crypto::Hash256::from_bytes(*key), root)
            {
                Ok(proof) => SyncResponse::StateProof {
                    root: *root.as_bytes(),
                    proof,
                },
                Err(error) => SyncResponse::Error(error.to_string()),
            }
        }
        SyncRequest::GetBlobMetadata { object_hash } => {
            match blockchain
                .proof_blobs
                .metadata(hyphen_crypto::Hash256::from_bytes(*object_hash))
            {
                Ok(metadata) => SyncResponse::BlobMetadata(metadata),
                Err(error) => SyncResponse::Error(error.to_string()),
            }
        }
        SyncRequest::GetBlobChunk { object_hash, index } => {
            match blockchain
                .proof_blobs
                .chunk_proof(hyphen_crypto::Hash256::from_bytes(*object_hash), *index)
            {
                Ok(proof) => SyncResponse::BlobChunk(proof),
                Err(error) => SyncResponse::Error(error.to_string()),
            }
        }
    }
}
