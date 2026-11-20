use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, connection_limits, gossipsub, identify, identity,
    kad, noise, ping, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use libp2p_allow_block_list as allow_block_list;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use hyphen_consensus::{InclusionReceiptVoteGossip, QuorumInclusionReceiptGossip};

use crate::protocol::{
    MAX_GOSSIP_BLOCK_SIZE, MAX_GOSSIP_ENVELOPE_SIZE, MAX_GOSSIP_TRANSACTION_SIZE, NetworkMessage,
    SyncRequest, SyncResponse,
};

#[derive(NetworkBehaviour)]
pub struct HyphenBehaviour {
    pub limits: connection_limits::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub request_response: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub block_list: allow_block_list::Behaviour<allow_block_list::BlockedPeers>,
}

pub struct HyphenNetwork {
    pub swarm: Swarm<HyphenBehaviour>,
    pub block_topic: gossipsub::IdentTopic,
    pub tx_topic: gossipsub::IdentTopic,
    pub receipt_topic: gossipsub::IdentTopic,
    sync_range: Option<(
        PeerId,
        request_response::OutboundRequestId,
        std::ops::RangeInclusive<u64>,
    )>,
    identify_protocol: String,
}

impl HyphenNetwork {
    pub fn new(
        listen_addr: Multiaddr,
        boot_nodes: Vec<(PeerId, Multiaddr)>,
        identity: identity::Keypair,
        network_magic: [u8; 4],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let network_tag = hyphen_crypto::hex_encode(network_magic);
        let sync_protocol =
            StreamProtocol::try_from_owned(format!("/hyphen/{network_tag}/sync/2"))?;
        let identify_protocol = format!("/hyphen/{network_tag}/id/2");
        let kad_protocol = StreamProtocol::try_from_owned(format!("/hyphen/{network_tag}/kad/1"))?;
        let behaviour_identify_protocol = identify_protocol.clone();

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(move |key| {
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut digest = DefaultHasher::new();
                    message.data.hash(&mut digest);
                    gossipsub::MessageId::from(digest.finish().to_string())
                };
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .max_transmit_size(MAX_GOSSIP_ENVELOPE_SIZE)
                    .message_id_fn(message_id_fn)
                    .build()
                    .expect("gossipsub config");

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .expect("gossipsub behaviour");

                let peer_id = key.public().to_peer_id();
                // The DHT provides peer routing only. Application data travels via sync or gossip.
                let store = kad::store::MemoryStore::with_config(
                    peer_id,
                    kad::store::MemoryStoreConfig {
                        max_records: 0,
                        max_value_bytes: 0,
                        max_provided_keys: 0,
                        ..Default::default()
                    },
                );
                let mut discovery = kad::Config::new(kad_protocol);
                discovery.set_kbucket_inserts(kad::BucketInserts::Manual);
                discovery.set_record_filtering(kad::StoreInserts::FilterBoth);
                let mut kademlia = kad::Behaviour::with_config(peer_id, store, discovery);
                kademlia.set_mode(Some(kad::Mode::Server));

                let rr = request_response::cbor::Behaviour::new(
                    [(sync_protocol, request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(20))
                        .with_max_concurrent_streams(16),
                );

                let identify = identify::Behaviour::new(identify::Config::new(
                    behaviour_identify_protocol.clone(),
                    key.public(),
                ));

                let ping = ping::Behaviour::new(ping::Config::new());

                HyphenBehaviour {
                    limits: connection_limits::Behaviour::new(
                        connection_limits::ConnectionLimits::default()
                            .with_max_pending_incoming(Some(32))
                            .with_max_pending_outgoing(Some(16))
                            .with_max_established_incoming(Some(48))
                            .with_max_established(Some(64))
                            .with_max_established_per_peer(Some(2)),
                    ),
                    gossipsub,
                    kademlia,
                    request_response: rr,
                    identify,
                    ping,
                    block_list: allow_block_list::Behaviour::default(),
                }
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(600)))
            .build();

        let block_topic = gossipsub::IdentTopic::new(format!("hyphen-{network_tag}-blocks-v2"));
        let tx_topic = gossipsub::IdentTopic::new(format!("hyphen-{network_tag}-txs-v2"));
        let receipt_topic =
            gossipsub::IdentTopic::new(format!("hyphen-{network_tag}-fair-receipts-v0"));

        swarm.behaviour_mut().gossipsub.subscribe(&block_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&tx_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&receipt_topic)?;

        swarm.listen_on(listen_addr)?;

        for (peer_id, addr) in &boot_nodes {
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(peer_id, addr.clone());
        }

        if !boot_nodes.is_empty()
            && let Err(e) = swarm.behaviour_mut().kademlia.bootstrap()
        {
            tracing::warn!("Kademlia bootstrap failed: {e:?}");
        }

        let mut network = Self {
            swarm,
            block_topic,
            tx_topic,
            receipt_topic,
            sync_range: None,
            identify_protocol,
        };
        network.dial_seeds(&boot_nodes);
        Ok(network)
    }

    pub fn broadcast_transaction(
        &mut self,
        tx_bytes: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if tx_bytes.len() > MAX_GOSSIP_TRANSACTION_SIZE {
            return Err("transaction exceeds gossip limit".into());
        }
        let msg = NetworkMessage::NewTransaction(tx_bytes).encode_proto()?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.tx_topic.clone(), msg)?;
        Ok(())
    }

    pub fn broadcast_block(
        &mut self,
        block_bytes: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if block_bytes.len() > MAX_GOSSIP_BLOCK_SIZE {
            return Err("block exceeds gossip limit".into());
        }
        let msg = NetworkMessage::NewBlock(block_bytes).encode_proto()?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.block_topic.clone(), msg)?;
        Ok(())
    }

    pub fn broadcast_receipt_vote(
        &mut self,
        receipt: InclusionReceiptVoteGossip,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let message = NetworkMessage::InclusionReceiptVote(receipt).encode_proto()?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.receipt_topic.clone(), message)?;
        Ok(())
    }

    pub fn broadcast_quorum_receipt(
        &mut self,
        receipt: QuorumInclusionReceiptGossip,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let message = NetworkMessage::QuorumInclusionReceipt(receipt).encode_proto()?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.receipt_topic.clone(), message)?;
        Ok(())
    }

    pub fn send_sync_request(
        &mut self,
        peer: &PeerId,
        request: SyncRequest,
    ) -> request_response::OutboundRequestId {
        self.swarm
            .behaviour_mut()
            .request_response
            .send_request(peer, request)
    }

    pub async fn next_event(&mut self) -> Option<SwarmEvent<HyphenBehaviourEvent>> {
        self.swarm.next().await
    }

    pub fn same_network(&self, protocol: &str) -> bool {
        self.identify_protocol == protocol
    }

    pub fn dial_seeds(&mut self, seeds: &[(PeerId, Multiaddr)]) {
        let mut addresses = std::collections::HashMap::<PeerId, Vec<Multiaddr>>::new();
        for (peer, address) in seeds {
            if peer != self.swarm.local_peer_id()
                && !self.swarm.is_connected(peer)
                && !self.is_blocked(peer)
            {
                addresses.entry(*peer).or_default().push(address.clone());
            }
        }
        for (peer, addresses) in addresses {
            let options = libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
                .addresses(addresses)
                .build();
            if let Err(error) = self.swarm.dial(options) {
                tracing::debug!(%peer, %error, "Seed dial deferred");
            }
        }
    }

    pub fn request_range(&mut self, peer: PeerId, local: u64, target: u64) {
        if local < target && self.sync_range.is_none() {
            let request = SyncRequest::GetBlocks {
                start_height: local + 1,
                count: (target - local).min(u64::from(crate::SYNC_BATCH_SIZE)) as u32,
            };
            let id = self.send_sync_request(&peer, request);
            self.sync_range = Some((peer, id, local + 1..=target));
        }
    }

    pub fn has_pending_range(&self) -> bool {
        self.sync_range.is_some()
    }

    pub fn finish_range(
        &mut self,
        peer: PeerId,
        id: request_response::OutboundRequestId,
    ) -> Option<std::ops::RangeInclusive<u64>> {
        self.sync_range
            .take_if(|range| range.0 == peer && range.1 == id)
            .map(|range| range.2)
    }

    /// Attempts a Kademlia bootstrap.  Safe to call periodically —
    /// harmless when no peers are configured yet.
    pub fn try_bootstrap(&mut self) {
        let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
    }

    /// Register a verified address for discovery and outbound requests.
    pub fn add_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, addr);
    }

    /// Number of peers currently connected via the swarm.
    pub fn connected_peer_count(&self) -> usize {
        self.swarm.connected_peers().count()
    }

    /// Blocks a peer and closes every connection to it.
    ///
    /// The caller must have locally verified the fault; a peer that merely
    /// relayed somebody else's bad data is not necessarily the author, so the
    /// node only calls this for proofed protocol violations.
    pub fn block_peer(&mut self, peer: PeerId) -> bool {
        self.swarm.behaviour_mut().block_list.block_peer(peer)
    }

    /// Lifts a block, allowing the peer to connect again.
    pub fn unblock_peer(&mut self, peer: PeerId) -> bool {
        self.swarm.behaviour_mut().block_list.unblock_peer(peer)
    }

    /// Returns whether the peer is currently blocked.
    pub fn is_blocked(&self, peer: &PeerId) -> bool {
        self.swarm
            .behaviour()
            .block_list
            .blocked_peers()
            .contains(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocking_a_peer_is_visible_and_reversible() {
        let key = identity::Keypair::generate_ed25519();
        let peer = key.public().to_peer_id();
        let mut network = HyphenNetwork::new(
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            Vec::new(),
            key,
            *b"TEST",
        )
        .expect("the network starts on a loopback port");

        assert!(!network.is_blocked(&peer));
        assert!(network.block_peer(peer));
        assert!(network.is_blocked(&peer));
        // Blocking an already blocked peer reports no change.
        assert!(!network.block_peer(peer));
        assert!(network.unblock_peer(peer));
        assert!(!network.is_blocked(&peer));
        assert!(!network.unblock_peer(peer));
    }
}
