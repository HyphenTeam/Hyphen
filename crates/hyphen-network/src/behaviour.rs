use futures::StreamExt;
use libp2p::{
    gossipsub, identify, kad, noise, ping, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::protocol::{NetworkMessage, SyncRequest, SyncResponse};

#[derive(Debug, Clone)]
pub struct BincodeCodec;

#[derive(NetworkBehaviour)]
pub struct HyphenBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub request_response: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

pub struct HyphenNetwork {
    pub swarm: Swarm<HyphenBehaviour>,
    pub block_topic: gossipsub::IdentTopic,
    pub tx_topic: gossipsub::IdentTopic,
}

impl HyphenNetwork {
    pub fn new(
        listen_addr: Multiaddr,
        boot_nodes: Vec<(PeerId, Multiaddr)>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = DefaultHasher::new();
                    message.data.hash(&mut s);
                    gossipsub::MessageId::from(s.finish().to_string())
                };
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .build()
                    .expect("gossipsub config");

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .expect("gossipsub behaviour");

                let peer_id = key.public().to_peer_id();
                let store = kad::store::MemoryStore::new(peer_id);
                let kademlia = kad::Behaviour::new(peer_id, store);

                let rr = request_response::cbor::Behaviour::new(
                    [(
                        StreamProtocol::new("/hyphen/sync/1"),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );

                let identify = identify::Behaviour::new(identify::Config::new(
                    "/hyphen/id/1".into(),
                    key.public(),
                ));

                let ping = ping::Behaviour::new(ping::Config::new());

                HyphenBehaviour {
                    gossipsub,
                    kademlia,
                    request_response: rr,
                    identify,
                    ping,
                }
            })?
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(Duration::from_secs(60))
            })
            .build();

        let block_topic = gossipsub::IdentTopic::new("hyphen-blocks");
        let tx_topic = gossipsub::IdentTopic::new("hyphen-txs");

        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&block_topic)?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&tx_topic)?;

        swarm.listen_on(listen_addr)?;

        for (peer_id, addr) in &boot_nodes {
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(peer_id, addr.clone());
        }

        Ok(Self {
            swarm,
            block_topic,
            tx_topic,
        })
    }

    pub fn broadcast_transaction(&mut self, tx_bytes: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let msg = NetworkMessage::NewTransaction(tx_bytes).encode_proto();
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.tx_topic.clone(), msg)?;
        Ok(())
    }

    pub fn broadcast_block(&mut self, block_bytes: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let msg = NetworkMessage::NewBlock(block_bytes).encode_proto();
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.block_topic.clone(), msg)?;
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
}
