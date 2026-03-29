use libp2p::PeerId;
use tracing::info;

use crate::protocol::SyncRequest;

pub enum SyncState {
    Idle,
    Discovering,
    Downloading {
        peer: PeerId,
        next_height: u64,
        target_height: u64,
    },
    Processing,
}

pub struct SyncManager {
    pub state: SyncState,
    pub batch_size: u32,
}

impl Default for SyncManager {
    fn default() -> Self { Self::new() }
}

impl SyncManager {
    pub fn new() -> Self {
        Self {
            state: SyncState::Idle,
            batch_size: 100,
        }
    }

    pub fn on_tip_response(
        &mut self,
        peer: PeerId,
        their_height: u64,
        their_cum_diff: u128,
        our_height: u64,
        our_cum_diff: u128,
    ) -> Option<SyncRequest> {
        if their_cum_diff > our_cum_diff && their_height > our_height {
            info!(
                "Peer {} is ahead (height {}, cum_diff {}), starting sync from {}",
                peer, their_height, their_cum_diff, our_height + 1
            );
            self.state = SyncState::Downloading {
                peer,
                next_height: our_height + 1,
                target_height: their_height,
            };
            Some(SyncRequest::GetBlocks {
                start_height: our_height + 1,
                count: self.batch_size,
            })
        } else {
            None
        }
    }

    pub fn on_blocks_received(
        &mut self,
        blocks_count: usize,
    ) -> Option<SyncRequest> {
        if let SyncState::Downloading {
            peer: _,
            ref mut next_height,
            target_height,
        } = self.state
        {
            *next_height += blocks_count as u64;
            if *next_height > target_height {
                info!("Sync complete up to height {target_height}");
                self.state = SyncState::Idle;
                None
            } else {
                Some(SyncRequest::GetBlocks {
                    start_height: *next_height,
                    count: self.batch_size,
                })
            }
        } else {
            None
        }
    }
}
