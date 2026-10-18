//! Peer misbehavior policy.
//!
//! A ban is a DoS defence, not a punishment: getting it wrong in the permissive
//! direction costs bandwidth, getting it wrong in the strict direction
//! disconnects honest peers and partitions the node. The policy therefore only
//! counts faults the node can verify locally, without depending on chain state
//! or on what other peers claim:
//!
//! - a gossip envelope that does not decode;
//! - a block or transaction payload that does not decode within the size limits;
//! - a sync response that violates its own structural budget;
//! - a sync block that does not decode.
//!
//! A block that decodes but fails contextual validation is **not** counted. The
//! node validates against its current tip, so a well-formed block for a height
//! the node has not reached yet fails for reasons that belong to the node, not to
//! the relay. Banning on that would turn ordinary sync into a ban storm.
//!
//! Strikes decay with a fixed window and a ban expires, so a transient bug or a
//! single corrupted frame does not isolate a peer permanently. The block list is
//! in-memory: restarting the node clears it, which is the honest trade-off until
//! bans are persisted with an auditable policy.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::PeerId;

/// A strike older than this no longer counts toward a ban.
pub const STRIKE_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Strikes within the window before a peer is blocked.
pub const STRIKE_THRESHOLD: u32 = 3;

/// How long a blocked peer stays blocked before it may reconnect.
pub const BAN_DURATION: Duration = Duration::from_secs(60 * 60);

/// Upper bound on tracked peers, so a flood of bogus identities cannot grow the
/// table without limit.
pub const MAX_TRACKED_PEERS: usize = 4096;

#[derive(Debug, Default)]
struct Record {
    strikes: Vec<Instant>,
    banned_until: Option<Instant>,
}

/// Bounded strike counter with time-based expiry.
#[derive(Debug)]
pub struct PeerPolicy {
    window: Duration,
    threshold: u32,
    ban_duration: Duration,
    max_tracked: usize,
    peers: HashMap<PeerId, Record>,
}

impl Default for PeerPolicy {
    fn default() -> Self {
        Self::new(
            STRIKE_WINDOW,
            STRIKE_THRESHOLD,
            BAN_DURATION,
            MAX_TRACKED_PEERS,
        )
    }
}

impl PeerPolicy {
    /// Builds a policy with explicit limits. All durations are monotonic; the
    /// caller passes the clock so the behaviour is testable and deterministic.
    pub fn new(
        window: Duration,
        threshold: u32,
        ban_duration: Duration,
        max_tracked: usize,
    ) -> Self {
        Self {
            window,
            threshold: threshold.max(1),
            ban_duration,
            max_tracked: max_tracked.max(1),
            peers: HashMap::new(),
        }
    }

    /// Records one locally verified fault.
    ///
    /// Returns `true` when this strike crossed the threshold and the peer must
    /// now be blocked. A peer already blocked keeps its ban and reports `false`,
    /// so the caller does not block it twice.
    pub fn record_offense(&mut self, peer: PeerId, now: Instant) -> bool {
        self.make_room(now);
        let record = self.peers.entry(peer).or_default();
        if let Some(until) = record.banned_until {
            if now < until {
                return false;
            }
            record.banned_until = None;
            record.strikes.clear();
        }
        record
            .strikes
            .retain(|strike| now.saturating_duration_since(*strike) <= self.window);
        record.strikes.push(now);
        if record.strikes.len() as u32 >= self.threshold {
            record.strikes.clear();
            record.banned_until = Some(now + self.ban_duration);
            return true;
        }
        false
    }

    /// Returns whether the peer is currently blocked by this policy.
    #[cfg(test)]
    pub fn is_banned(&self, peer: &PeerId, now: Instant) -> bool {
        self.peers
            .get(peer)
            .and_then(|record| record.banned_until)
            .is_some_and(|until| now < until)
    }

    /// Removes expired bans and returns the peers the caller must unblock.
    ///
    /// Records with no remaining state are dropped so the table stays small.
    pub fn take_expired(&mut self, now: Instant) -> Vec<PeerId> {
        let mut expired = Vec::new();
        self.peers.retain(|peer, record| {
            if let Some(until) = record.banned_until {
                if now >= until {
                    record.banned_until = None;
                    expired.push(*peer);
                }
            }
            record
                .strikes
                .retain(|strike| now.saturating_duration_since(*strike) <= self.window);
            record.banned_until.is_some() || !record.strikes.is_empty()
        });
        expired
    }

    /// Number of peers currently tracked.
    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.peers.len()
    }

    /// Drops the oldest-decayed entries when the table is full.
    fn make_room(&mut self, now: Instant) {
        if self.peers.len() < self.max_tracked {
            return;
        }
        self.take_expired(now);
        while self.peers.len() >= self.max_tracked {
            let victim = self
                .peers
                .iter()
                .filter(|(_, record)| record.banned_until.is_none())
                .min_by_key(|(_, record)| record.strikes.last().copied())
                .map(|(peer, _)| *peer);
            match victim {
                Some(peer) => {
                    self.peers.remove(&peer);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        PeerId::from_multihash(libp2p::multihash::Multihash::wrap(0x12, &bytes).unwrap()).unwrap()
    }

    #[test]
    fn three_strikes_inside_the_window_block_the_peer() {
        let mut policy = PeerPolicy::default();
        let now = Instant::now();
        let offender = peer(1);
        assert!(!policy.record_offense(offender, now));
        assert!(!policy.record_offense(offender, now + Duration::from_secs(1)));
        assert!(policy.record_offense(offender, now + Duration::from_secs(2)));
        assert!(policy.is_banned(&offender, now + Duration::from_secs(3)));
        assert!(!policy.record_offense(offender, now + Duration::from_secs(4)));
    }

    #[test]
    fn strikes_outside_the_window_do_not_accumulate() {
        let mut policy = PeerPolicy::default();
        let now = Instant::now();
        let peer = peer(2);
        assert!(!policy.record_offense(peer, now));
        assert!(!policy.record_offense(peer, now + STRIKE_WINDOW + Duration::from_secs(1)));
        assert!(!policy.record_offense(peer, now + 2 * STRIKE_WINDOW + Duration::from_secs(2)));
        assert!(!policy.is_banned(&peer, now));
    }

    #[test]
    fn a_ban_expires_and_is_reported_once() {
        let mut policy = PeerPolicy::default();
        let now = Instant::now();
        let peer = peer(3);
        let mut banned_at = now;
        for offset in 0..STRIKE_THRESHOLD {
            banned_at = now + Duration::from_secs(offset as u64);
            policy.record_offense(peer, banned_at);
        }
        assert!(policy.is_banned(&peer, now));
        let after_ban = banned_at + BAN_DURATION + Duration::from_secs(1);
        assert!(policy.take_expired(now + Duration::from_secs(1)).is_empty());
        let expired = policy.take_expired(after_ban);
        assert_eq!(expired, vec![peer]);
        assert!(!policy.is_banned(&peer, after_ban + Duration::from_secs(1)));
        assert!(policy
            .take_expired(after_ban + Duration::from_secs(2))
            .is_empty());
    }

    #[test]
    fn the_table_is_bounded() {
        let mut policy = PeerPolicy::new(Duration::from_secs(60), 3, BAN_DURATION, 4);
        let now = Instant::now();
        for index in 0..16u8 {
            policy.record_offense(peer(index), now + Duration::from_secs(index as u64));
        }
        assert!(policy.tracked() <= 4, "tracked {}", policy.tracked());
    }

    #[test]
    fn a_single_offender_is_tracked_once() {
        let mut policy = PeerPolicy::default();
        let now = Instant::now();
        let peer = peer(9);
        for offset in 0..10 {
            policy.record_offense(peer, now + Duration::from_secs(offset));
        }
        assert_eq!(policy.tracked(), 1);
    }
}
