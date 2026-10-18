# Peer policy: what earns a ban

Status: active in `hyphen-node`. Scope: inbound P2P only.

## Principle

A ban protects the node's bandwidth and its connection slots. It is not a
consensus judgement, and it must never punish a peer for something the node
cannot verify itself. The policy therefore distinguishes **proofed faults** —
evidence the node validates locally, independent of chain state — from
**contextual rejections**, which may say more about the node than about the peer.

## Proofed faults (counted)

| Fault | Where | Why it is proofed |
| --- | --- | --- |
| Gossip envelope does not decode | `NetworkMessage::decode_proto` | The protobuf envelope is self-describing; no chain state is involved. |
| Block payload does not decode within `max_block_size` | `Block::deserialise_limited` | The limit and the codec are consensus constants. |
| Transaction payload decodes as none of the four transaction families and then fails `Transaction::deserialise_limited` | node gossip path | Every codec had its turn; the bytes are malformed for this chain. |
| Sync response violates its structural budget | `SyncResponse::validate` | Bounded counts and sizes, checked before use. |
| Sync block does not decode | `Block::deserialise_limited` | Same as gossip. |

## Contextual rejections (not counted)

- A block that decodes but fails `accept_block`. The node validates against its
  current tip, so a well-formed block for a height the node has not reached fails
  with a height mismatch. Counting that would turn ordinary catch-up sync into a
  ban storm against honest peers.
- A transaction rejected because of its ring, fee, or nullifier relative to the
  current state. The same bytes can be valid a block later, and the sender may be
  relaying someone else's transaction.
- Wrong-chain messages: these fail the protocol discriminator, which is already a
  connection-level mismatch, not something to score.

## Scoring

```text
window    = 10 minutes
threshold = 3 strikes
ban       = 60 minutes
capacity  = 4096 tracked peers
```

Strikes older than the window are dropped before each new strike. A ban clears
the strike list, so re-offending after a ban starts from zero. The table is
bounded: when it is full, entries with no active ban and the oldest last strike
are evicted first; active bans are never evicted to make room, because dropping a
ban is worse than declining to track one more identity.

Enforcement is `libp2p-allow-block-list`: blocking a peer closes its live
connections and refuses new ones. Expiry is checked on the node's 60-second
maintenance tick, which unblocks the peer and lets it reconnect.

## Known limits

- **In-memory only.** Restarting the node clears every ban. Persisting bans needs
  a bounded on-disk format, a retention policy, and an operator override; none of
  those exist yet.
- **No shared ban list.** Two nodes maintain independent views by design. A
  gossiped ban list would let one node censor another's peers.
- **Sybil cost is identity cost.** A peer that can generate identities can spend
  connection slots; the strike table only bounds local memory, not the number of
  identities. Connection limits and the Kademlia topology are the relevant
  defences, and neither is a substitute for an authenticated peer set.
- **No snapshot or pruning-point import exists.** There is no code path that
  accepts a UTXO snapshot, so the snapshot-tampering class of attack has no
  surface in this revision. Any future snapshot sync must verify the snapshot
  against a checkpoint the node already trusts and must treat a failed
  verification as a proofed fault.
