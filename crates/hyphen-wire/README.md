# hyphen-wire

The frozen chain wire contract for Hyphen, chain identity **v6**.

Every byte the chain commits to — block headers, transactions, receipts,
miner/pool envelopes, archives, wallet state — is produced and consumed through
this crate's one profile. Keeping the profile in a single crate is what stops the
node, the pool, the miner and the wallet from drifting apart by re-implementing
it, and what makes a profile change a change to exactly one file.

## The profile

`wire_config(max_bytes)` returns a `rustbinary` **schema-guided compact**
configuration:

| Property | Encoding |
| --- | --- |
| Struct fields | declaration order, no field names, no type tags |
| Integers, lengths, discriminants | canonical little-endian varints |
| Containers | length-prefixed |
| `Option` | one presence byte |
| Enums | positional variant index |
| Trailing bytes | **rejected** |
| Budgets | byte budget per value, plus an element budget per container |

Because names and tags are absent and trailing bytes are refused, **one value has
exactly one accepted encoding**. That is the property a consensus format needs:
two nodes cannot disagree about the hash of the same logical value, and a
transaction that verifies in one implementation verifies in all of them.

Two budgets bind on every call:

- `max_bytes`, supplied by the caller, is the byte budget this decoder may spend
  on the value in front of it;
- the element budget is `min(max_bytes, MAX_WIRE_COLLECTION_ITEMS)`, so a caller
  may ask for a large frame and may never ask for an unbounded element count.

`DEFAULT_WIRE_BYTES` (64 MiB) is the conservative default for one value.

## Container adapters

`rustbinary` encodes `Vec`, `VecDeque`, arrays, `BTreeMap` and `HashMap`
directly. `CanonicalSet<T>` covers the remaining shape in the chain model:
ordered sets, encoded as the canonical strictly-ascending sequence. Decoding
rejects a duplicate or a descending pair, so a set has one representation rather
than a permutation of one.

## Frozen digests

The crate carries the profile's own tests — the byte and element budgets bind,
and trailing bytes are refused. Chain identity itself is pinned one level up:

- `hyphen-core` freezes one value's encoding byte for byte
  (`rustbinary_profile_preserves_the_frozen_wire_vector`, expected
  `[7, 251, 2, 1, 2, 3, 4, 1, 9]`), so the profile cannot drift silently;
- `hyphen-consensus` reads `test-vectors/chain-identity-v6.json` and checks the
  network magic, the consensus parameter hash and the genesis hash of all three
  profiles against the implementation.

Changing the profile changes the genesis hash. That is a chain fork, not a
patch, and the identity vectors exist so the difference cannot be discovered by
users instead of by CI.
