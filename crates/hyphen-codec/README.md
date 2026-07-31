# Hyphen Codec v1

`hyphen-codec` is the in-repository canonical serializer used by Hyphen
protocol, consensus, and persistent-state code. It replaces the unmaintained
`bincode` dependency. The implementation was written for this repository; it
does not vendor or copy bincode source.

This crate is memory-safe Rust (`#![forbid(unsafe_code)]`) and rejects trailing
bytes, unbounded Serde sequences, oversized collections, excessive nesting,
invalid scalar tags, non-finite floats, invalid UTF-8, and non-canonical maps.
It has not had an independent security audit.

## Wire format

All integers are fixed width and little endian:

| Serde value | Encoding |
| --- | --- |
| `bool` | one byte, exactly `0` or `1` |
| signed/unsigned integer | two's-complement/fixed-width LE bytes |
| `f32`, `f64` | IEEE bit pattern in LE; NaN and infinity are rejected |
| `char` | one `u32`; surrogate and out-of-range scalars are rejected |
| string/bytes | `u64` byte length, then bytes |
| sequence | `u64` element count, then elements |
| tuple/struct | fields in declaration order, without names or length |
| option | `0` for `None`; `1` followed by the value for `Some` |
| enum | `u32` declaration-order variant index, then variant fields |
| map | `u64` pair count, then key/value pairs sorted by encoded key bytes |

Map keys must have distinct canonical encodings. The encoder buffers at most
the configured output budget, sorts pairs by key bytes, and rejects duplicate
encodings. The decoder requires strictly increasing encoded key bytes. Thus map
serialization is independent of `HashMap` iteration order.

The decoder succeeds only if exactly one value consumes the entire input. This
is part of the format, not an optional configuration.

## Resource bounds

The default limits are:

```text
max_bytes          = 64 MiB
max_collection_len = 1,000,000 elements
max_depth          = 128 compound levels
```

Network and consensus callers use smaller context-specific byte limits where
the protocol already has one. Lengths are checked before collection allocation,
all position arithmetic is checked, and a sequence/map visitor must consume
exactly its declared number of elements.

For input length `B`, collection bound `C`, and depth bound `D`, decoder-owned
memory is `O(B + C)` in the worst case imposed by the target Serde type, and
recursive descent is bounded by `D`. The codec itself performs no allocation
from an unchecked wire length.

## Canonicality argument

Let `Enc` be the encoder on the supported Serde data model. Primitive encodings
are injective because tags, widths, and byte order are fixed. Struct and tuple
encodings are injective relative to their schema by induction over fields.
Sequences are separated by an exact element count. Maps are sorted by the
already-canonical key encoding and reject equal key encodings, so iteration
order cannot create a second output. Enums include a fixed variant index.

Therefore, for one fixed Rust/Serde schema and supported values,

```text
x != y  =>  Enc(x) != Enc(y),
```

unless the schema itself maps distinct semantic values to the same Serde data
model. This is a schema-relative property; Serde attributes and field order are
consensus changes.

Decoder round-trip follows by structural induction: each primitive consumes
its fixed representation; every compound visitor must consume its declared
arity; and top-level trailing bytes are rejected. The tests include fixed
vectors, malformed tags, hostile lengths, truncation, depth overflow,
non-canonical maps, output overflow, unknown-length sequences, unknown enum
variants, and a deterministic no-panic byte corpus.

## Compatibility rule

The fixed-width subset used by devnet v2 block headers and transactions remains
byte-compatible with the previously published encoding. CI verifies
`test-vectors/chain-identity-v2.json`; changing those bytes requires a new
consensus profile and new chain identity. Existing persistent objects containing
maps may require an explicit storage migration because v1 canonicalizes map
order by encoded key bytes.

Never add a fallback decoder to hash/signature paths. A migration decoder may
read an old storage record, but it must rewrite it under an explicit storage
format version before the value can enter a consensus digest.

