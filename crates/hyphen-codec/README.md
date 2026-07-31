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

---

<!-- hyphen-bilingual-chinese -->

# Hyphen Codec v1（中文）

`hyphen-codec` 是 Hyphen 仓库内部用于协议、共识和持久化状态代码的规范序列化器。它取代了已停止维护的 `bincode` 依赖。该实现专为本仓库编写，没有引入或复制 bincode 的源代码。

本 crate 使用内存安全的 Rust（`#![forbid(unsafe_code)]`），并拒绝尾随字节、无界 Serde 序列、超大集合、过深嵌套、非法标量标签、非有限浮点数、非法 UTF-8 和非规范 map。它尚未接受独立安全审计。

## 线格式

所有整数均为固定宽度、小端序：

| Serde 值 | 编码 |
| --- | --- |
| `bool` | 一个字节，只允许 `0` 或 `1` |
| 有符号/无符号整数 | 二进制补码/固定宽度小端字节 |
| `f32`、`f64` | IEEE 位模式的小端编码；拒绝 NaN 和无穷大 |
| `char` | 一个 `u32`；拒绝代理项和超范围标量 |
| 字符串/字节 | `u64` 字节长度，随后为字节内容 |
| 序列 | `u64` 元素数量，随后为各元素 |
| 元组/结构体 | 按声明顺序编码字段，不编码名称或长度 |
| option | `None` 为 `0`；`Some` 为 `1` 后跟值 |
| enum | `u32` 声明顺序 variant 索引，随后为 variant 字段 |
| map | `u64` 键值对数量，随后按键的编码字节排序 |

map 的键必须具有互不相同的规范编码。编码器最多缓冲配置的输出预算，按键字节排序，并拒绝重复编码。解码器要求键的编码字节严格递增。因此，map 的序列化结果不受 `HashMap` 迭代顺序影响。

只有当一个值恰好消耗全部输入时，解码才成功。这是格式本身的规则，不是可选配置。

## 资源边界

默认限制为：

```text
max_bytes          = 64 MiB
max_collection_len = 1,000,000 elements
max_depth          = 128 compound levels
```

网络和共识调用方在协议已有更小限制时使用更严格的、按上下文区分的字节上限。分配集合前会检查长度，所有位置运算都经过溢出检查，序列/map visitor 必须恰好消费其声明的元素数量。

对于输入长度 `B`、集合上限 `C` 和深度上限 `D`，由解码目标 Serde 类型决定的最坏情况下，解码器拥有的内存为 `O(B + C)`，递归下降由 `D` 限制。codec 不会依据未经检查的线格式长度进行分配。

## 规范性论证

令 `Enc` 表示支持的 Serde 数据模型上的编码器。原始类型编码是单射，因为标签、宽度和字节序固定。相对于给定 schema，结构体和元组通过字段归纳得到单射性。序列由精确元素数量分隔。map 按已经规范化的键编码排序并拒绝相同键编码，因此迭代顺序不能产生第二种输出。enum 包含固定 variant 索引。

因此，对一个固定的 Rust/Serde schema 和受支持的值：

```text
x != y  =>  Enc(x) != Enc(y),
```

除非 schema 本身把不同语义值映射为同一 Serde 数据模型。这是相对于 schema 的性质；Serde attribute 和字段顺序的变化属于共识变更。

解码往返性质可由结构归纳得到：每个原始类型消耗其固定表示；每个复合 visitor 必须消耗声明的元数；顶层拒绝尾随字节。测试覆盖固定向量、非法标签、恶意长度、截断、深度溢出、非规范 map、输出溢出、未知长度序列、未知 enum variant，以及确定性的无 panic 字节语料。

## 兼容性规则

Devnet v2 区块头和交易使用的固定宽度子集与此前公布的编码保持字节兼容。CI 校验 `test-vectors/chain-identity-v2.json`；改变这些字节必须创建新的共识 profile 和链身份。由于 v1 按键编码字节规范化 map 顺序，包含 map 的现有持久化对象可能需要显式存储迁移。

绝不能在哈希或签名路径中添加回退解码器。迁移解码器可以读取旧存储记录，但必须在该值进入共识摘要前，以明确的存储格式版本重写它。
