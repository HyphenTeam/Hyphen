# HYN3 identity, recovery and block coordinates

The development network starts from its own genesis. `hyphen-node --network neural-devnet --print-chain-identity` prints the expected magic `48594e33`, consensus digest `4f3b68f56eb14d9d022d2f6b970811b3d8d53f5a3f6db07f70763cd7e5c17d49` and genesis `710ad7eb105d56901495cf9c31f07f749cb812ddf3848f978e2bd133b7ebc926`. Each node, pool and wallet selects that identity before exchanging work or scanning outputs. [Identity vector](../test-vectors/chain-identity-neural-v3.json) · [Network configuration](../crates/hyphen-core/src/config.rs)

## Signature and hash inventory

| Use | HYN3 rule | Compatibility boundary |
|---|---|---|
| Miner authorization v2 | Sign the 32-byte BLAKE3 authorization digest with Ed25519. Verify the 64-byte signature strictly against the header's miner key. | The network magic selects the required authorization version. A v1 envelope fails HYN3 verification. |
| Mining | BLAKE3 challenge and commitment, BLAKE3 neural gate, keyed BLAKE3 scratchpad, BLAKE3 final digest. | ChaCha20 expands the public weights. Integer candidate mixing and fixed-point output folding are specified separately. |
| Private payments | The spending wallet constructs CLSAG signatures, Pedersen commitments and range proofs. | Miner authorization governs the reward keys. Transaction signatures retain their own verification rules. |
| New wallet recovery | Marked English words, BLAKE3 checksum, Argon2id and keyed BLAKE3 expansion. | Unmarked historical words use the original byte-preserving PBKDF2-HMAC-SHA512 derivation. |
| Wallet files | `HYWLT001`, BLAKE3 password prehash, Argon2id v19 and XChaCha20-Poly1305. | The envelope authenticates its header and ciphertext. Historical files retain a decoding path. |
| Peer transport | libp2p Noise over TCP and Yamux, network-specific sync, identify, discovery and gossip names. | Cryptographic primitives internal to standardized signatures, KDFs and secure channels follow their respective specifications. |

The authorization digest hashes the ASCII bytes `Hyphen/NCAP/block-authorization/v2`, `LE16(2)`, four magic bytes, 32-byte consensus digest, genesis hash, completed header hash, reward view public key and reward spend public key, in that order. Both reward keys are 32 bytes. The header's `extra_nonce` contains their domain-separated BLAKE3 commitment. The miner signs once the header is complete. The wallet and consensus layer use the same strict verifier. [Signature and reward commitment](../crates/hyphen-core/src/authorization.rs) · [Node admission](../crates/hyphen-consensus/src/chain.rs)

## Wallet creation and migration

The node CLI, Flutter wallet, miner and pool validate both compressed Ristretto recipient keys. Each key must decode to a nonidentity point. Text decoders also check the prefix, length, version and BLAKE3 checksum. The external-signer request accepts HYN3 test-class addresses and binds its request ID to the network magic and genesis. Hardware interoperability still requires a device implementing this signing protocol. [Shared key validation](../crates/hyphen-crypto/src/stealth.rs) · [Address decoder](../crates/hyphen-wallet/src/address.rs) · [External signer](../crates/hyphen-wallet/src/signer.rs)

The new encoder draws 128 to 256 bits of system entropy in steps of 32. Append the first `entropy_bits/32` bits of `BLAKE3-derive-key("Hyphen recovery checksum v3", entropy)`. Interpret consecutive groups of 11 bits as indices in the English BIP39 dictionary. Prefix the first word with `hy3-` and suffix the final word with `-hy3`. Use lowercase ASCII and one space between words. Record both markers. A checksum detects some transcription errors; its length is four bits for a 12-word phrase and eight bits for a 24-word phrase.

The original password enters `BLAKE3-derive-key("Hyphen wallet password prehash v1", password_utf8)`. Derive a 16-byte salt from the first half of `BLAKE3-derive-key("Hyphen recovery salt v3", complete_marked_phrase)`. Feed the prehash and salt into Argon2id v19 with 65,536 KiB, three passes, one lane and 32 output bytes. Use that output as the key for a 64-byte BLAKE3 XOF over `Hyphen recovery seed v3`, one zero byte and the complete marked phrase. The existing address derivation consumes this seed. Preserve the password along with a separate backup of the marked phrase.

1. Before upgrading, retain the original encrypted wallet, recovery words, password and a known receiving address. Retain the old node database and corresponding client version for historical balances and receipts.
2. Restore through the wallet's password entry point. Unmarked phrases select the historical password transform, SHA-256 mnemonic checksum and legacy seed derivation. Preserve internal whitespace and the original Unicode byte form. Adding markers to existing words changes their interpretation. Confirm the recovered address against the saved address before use.
3. Start a fresh HYN3 node directory and an independent pool ledger. Connect the HYN3 wallet to its trusted endpoint. Its output cache and transfer history are scoped to the new chain. Wait for a successful scan from genesis before reading the balance or spending. HYN2 balances, signed deliveries and pool debts are accounted for on HYN2. A new genesis starts a separate ledger.
4. To rotate recovery credentials on a funded chain, create a fresh recipient, back up its complete phrase and password, verify its address through recovery, and send an ordinary signed transfer on that same chain. Retain the sending wallet until the recipient confirms canonical inclusion and rescans. Record the transaction hash and fee. [Wallet operation](https://github.com/HyphenTeam/HyphenWallet/wiki/Operations) · [Wallet implementation](https://github.com/HyphenTeam/HyphenWallet/blob/main/rust/src/api/wallet.rs)

## Transport and resumption

The HYN3 sync protocol is `/hyphen/48594e33/sync/2`. Peers use magic-scoped discovery and gossip channels. Template Provider checks magic, consensus digest and genesis on its chain-bound request. The wallet pins these values and the advertised versions before trusting an RPC scan. Peer authentication, miner authorization and transaction authorization identify different participants and bind different data. [P2P protocol selection](../crates/hyphen-network/src/behaviour.rs) · [Template Provider](../crates/hyphen-node/src/main.rs)

Keep binary RPC and Template Provider on loopback or a trusted private link. For remote wallet or mining deployments, use an authenticated encrypted tunnel for any plaintext hop. Pool envelopes and share receipts authenticate messages. A proxy alone supplies routing. After reconnecting, verify the expected chain, request a fresh parent job, and scan from a matching canonical anchor. For a transfer whose acknowledgement was lost, retain its signed bytes and hash and check canonical inclusion before rebroadcast. Offline recipients retain their own signed invoice and validate the settlement after synchronization. [Peer operations](Operations-Peer-Network.md) · [Offline settlement](Offline-Payments.md)

## Three-dimensional block stack

Let `b` be the first raw byte of the 32-byte block hash. The coordinate cell is `(x, y, z) = (b >> 4, b & 15, height)`. Every height has a 16 × 16 plane. The API encodes `z` as a decimal string to preserve the complete `u64` space in JavaScript. The HYN3 genesis occupies `(7, 1, 0)`. Equal planar coordinates are possible, including among siblings at the same height. The full block hash identifies each block in the selector.

Draw an edge from a child to the block identified by its full `prev_hash`. The explorer reads the canonical window and retained fork positions under one chain-view lock. **Canonical** marks the current chain, **Validated fork** a previously accepted block, and **Staged body** a retained candidate without evidence of a successful state transition. The node retains detached identities across restarts. On upgrade it indexes historical detached bodies using the undo records, and staged bodies from the branch archive. **Refresh** reads the latest view from the node. The selector displays the complete selected hash even when siblings occupy the same cell.

The query `GET /api/blocks?branches=1&page=0&limit=20` returns up to eight extra blocks per height, ordered by hash within that height. `forks.truncated` flags additional siblings. The first page also checks the next 20 heights for a longer branch with less work. Edges to blocks outside the visible set are clipped. Screen orientation and page offsets do not enter block serialization or branch weight. [Explorer response](../crates/hyphen-explorer/src/lib.rs) · [Projection and edge rendering](../crates/hyphen-explorer/src/stack.js)

## 中文操作要点

HYN3 使用区块授权 v2。矿工签署完成后的区块头、链身份和两把奖励公钥，钱包据此核验首奖。新钱包恢复时必须保留首词 `hy3-`、末词 `-hy3` 和创建时的密码。旧钱包用原助记词和原密码恢复，并用已知收款地址核对结果。历史余额和离线凭证应在原链上核验。浏览器以高度为纵轴、区块哈希首字节的高低四位为平面坐标，连线依据完整父哈希。重新打开页面也可查看节点保留的已验证分支和暂存块体。
