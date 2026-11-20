# 双离线有条件付款 · Conditional offline payments

`offline-devnet`（`HYOF`）允许一笔已确认预锁经过最多 16 次离线整额转付，再由当前持有人独立签名结算。预锁为普通钱包交易的实际输出。离线接收只记一笔有条件索偿。只有在收款人自己核验的规范链上有结算输出时，在线钱包才将其计入余额。该开发网尚待独立密码学审计、安全认证和移动设备验收。

## 资金与身份

预锁条款绑定创世哈希、首位持有人的 Ed25519 公钥、随机数、总金额和结算费。锁定地址的支出点由 `hash_to_point` 导出。通过普通 CLSAG 支出这笔预锁需要知道该点的离散对数。资金方按条款派生的地址和精确总额打款；金额错误也会改变对应的锁定条件，可能造成永久损失。应保留条款、已签资金交易和收到的最新凭证，直到结算确认。助记词只能恢复签名密钥，无法恢复他人已签发而本机丢失的转付凭证。

每次转付中，收款人用自己的密钥对前一环摘要、公钥和新的随机数签名。付款人核对约定金额，用独立渠道确认预期收款公钥，再签署该请求。末端收款人核对留存的本次请求。双方在交付凭证前可保持断网。持有人可以继续转付或指定自己的常规钱包地址索偿。结算签名绑定完整转付历史、目标地址、选定链位置和范围证明。节点从规范链输出和签名条款复算唯一净额及手续费。

同一个预锁公钥和金额承诺产生相同的花费标识。即使钱包克隆、条款复制、离线链分叉、同一输出内容出现在不同位置，所有索偿仍竞争同一个标识。共识在一次数据库事务中写入花费标识和兑付输出。冲突分支各自可能有一笔临时确认，重组会撤销脱链标识和兑付。持有以前签名权的人仍可能抢先用较短的链索偿。谁先获得规范链确认取决于出块顺序和后续分叉选择，离线交付时间没有全局排序。

每一跳有两个签名角色：收款人签请求，当前持有人签授权。协议为每一任持有人登记一把公钥；现有签名器没有 M-of-N 门限托管接口。多人串谋或控制同一把密钥时，可以产生彼此竞争的有效授权。即使所有转付签名都有效，收款人仍依赖自己验证的预锁、约定净额和规范链上的实际赢家来确认这一单。

## 操作

在主仓构建 `hyphen-offline` 和 `hyphen-node`。在独立钱包仓构建 `hyphen-reserve-wallet`。节点、矿池和矿工均选择 `--network offline-devnet`。带签名、钱包余额和地址派生的命令从标准输入读取本人的原始 64 字节 BIP39 种子。`--account` 选择离线授权账户，默认值为 0。在线准备工具使用常规钱包账户 0。输出文件采用新文件名。离线端之间仅传递公开的预锁凭证、收款请求和签名转付文件。

```sh
cargo build --release --locked -p hyphen-node --bin hyphen-node --bin hyphen-offline
cargo build --release --locked --manifest-path HyphenWallet/rust/Cargo.toml --bin hyphen-reserve-wallet
```

| 操作 | 命令 |
| --- | --- |
| 首位持有人生成条款，保存屏幕打印的锁定地址 | `hyphen-offline reserve GROSS FEE terms.bin` |
| 在线钱包签署普通付款，随后广播已保存交易 | `hyphen-reserve-wallet prepare RPC LOCK_ADDRESS GROSS FUNDING_FEE funding.tx`，然后 `hyphen-reserve-wallet submit RPC funding.tx` |
| 资金交易确认后，在自己的已停止节点数据库定位收款输出并导出凭证 | `hyphen-offline locate NODE_DB FUNDING_TXID 0`，然后 `hyphen-offline issue NODE_DB terms.bin INDEX offer.bin` |
| 每个参与方在断网前用自己的已验证节点安装检查点 | `hyphen-offline checkpoint OWN_NODE_DB own.ck own-wallet-db` |
| 收款人发送请求，以独立渠道向付款人提供其授权公钥 | `hyphen-offline request own.ck offer.bin NET own-wallet-db request.bin`，公钥可用 `hyphen-offline public-key` 核对 |
| 付款人用自己的检查点、原凭证和同一持久化钱包日志签署转付 | `hyphen-offline transfer payer.ck offer.bin request.bin RECIPIENT_KEY NET payer-wallet-db delivery.bin` |
| 收款人核验返回文件 | `hyphen-offline accept own.ck delivery.bin request.bin NET own-wallet-db`，`new=false` 表示重复导入 |
| 末端持有人离线签署兑付，任何转发者可在联网后提交原文件 | `hyphen-offline redeem own.ck delivery.bin PAYOUT_ADDRESS NET own-wallet-db claim.tx`，然后 `hyphen-offline submit claim.tx --rpc RPC` |
| 从收款方自己的节点确认一笔到账 | `hyphen-offline confirm OWN_NODE_DB delivery.bin request.bin OWN_PAYOUT_ADDRESS NET --min-confirmations N` |
| 从运行中的自有节点核对同一笔订单并保留签名交易 | `hyphen-offline confirm-online --rpc 127.0.0.1:48333 delivery.bin request.bin OWN_PAYOUT_ADDRESS NET --min-confirmations N --save-settlement observed.tx` |
| 离线复核冲突签名 | 两份交付凭证用 `hyphen-offline verify-conflict delivery.bin other.bin`。另一份材料是签名兑付交易时用 `hyphen-offline verify-conflict delivery.bin observed.tx --settlement` |
| 查询竞争索偿及可花余额 | `hyphen-offline status OWN_NODE_DB delivery.bin --expected-tx CLAIM_TXID`；用 `hyphen-reserve-wallet balance RPC` 重扫自己的运行中节点 |

每笔订单保留收款方自己生成的 `request.bin`、预期净额和自己的常规钱包地址。`confirm` 读取自己已同步并停止的完整节点，核对该预锁的规范兑付、末端授权、请求、目的地址、金额及确认深度。只有全部匹配才以退出码 0 输出 `status=confirmed`。默认深度为 1，即首次入块，后续重组仍可撤销它。每次查询都会重新计算结果。业务账本可用 `reserve_spend` 作为唯一键，保存对应的收款请求、交易号及区块哈希；重试更新同一条记录，重组后重新核验并撤销失效入账。`accept` 产生的 `conditional_receipt` 仅代表离线索偿。即使付款方创建或丢弃许多钱包，收款方的检查点和节点仍逐笔验证真实预锁。

`NET = GROSS − FEE`。首次普通付款的 `FUNDING_FEE` 单独支付。继续转付时，将 `delivery.bin` 用作下一轮的 `offer.bin`。节点数据库命令使用已关闭的本地数据库；提交和扫描命令使用运行中的 RPC。若资金交易重新确认在另一位置，当前持有人可用 `locate` 获取新索引，用 `hyphen-offline refresh NODE_DB delivery.bin NEW_INDEX renewed.bin` 更新证明，安装新的本地检查点，再用同一日志和同一目的地址重签。若资金交易本身脱链且未重新确认，索偿没有规范链资金可供兑付。

### 甲经乙向丙付款

丙用自己断网前安装的检查点检验预锁，再对自己留存的订单验签。甲在自己的数据库中虚构资金，即使乙签名转交，丙也无法验出对应的规范链预锁。若检查点尚未覆盖资金证明所在的区块，丙必须先同步自己的节点并更新检查点。对确有资金的付款，丙可以在甲、乙均失联后独立签署和提交兑付。检查点之后有人从同一预锁另行兑付的风险，持续到丙恢复联网并重新核验。需要以到账为条件交货的订单，应等到自己的节点确认该请求、地址、净额及约定深度后再交货。

`confirm-online` 使用本机回环地址上的自有同步节点，在一次链状态读取中取得链顶、花费标识对应的交易、区块及资金输出。客户端复核签名和兑付条款。仅进入交易池、节点离线、查询失败或确认深度不足时，订单均不能据此入账。重组后按原订单再查一次：若另一笔授权胜出，原确认作废；若节点暂时不可达，当前状态待核验。`--save-settlement` 可选，会保存当时观察到的规范兑付原文，包括竞争方的有效兑付。相同字节可重复保存，换链后请为新交易使用新文件名。留存原交易及查询时的区块哈希，日后可分别核对谁签过什么，以及当时观察到哪一条链。

`verify-conflict` 会验证两条完整授权链。若同一公钥从同一前序状态授权两份不同的请求，结果给出公钥、前序摘要及两份请求摘要。若旧持有人既签出转付，又在同一状态签署兑付，搭配原始兑付交易可验证 `redeemed_and_delegated_by`。仅有一条授权链及其前缀不足以证明双签。上述离线证据可以验证密钥行为；确认交易是否仍在规范链上需要自有节点。协议未登记现实身份，也没有自动赔付资金来源。

## 检查点、恢复和数据开销

本机日志先持久化签名决定，再对外释放文件。同一次请求重试可重新生成签名；对同一状态改签另一收款人会被拒绝。日志将检查点与本机随机认证密钥、链顶、累计工作、链高及已花数量绑定。只更换检查点文件、修改其中读取的单元或向保留原日志的钱包安装累计工作更低的快照都会失败。复制或回滚整个设备仍可产生冲突签名。恶意设备也能伪造自己的显示。诚实收款人必须信任自己的验证设备和自有节点数据，并能独立获得预锁所在历史的检查点；来自交易对手的数据库或导入日志不能作为信任根。上次同步后发生的结算只能在恢复联网后发现。

凭证文件和结算交易上限为 8 KiB，索偿附加数据上限为 4 KiB。Merkle 路径固定为 32 个哈希。检查点占用 `64 + 64 × (链高 + 1 + 已结算预锁数)` 字节磁盘，包含每个历史输出根和已排序的花费标识。离线核验按位置读取一个根，二分查找已花集合并逐个验证读取的数据单元。生成检查点需顺序读取区块历史。新钱包采用页缓存预算为 2 MiB 的 redb 事务日志，打开旧 sled 日志时继续使用其中的签名决定和检查点。凭证及结算会披露金额、转付公钥链和兑付目的地址。

## 开发网实测

在同一台 Windows x64 主机上，各方分别从创世重放资金历史并安装检查点。高度 8 的普通付款 `c671da6b17f05c819a3f71b52d5c35e8e9159d2e0c3e18647b9d649c1084cf09` 锁入 10,000,000 原子单位。两跳凭证的索偿在高度 9 确认，持有人实际扫到净额 9,000,000。另一节点从共同父块出发，将竞争凭证打包，独立挖出更重历史。两个节点通过本机 TCP 重连后，原收款人余额归零，新收款人扫到 9,000,000。另建数据库分别从创世重放两份归档，恢复对应的高度 9 和高度 10 链顶。新收款人随即使用普通 CLSAG 交易付出 7,000,000，找零 1,000,000，手续费 1,000,000。

| 离线转付次数 | 交付凭证 | 签名结算交易 | 重复接收耗时中位数 | 进程峰值工作集（五次中的最大值） |
| --- | ---: | ---: | ---: | ---: |
| 2 | 1,552 B | 1,631 B | 11.19 ms | 5.51 MiB |
| 16 | 4,240 B | 4,319 B | 14.25 ms | 5.52 MiB |

每次测量均另起 release CLI 进程，重新打开钱包并完整验签。计时含进程启动和数据库访问。内存取自 Windows `GetProcessMemoryInfo` 的 `PeakWorkingSetSize`。同机同用例使用原 sled 日志时，16 跳五次复测的最高峰值为 27.32 MiB。上述数字对应开发网短历史及 i7-11850H 主机，手机和大规模已花集合的成本尚待测量。运行记录位于 `target/offline-settlement-8z1a2lao/result.json`，原日志基线位于 `target/offline-settlement-9pbqd3kh/result.json`。脚本会为每次运行创建独立目录。[验收脚本](../scripts/test-offline-payments.py)

## 重组与资源复核记录 · Reorganization and storage measurements

同笔已签资金交易 `77fbe05d2468440accf2bd747be6b09a0367d38c52b7d4f00f1909eecc4258dc` 最初在高度 7、输出索引 6 确认。末端结算后，节点通过 P2P 跟随另一条较重历史，原结算脱链，资金交易在高度 13、索引 12 重新确认。末端钱包单独刷新证明、安装新检查点并重签，同一请求重复接收返回 `new=false`。索偿 `9e03dc3ed59255b7c688cda589658fb717df46d49b0f11562c69a211b4d04e4d` 在高度 14 兑付 9,000,000。另建数据库重放至同一链顶 `4446af5e72b537271242b34c51f5bd7c3aceee4c9297571fad5ec3505336970e`。同轮还验证了进程独占日志、终止读种子的进程后重开，以及签名决定已提交而交付文件发布失败后用新文件名重试。断电时的设备写入持久性仍待实机验证。原始记录在 `target/offline-settlement-42kvy6_f/`。

In this run the original funding transaction moved from output 6 to output 12 after the node adopted a heavier history. The terminal holder reused the original two-hop delegation, installed a checkpoint from the updated local node and claimed 9,000,000 at height 14. Replaying the archive into a fresh database reproduced the block hash and claim status. Independent checks exercised exclusive journal access, process termination during seed input and a failed output-file publication after a signing decision had committed.

20 万个确定性测试叶子组成的承诺树占用 14,733,485 字节未压缩快照。用同一份旧格式数据库交替启动优化前后的 release 进程，每种操作各测 5 次，页缓存预算均为 2 MiB。打开数据库并核对中间叶子证明的最高工作集从 90.59 降至 85.14 MiB；打开、追加一个叶子、持久化并核对证明的最高工作集从 122.27 降至 97.75 MiB。每个追加进程使用原数据库的新副本。两版产生相同根。完整节点仍会加载所有树节点，undo 日志仍存储前一棵树。完整区块吞吐和大量已结算预锁的检查点导出需要另外测量。原始样本在 `target/offline-state-profile/measurements.json`。

For a storage-only benchmark, the two release builds read the same 200,000-leaf snapshot generated by the earlier implementation. Across five processes per operation, maximum working set fell from 90.59 to 85.14 MiB for reopening and verifying a proof, and from 122.27 to 97.75 MiB for reopening, persisting one appended leaf and verifying a proof. These are constructed leaves. The benchmark measures the persistent commitment tree in isolation. Full-chain growth also depends on block validation, undo records and the number of settled reserves.

## 签名日志与升级 · Signing journal and upgrades

冻结版使用 redb 5.0.0。该候选的四仓验收中，两跳和十六跳凭证分别为 1,552 和 4,240 字节。重复验收中位数分别为 11.18 和 11.85 ms，最高工作集均为 5.68 MiB，每项各五个新进程。冻结版另外在 20 对竞争转付、5 份截短日志和 12 份不完整交付材料上复核了拒绝路径。竞签均仅交付一份；不完整材料全部被拒，完整材料随后能首次接收并幂等重试。数据见候选包 `settlement/result.json` 和 `checks/journal-upgrade.json`。

新日志在同目录创建并同步完整数据库，以不覆盖已有文件的方式发布。签名器使用 redb 5.0，先取得与旧版相同的整文件独占锁，再校验数据库并打开原钱包记录表。签名决定使用两阶段持久提交。旧 redb 3.1 日志保留已收凭证和已签请求，旧 sled 日志继续在原目录打开。Windows 上实测新旧两个进程分别先持锁，另一版均拒绝打开。5 份截短日志在 8 秒限时内均报错，文件摘要保持一致。20 对竞争转付均恰有一个进程发布凭证，释放锁后另一请求仍因冲突被拒绝。记录在 `target/offline-journal-upgrade-3zkey2f0/result.json`。

用 redb 5.0 对 26 份相同初始日志分别运行一次转付，在写入种子后的不同时间尝试终止签名进程。实际终止的 18 次中，13 次未提交决定也未发布文件，2 次已提交决定但尚未发布，3 次已提交并发布。其余 8 次在终止前已成功返回。所有已发布文件均由收款人独立验过。全部 26 次重开后都能重试原请求并得到相同字节，随后对竞争请求均拒签。另一次验收将检查点、请求、交付凭证各截至四种长度，12 次导入均被拒绝，随后完整导入首次返回 `new=true`，再次返回 `new=false`。记录在 `target/offline-interrupt-ribe3xdl/` 和 `target/offline-partial-p5ml6_4e/`。进程终止时操作系统和设备仍有供电。

The signer takes the legacy OS file lock before inspecting a redb wallet, verifies the database on open and persists each signing decision in a two-phase commit. The upgrade preserved the old sender's decision and the terminal wallet's receipt after reindexing. With the same release executable, two-hop receipt verification took a median 19.48 ms on sled and 11.61 ms on redb 5.0, with maximum working sets of 27.32 and 5.69 MiB. At sixteen hops the medians were 23.17 and 13.74 ms and the maxima were 27.33 and 5.63 MiB. Each figure covers five new processes after receipt installation. Samples and signer digest are in `target/offline-journal-comparison-68k7q14z/measurements.json`.

## 检查点随历史增长的实测 · Checkpoint scaling

在独立的 `HYOF` 数据库中，测试程序按 30 秒的区块时间戳间隔生成有效工作量和矿工签名，把每个区块奖励付到一笔新的预锁。第 1 笔保留未花，第 2 笔的凭证保留作已花检查；从高度 3 开始，每个块结算上一块的一笔预锁。生产验证器接受了全部 1,024 个块。用 release 节点另建数据库从创世重放，得到相同链顶 `5500d899aa27b71d9702217f5448876e62d468f717cebd292034dec3dd285db8`。这组构造的开发网付款用于测量检查点，其出块间隔不代表实际挖矿速度。

| 链高 / 已结算预锁 | 检查点字节 | 导出中位数 / 最高工作集 | 离线重复接收中位数 / 最高工作集 |
| ---: | ---: | ---: | ---: |
| 2 / 0 | 256 | 56.15 ms / 28.41 MiB | 23.30 ms / 5.64 MiB |
| 128 / 126 | 16,384 | 61.12 ms / 28.82 MiB | 22.25 ms / 5.67 MiB |
| 1,024 / 1,022 | 131,072 | 84.07 ms / 31.39 MiB | 15.24 ms / 5.66 MiB |

Each cell summarizes five new Windows release CLI processes using the redb 5.0 signer and the same archived blocks. Export includes reopening a stopped full-node database, writing the authenticated file and committing the wallet pin. Acceptance rechecks the original one-hop voucher against each new checkpoint. At height 1,024 all five attempts to import the second, already settled reserve failed, with a median of 16.88 ms and maximum working set of 5.56 MiB. Samples and the signer digest are in `target/offline-checkpoint-recheck-vzxgnerj/result.json`. The original archive, replay tip and earlier redb 3.1 samples are in `target/offline-history-13f7b1adf33f4f99b630810eb711234e/`.

### 完整区块提交与回退 · Block commit and rollback

同一份归档的三个高度各取五份相同的父状态数据库副本。每个待提交块都含有一笔索偿和一笔区块奖励。分别在新进程中验块并提交、按节点重组路径原子回退，再重开核对父链顶、承诺树根与已花集合根。耗时取操作本身和数据库刷新，不含启动；内存取整个进程的最高工作集。Undo 大小是该块在 `block_undo` 中的压缩值字节数。

| 块高 / 父状态输出数 | 验块提交中位数 / 最高工作集 | 回退中位数 / 最高工作集 | 单块 undo |
| ---: | ---: | ---: | ---: |
| 3 / 2 | 44.92 ms / 28.01 MiB | 1.25 ms / 27.21 MiB | 1,475 B |
| 128 / 252 | 44.90 ms / 28.90 MiB | 1.71 ms / 27.97 MiB | 18,320 B |
| 1,024 / 2,044 | 58.66 ms / 31.85 MiB | 4.12 ms / 29.89 MiB | 145,743 B |

The parent at height 1,023 held 75,015,400 bytes of compressed undo values before the measured block. Undo retains the previous output tree, so block count alone cannot predict long-term disk use. The 200,000-leaf measurement above exercises tree storage separately. Raw block trials and the input archive digest are in `target/offline-block-profile-eils2evz/result.json`.

## English protocol and operations

To confirm an order, supply the recipient's retained invoice, expected net amount and payout address to `hyphen-offline confirm`. The command reads the recipient's synchronized, stopped node and exits successfully only after the matching settlement has reached the requested depth on that node's canonical chain. The default is one block. The returned `reserve_spend` stays the same across retries, competing authorizations and funding relocation. Use it as a unique ledger key and reconcile its block hash after a reorganization. A sender can discard every wallet it created without affecting these checks. Offline acceptance establishes a conditional claim until settlement.

With your own synchronized node running, use `confirm-online` as shown in the command table. The node reads the source, spending transaction, block and tip in one chain state. The client verifies the signed claim and checks it against the retained order. A mempool entry, insufficient depth or an unavailable node leaves that order unconfirmed by the query. Recheck after a reorganization. Use `--save-settlement` to preserve the signed transaction even when a competing receipt won. Use a fresh filename for a different winner. The saved transaction and signed delivery allow `verify-conflict --settlement` to identify a key that both delegated and redeemed the same state, or authorized two different requests from it. Two delivery files alone can prove the latter. Offline signature evidence survives a reorganization. Canonical inclusion, the operator's legal identity and compensation each require separate evidence or arrangements.

Each hop uses one recipient key to sign the request and one current-holder key to authorize delivery. The current signer exposes a single holder key per hop. M-of-N custody is outside this signer. Colluding key holders can authorize competing histories. The canonical reserve marker still limits the chain to one payout, and each recipient checks their retained order against that payout.

On `hyphen-offline-devnet-v1`, fund one whole reserve with an ordinary signed shielded payment. The reserve address commits to its initial holder, chain, nonce, gross amount and settlement fee. Before going offline each participant installs a checkpoint from their own verified node. The recipient checks inclusion, net value, prior signatures and the spent set at that checkpoint, then signs a fresh request. The payer verifies the intended recipient key out of band and countersigns the request. The recipient checks the delivery against their retained request. Each transfer consumes one of sixteen available hops. Anyone can relay the terminal holder's signed withdrawal. The transaction creates a regular spendable wallet output for the gross amount less the fixed fee.

The command table lists the arguments in execution order. `reserve`, `public-key`, `request`, `transfer`, `accept` and `redeem` read the owner's raw 64-byte BIP39 seed on stdin. The independent wallet's `address`, `balance` and `prepare` commands use the same seed format. `RPC` is a socket address. `NODE_DB` is a stopped verified node database. Keep the funding terms and latest signed packet with the wallet backup. The recovery phrase restores keys. The packet carries the other parties' authorizations. Each party retains its own journal and checkpoint. Archived funding or claim bytes can be relayed again and their canonical location checked after a disconnect.

All branches for the same reserve share a spent marker. Canonical block application writes the marker and payout atomically. A heavier branch may replace the winner. Previous holders can copy their signing state and race the terminal holder. The receipt remains conditional until canonical settlement. A locally authenticated checkpoint covers history through its recorded tip. An intact journal rejects lower-work checkpoint imports. Full-device rollback permits conflicting signatures and stale offline views. Settlement reveals amount, delegation keys and payout address. This software has development-network tests. External certification, independent cryptographic review and mobile NFC acceptance remain outstanding.

Run `python scripts/test-offline-payments.py` after building the node, offline signer, reserve wallet, miner and pool in release mode. The script independently replays funding history, tests 2- and 16-hop deliveries, confirms competing withdrawals on isolated branches, rejoins two nodes over local TCP, scans both wallets after the reorganization and spends the winning payout through ordinary CLSAG. Each run retains the two settlement archives, signed transactions and raw timing samples. In the Windows run above, maximum working set during 16-hop receipt verification fell from 27.32 MiB with the legacy journal to 5.52 MiB with redb. The five fresh-process samples include CLI startup and database access. True independent-device NFC and public-network partition tests remain outstanding.
