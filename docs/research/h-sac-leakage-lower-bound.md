# H-SAC：合规任务的最小泄漏下界

状态：理论边界与接口规范。当前代码只有单输出明文 opening disclosure，不是本文
所述近最优零知识协议。

## 1. 问题变量

令：

```text
X : 用户的完整私有状态（金额、opening、真实输入、凭证、交易关系）；
P : adversary 在协议前已知的公开链信息；
Y = F(X,P) : 合规任务输出；
V : adversary 最终视图，包括 transcript、公开输出、错误和 timing。
```

`F` 必须是可判定的具体任务，例如“选定承诺对应金额之和是否低于阈值”或
“真实来源 credential 是否属于给定 policy root”。“资金合法”不是无需外部信任
即可计算的数学谓词；名单签发、现实身份和政策正确性属于 `P` 中的外部假设。

所有信息量相对明确分布 `(X,P)` 定义。没有分布时，Shannon leakage 数字没有
意义；只能给出 worst-case indistinguishability/simulation 定义。

## 2. 零错误下界

假设 auditor 从 `(V,P)` 零错误恢复 `Y`，即

```text
H(Y | V,P)=0.
```

因为 `Y=F(X,P)` 是确定函数，链式法则给出：

```text
I(X;V | P)
 = I(X,Y;V | P)
 = I(Y;V | P) + I(X;V | Y,P)
 >= I(Y;V | P)
 = H(Y | P) - H(Y | V,P)
 = H(Y | P).
```

### 定理 SAC-N1（任务输出下界）

任何让 auditor 正确判定 `Y` 的协议，对其视图的条件互信息泄漏至少为

```text
Leak(X -> V | P) >= H(F(X,P) | P).
```

这是功能本身不可避免的泄漏，不依赖使用 view key、SNARK、MPC 或可信硬件。

## 3. 有错误版本

令 `Y` 的值域大小为 `M>=2`，auditor 输出 `Y_hat(V,P)`，错误率
`Pr[Y_hat != Y] <= epsilon`。Fano inequality 给出：

```text
H(Y | V,P) <= h_2(epsilon) + epsilon log_2(M-1),
```

其中

```text
h_2(epsilon)=-epsilon log_2 epsilon
             -(1-epsilon)log_2(1-epsilon).
```

代回链式法则：

```text
I(X;V | P)
 >= H(Y | P)-h_2(epsilon)-epsilon log_2(M-1).
```

对 boolean 合规输出 `M=2`，下界为 `H(Y|P)-h_2(epsilon)`。允许误判可降低
必要信息，但监管任务通常不能把假阴性/假阳性隐藏在一个未声明的 `epsilon` 中。

## 4. 何谓“达到下界”

### 4.1 完美 task privacy

若

```text
I(X;V | Y,P)=0,
```

则给定公开信息和必要任务输出后，view 不再包含关于 `X` 的额外信息。此时

```text
I(X;V | P)=H(Y|P)
```

（零错误条件下），协议正好达到下界。

等价 simulation 表述：存在 simulator `Sim`，仅输入 `(P,Y)`，其输出分布与真实
`V` 相同。密码学协议通常只能要求 PPT adversary 下计算不可区分：

```text
Real(X,P) ~=_c Sim(P,F(X,P)).
```

这给出 computational near-optimality，而不是无条件 Shannon 等式。

### 4.2 worst-case transcript 下界

零错误 deterministic auditor 至少要区分 `F` 在给定 `P` 下仍可能产生的输出
等价类。若有 `R_P=|{F(x,P)}|` 个可达输出，则最坏情况 view 至少需要
`log_2 R_P` bits 的区分能力。该陈述不等于平均互信息，二者不能混写。

## 5. 多次披露会组合泄漏

对自适应任务 `Y_j=F_j(X,P,V_<j)` 和联合视图 `V_(1:q)`，正确回答所有任务时：

```text
I(X;V_(1:q) | P) >= H(Y_1,...,Y_q | P)
```

（有错误时减去对应 Fano 项）。即使每次证明单独是 task-optimal，多次 boolean
查询也可能逐步定位 `X`。因此 H-SAC 必须有：

- capability scope 和 task identifier；
- 查询/披露预算；
- expiry 与 revocation；
- 用户可审计的 disclosure log；
- 禁止 auditor 把窄任务改写成高基数输出。

revocation 只能阻止未来验证或解密，不能让已知 transcript 从 auditor 记忆中消失。

## 6. 链上公开信息必须先扣除

`P` 至少包括链 ID、区块时间、交易大小、fee、commitment、nullifier、公开脚本和
网络层可观察信息。下界使用 `H(Y|P)` 而不是 `H(Y)`，因为公开链可能已经泄漏
任务输出的一部分或全部。

反过来，零知识 proof 不会自动隐藏 timing、proof size、失败原因、RPC source IP
或 capability 请求模式。这些都属于现实 `V`，必须进入实现 threat model。

## 7. H-SAC' 候选关系

公开 statement：

```text
Z=(cid, task_id, task_output Y, scope, expiry, auditor_pk,
   selected_commitments, input_nullifiers, policy_root, inclusion_roots).
```

私有 witness：

```text
W=(values,blindings,spend_secrets,real_ring_indices,
   ownership_paths,policy_credentials,policy_paths).
```

电路关系 `R_F(Z,W)=1` 必须同时约束：

```text
commitment openings correct;
ownership/nullifier relation correct;
selected objects included in authenticated chain state;
credential accepted by policy_root;
scope/task_id/auditor/expiry bound into statement;
F(W,public chain facts)=Y;
transaction balance relation holds where relevant.
```

协议输出应是 auditor-addressed encrypted capability 加零知识 proof。proof 的
auditor binding 不能替代加密：公开包中出现 `auditor_pk` 只防止跨 auditor 重放，
不能阻止其他拿到包的人读取明文字段。

若最终证明系统对关系 `R_F` 满足 completeness、knowledge soundness 和 zero
knowledge，并存在只用 `(P,Y)` 的 transcript simulator，则它在计算意义上接近
SAC-N1 下界。还必须单独证明 chain inclusion、credential issuer 和 encryption。

## 8. 当前实现离下界有多远

`crates/hyphen-wallet/src/audit.rs` 的 v0 package 明文公开：

```text
chain_id, txid, output/global index, auditor key, scope, validity,
nonce, commitment, one-time public key, amount, blinding, Schnorr proof.
```

代码现在通过 `DISCLOSED_FIELDS_V0` 返回机器可读泄漏清单。该包证明金额 opening
和一次性密钥所有权，但 amount 与 blinding 都直接进入 `V`。如果任务 `F` 只需要
一个合规 bit，v0 显然远高于 `H(F(X,P)|P)` 的理论下界。

当前 proof 也不证明：

- txid 已包含在 canonical chain；
- `global_index` 与输出位置一致；
- 真实 ring input 或来源路径；
- policy credential；
- 现实世界“合法性”；
- 包只对 auditor 可读。

所以 v0 应称 targeted opening disclosure，不应称完整 audit key 或最优选择性透明。

## 9. 为什么此时不接入一个新 ZK crate

通用 proof system 的选择会固定 field、curve、trusted setup、proof recursion、
电路审计和长期兼容性。主链已有 `hyphen-codec` v1，但 H-SAC 关系的公开输入 schema、
版本迁移规则及 provenance policy 尚未固定。
在这些输入不稳定时接入任意 proving library，只会产生不能证明目标关系的代码。

生产接入前至少需要：

1. 固定 `F`、公开输入和 leakage ledger；
2. 选取维护中且有外审的证明系统；
3. 固定 circuit/constraint hash 和参数生成流程；
4. 发布正负向跨实现 vectors；
5. 做 soundness、zero-knowledge、side-channel 和 malformed-proof 审查；
6. 再接交易、区块验证、状态根和 RPC。

当前 `circom 2.2.3` 可执行文件只证明开发环境能编译 Circom 源码，不代表已经定义
正确关系。现有链使用 Ristretto255/BLAKE3，普通 Circom 位于 BN254 标量域；把
256-bit digest 直接取模为一个 signal 不是单射，无法证明原始 digest 相等。必须
约束完整 bit decomposition、BLAKE3 和 Ristretto 编码/群等式，或引入一个与现有
commitment 有严格 binding proof 的版本化 field-friendly relation。详细门槛见
[`cryptographic-activation-gates.md`](../security/cryptographic-activation-gates.md)。

仓库当前没有 H-SAC Circom 源、R1CS、proving/verifying key、Rust verifier 或正负向
跨实现向量，也没有外部审计报告。因此“经过审计的 H-SAC ZK 电路”这一项当前明确
是未完成，而不是通过文档或单元测试可以内部宣告完成的事项。

## 10. Prior-art 边界

Monero view key/payment proof、Zcash viewing/payment disclosure、匿名凭证选择性披露、
可撤销凭证和通用 ZK/MPC 都已覆盖“向指定方证明部分事实”的大量设计空间。
当前可核验入口包括：

- Zcash Protocol Specification 与 ZIP-310:
  <https://zips.z.cash/protocol/protocol.pdf>，<https://zips.z.cash/zip-0310>；
- *Practical Revocable Anonymous Credentials*, FC 2012,
  DOI `10.1007/978-3-642-32805-3_22`。

可研究贡献应落在“给定公开链侧信息后的任务条件泄漏、组合查询预算和达到下界的
simulation 证明”，而不是重新命名 view key。正式新颖性仍需系统文献和专利检索。
