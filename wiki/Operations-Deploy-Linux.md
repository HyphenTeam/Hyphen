# Deploying a Hyphen node on Linux

This is the operator runbook for a single full node under `systemd`. It covers
the "local devnet" and "private multi-node" stages of
[incentivized-testnet.md](Operations-Incentivized-Testnet); the entry blockers listed
there are still open, so nothing in this guide makes a balance worth money.

Every `hyphen-node` command below was executed against a binary built from this
tree on Linux (Ubuntu 24.04, Rust 1.97.1). The unit file passes
`systemd-analyze verify`; the `systemctl` steps themselves need a real host.

## 1. Host requirements

| Item | Requirement |
| --- | --- |
| OS | Linux with systemd (Ubuntu 22.04+, Debian 12, RHEL 9) on x86_64 or aarch64 |
| CPU / RAM | 2 vCPU / 4 GB. sled keeps its cache in RAM; 2 GB runs devnet but leaves no headroom for sync spikes. |
| Disk | Local SSD, mounted normally (not NFS). Measure growth during your own sync test and size the volume above it. |
| Inbound | TCP on the P2P port only (see §5) |
| Outbound | TCP to boot nodes, and **UDP 123**. The node runs its own SNTP client and applies the measured offset to the local clock; fewer than three responding servers, or offsets disagreeing by more than 2 s, mark the clock untrusted and log a warning. Block-time validation reads that adjusted clock. |
| Toolchain | Rust 1.97.0 (pinned by `rust-toolchain.toml`), a C compiler and linker (`zstd-sys` compiles the bundled zstd), `git`, `curl` |

## 2. Build

Build on the machine you deploy to, then ship the binary; cross-building is
not supported by this tree.

```bash
sudo apt-get update
sudo apt-get install -y build-essential git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
. "$HOME/.cargo/env"

git clone https://github.com/HyphenTeam/Hyphen.git
cd Hyphen
cargo build --release --locked -p hyphen-node
```

`rust-toolchain.toml` installs 1.97.0 on first use and `--locked` builds the
committed `Cargo.lock` — the dependency set CI validates. Build the node
package rather than the whole workspace: `-p hyphen-node` is what you deploy,
and a workspace build additionally compiles test, fuzz and explorer assets that
have no place on a node.

Record the identity before you install anything:

```bash
./target/release/hyphen-node --network devnet --print-chain-identity
```

Expected for the current devnet profile:

```text
network=hyphen-devnet-v2
network_magic=48594456
consensus_params_hash=521f6cdc47f4424c1ea7b9f4d6770cf114f620cdff62958060f8c6953cb69de8
genesis_hash=5f7c144f0ef27880259b2429e46ef175685da679916fcc6b80c45f457465e32d
```

If those lines differ from what your peers publish, you built a different
chain — stop here.

## 3. Install

```bash
sudo useradd --system --home /var/lib/hyphen --shell /usr/sbin/nologin hyphen
sudo install -d -o root  -g root   -m 0755 /opt/hyphen /opt/hyphen/bin
sudo install -d -o root  -g root   -m 0755 /etc/hyphen
sudo install -d -o hyphen -g hyphen -m 0750 /var/lib/hyphen

sudo install -o root -g root -m 0755 target/release/hyphen-node /opt/hyphen/bin/hyphen-node
sudo install -o root -g hyphen -m 0640 deploy/systemd/node.env.example /etc/hyphen/node.env
sudo install -o root -g root   -m 0644 deploy/systemd/hyphen-node.service /etc/systemd/system/hyphen-node.service
```

`/var/lib/hyphen/data` holds the sled database; `/var/lib/hyphen/data/p2p_identity.key`
is the node's libp2p key and is created with mode `0600`. That key is the
node's network identity: losing or leaking it changes who your peers think you
are.

## 4. Configure

Edit `/etc/hyphen/node.env`:

```bash
sudoedit /etc/hyphen/node.env
```

- `HYPHEN_NETWORK` — `devnet`, `testnet` or `mainnet`.
- `HYPHEN_P2P_PORT` — must match the firewall rule in §5. Network defaults:
  mainnet `18334`, testnet `38334`, devnet `48334`.
- `HYPHEN_RPC_PORT` — mainnet `18333`, testnet `38333`, devnet `48333`.
- `HYPHEN_BOOT_NODES` — comma-separated multiaddrs, each ending in
  `/p2p/<peer-id>`. An address without a peer id is rejected at startup
  because it cannot be authenticated. Empty is valid on devnet/testnet;
  **mainnet refuses to start without at least one** (a first seed node uses
  `--allow-isolated-mainnet` manually instead).

The unit keeps the RPC, the template provider and the explorer on loopback and
binds only the P2P port publicly. Leave it that way: those three services have
no authentication and no rate limiting yet.

Your own peer id appears once per start in the journal:

```bash
journalctl -u hyphen-node -n 50 --no-pager | grep 'local peer ID'
```

The other operators' nodes are pointed at `/ip4/<your-ip>/tcp/<p2p-port>/p2p/<that-id>`.

## 5. Firewall

```bash
# ufw
sudo ufw allow 22/tcp
sudo ufw allow 48334/tcp
sudo ufw enable

# firewalld
sudo firewall-cmd --permanent --add-port=48334/tcp
sudo firewall-cmd --reload
```

Do **not** open the RPC port (`48333`), the template provider (`3350`) or the
explorer (`8080`). For remote access, tunnel them:

```bash
ssh -N -L 8080:127.0.0.1:8080 user@server
# then open http://127.0.0.1:8080 locally
```

## 6. Start and verify

```bash
sudo systemctl daemon-reload
sudo systemd-analyze verify hyphen-node.service
sudo systemctl enable --now hyphen-node
systemctl status hyphen-node --no-pager
journalctl -u hyphen-node -f
```

A healthy start logs, in order: the chain identity (from `ExecStartPre`), the
chain tip, the P2P peer id, the template provider, the RPC server and
`Node running. Send SIGINT or SIGTERM to stop.`.

Machine-readable health comes from the explorer:

```bash
curl -fsS http://127.0.0.1:8080/healthz   # liveness, no chain lock
curl -s http://127.0.0.1:8080/api/info     # chain tip and supply
```

```json
{"height":0,"tip_hash":"…","cumulative_difficulty":"0","network":"hyphen-devnet-v2",
 "block_time_target_secs":30,"current_reward":"…","total_supply":"…","difficulty":1,"…"}
```

`height` and `tip_hash` are the two fields to alert on. There is no Prometheus
endpoint in this build; scrape `/api/info` from your own checker if you need
history.

Confirm the listeners:

```bash
ss -lntp | grep hyphen
```

## 7. Public explorer behind Cloudflare

Keep the explorer bound to `127.0.0.1:8080`. Publish it through a Cloudflare
Tunnel, not by pointing a proxied DNS record at port 8080: Cloudflare's HTTP
proxy only accepts the standard HTTP/HTTPS ports.

```bash
cloudflared tunnel --url http://127.0.0.1:8080
```

That quick tunnel is for testing. A production deployment uses a named tunnel
with a credentials file and an ingress rule pointing at
`http://127.0.0.1:8080`, run as its own `cloudflared` systemd service
(`deploy/systemd/cloudflared.service.example`). Keep the tunnel and node
restarts independent: restarting the node must not require recreating the
tunnel, and a dead tunnel must be visible in `journalctl -u cloudflared`.

Before touching Cloudflare, prove the origin answers locally:

```bash
curl -fsS -D- http://127.0.0.1:8080/healthz
curl -fsS -D- http://127.0.0.1:8080/api/info
ss -lntp | grep 8080
systemctl status hyphen-node --no-pager
journalctl -u hyphen-node -g 'Explorer|panic|ERROR' --since '30 min ago' --no-pager
journalctl -u cloudflared --since '30 min ago' --no-pager
```

`/healthz` is a pure liveness response with no chain lock; use it for Cloudflare
health checks and supervisors. `/api/info` additionally reads the chain tip.
Point the tunnel at `127.0.0.1`, not `localhost`: if `localhost` resolves to
`::1` first and the node is bound to IPv4, every request is refused.

### Error 1033 while mining

Error 1033 is Cloudflare saying it has no live connection for the tunnel. The
origin is irrelevant to it: a node whose explorer answers `/healthz` in 1 ms is
healthy while the page still shows 1033. Measured on a devnet box that was
mining, pool and node co-located, the origin served 400 concurrent requests with
100% `200` and single-digit millisecond latency. So:

| Check | Meaning |
| --- | --- |
| `systemctl status cloudflared` is not `active (running)` | The tunnel process stopped. Start it as a service, not in a terminal |
| `journalctl -u cloudflared` shows repeated reconnects | Egress problem: UDP 7844 blocked, or the network drops long-lived QUIC |
| `dmesg -T \| grep -i 'killed process'` mentions `cloudflared` | The OOM killer took it. Give the box headroom |
| `uptime` shows load above the core count while mining | CPU starvation; see below |
| `/healthz` fails locally too | Then and only then is it the node |

A miner started with `--threads 0` now leaves one core free for exactly this
reason; pass an explicit `--threads` to claim every core on a dedicated mining
host.

A node whose explorer port is already held by another process fails at startup
with `bind block explorer …: address in use`; it no longer runs with a silently
dead public surface. If the port was held by a previous node instance,
`systemctl restart` is the wrong fix — stop the old process first.

## 8. Stop, restart, upgrade

`systemctl stop` sends `SIGTERM`; the node breaks its main loop, flushes sled
and exits. `Ctrl+C` in a foreground run does the same through `SIGINT`.
`TimeoutStopSec=90` only has to cover the flush — not a long drain.

Upgrade procedure:

```bash
sudo systemctl stop hyphen-node
sudo install -o root -g root -m 0755 target/release/hyphen-node /opt/hyphen/bin/hyphen-node
sudo systemctl start hyphen-node
journalctl -u hyphen-node -n 20 --no-pager | grep -E 'network=|consensus_params_hash='
```

If the consensus parameters changed, the node refuses to open the old
database:

```text
Failed to open blockchain: block validation failed: consensus parameters differ from genesis —
the chain database was created with different rules; refusing to open to prevent fork
```

That is the intended behaviour, not a bug to work around: a profile change is a
new chain identity and needs a new data directory. Roll back by reinstalling
the previous binary; if the data directory was already migrated, restore the
backup instead.

## 9. Backup and restore

The only consistent backup of a sled database is a stopped copy:

```bash
sudo systemctl stop hyphen-node
sudo tar -C /var/lib/hyphen -czf /var/backups/hyphen-$(date +%F).tar.gz .
sudo systemctl start hyphen-node
```

Copy `p2p_identity.key` with it, or every boot-node entry pointing at this host
breaks.

Block history can also move as an archive — block bodies only, verified
against the chain identity on the receiving side:

```bash
sudo systemctl stop hyphen-node
sudo /opt/hyphen/bin/hyphen-node --network devnet \
  --data-dir /var/lib/hyphen/data \
  --export-history /var/backups/hyphen.chain
sudo systemctl start hyphen-node

# verify without touching any database
sudo /opt/hyphen/bin/hyphen-node --network devnet --verify-history /var/backups/hyphen.chain

# or rebuild a fresh data directory from it
sudo /opt/hyphen/bin/hyphen-node --network devnet \
  --data-dir /var/lib/hyphen/restore \
  --replay-history /var/backups/hyphen.chain
```

`--verify-history` and `--replay-history` reject archives above 512 MiB; past
that size move the stopped data directory instead.

## 10. Logs and monitoring

```bash
journalctl -u hyphen-node --since '1 hour ago' --no-pager
journalctl -u hyphen-node -p warning --no-pager      # warnings and worse
journalctl -u hyphen-node -g 'No peers connected|ban expired|in sync' --no-pager
```

`RUST_LOG=info` is the production level. Raise a single target while
diagnosing (`RUST_LOG=info,hyphen_network=debug`) rather than turning the world
to `debug`.

What actually matters in the journal:

| Line | Meaning |
| --- | --- |
| `Chain tip: height=…, hash=…, cum_diff=…` | per-block progress; `cum_diff` is the fork-choice weight |
| `No peers connected, retrying Kademlia bootstrap...` | isolation; check firewall, boot node multiaddrs and that the boot node is up |
| `Peer … banned for …` | three proven-fault strikes in ten minutes; see [../security/peer-policy.md](Security-Peer-Policy) |
| `Peer … ban expired` | the hour elapsed, reconnects are allowed |
| `Remote … at height …, local at … – in sync` | sync responses applied |

## 11. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `mainnet requires --boot-nodes` | set `HYPHEN_BOOT_NODES`; only a first seed node may run isolated |
| `boot node '…' is missing /p2p/<peer-id>` | add the peer id; unauthenticated addresses are refused |
| `consensus parameters differ from genesis` | data directory from another network or profile — use a fresh one |
| `Address already in use` | another process holds the port; check `ss -lntp` |
| `Address family not supported by protocol` | `RestrictAddressFamilies` is missing `AF_NETLINK`, which libp2p's interface watcher needs |
| `Permission denied` under `/var/lib/hyphen` | the unit runs as `hyphen`; fix ownership, do not run as root |
| Service restarts every 5 s | `Restart=on-failure`; the reason is always the last journal error |
| Peers connect then drop | clock untrusted (check UDP 123 egress) or the peer earned strikes |
| `height` stuck at 0 | no peers, or the boot node is on a different chain identity |

## 12. What this deployment does not give you

- No public authenticated RPC, no public pool edge, no rate limiting.
- No metrics endpoint; `/healthz` reports liveness and `/api/info` is the only
  chain-state signal.
- No live P2P branch intake: the reorg backend is implemented and tested, but
  automatic fork-choice on live competing branches is not wired up.
- No monetary value. Running this node is a research and testing activity.

---

<!-- hyphen-bilingual-chinese -->

# 在 Linux 上部署 Hyphen 节点

这是单台 `systemd` 全节点运维手册。它覆盖 [incentivized-testnet.md](Operations-Incentivized-Testnet) 里的"本地 devnet"与"私有多节点"阶段；该文档列出的准入阻断项仍未关闭，因此本文任何步骤都不会让余额具备货币价值。

以下 `hyphen-node` 命令都在本仓库构建出的二进制上、在 Linux 上实际执行过（Ubuntu 24.04，Rust 1.97.1）。单元文件通过 `systemd-analyze verify`；`systemctl` 那几步需要在真实主机上执行。

## 1. 主机要求

| 项 | 要求 |
| --- | --- |
| 系统 | 带 systemd 的 Linux（Ubuntu 22.04+、Debian 12、RHEL 9），x86_64 或 aarch64 |
| CPU / 内存 | 2 vCPU / 4 GB。sled 的缓存驻留内存；2 GB 能跑 devnet，但同步高峰没有余量。 |
| 磁盘 | 本地 SSD，常规挂载（不要 NFS）。用自己的同步实测增长量来定容量。 |
| 入站 | 只开放 P2P 端口的 TCP（见第 5 节） |
| 出站 | 到 boot node 的 TCP，以及 **UDP 123**。节点内置 SNTP 客户端，把测得的偏移量应用到本地时钟；应答服务器少于三台，或偏移相差超过 2 秒，时钟即被标记为不可信并写入告警日志。区块时间校验读的就是这个校正后的时钟。 |
| 工具链 | Rust 1.97.0（由 `rust-toolchain.toml` 固定）、C 编译器与链接器（`zstd-sys` 会编译自带的 zstd）、`git`、`curl` |

## 2. 构建

在要部署的机器上构建，再分发二进制；本仓库不支持交叉编译。

```bash
sudo apt-get update
sudo apt-get install -y build-essential git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
. "$HOME/.cargo/env"

git clone https://github.com/HyphenTeam/Hyphen.git
cd Hyphen
cargo build --release --locked -p hyphen-node
```

`rust-toolchain.toml` 会在首次使用时安装 1.97.0，`--locked` 使用提交进仓库的 `Cargo.lock`——也就是 CI 校验的那套依赖。只构建节点包，不要构建整个工作区：你要部署的就是 `-p hyphen-node`，而全量构建还会顺带编译测试、fuzz 与浏览器相关产物，那些不属于节点。

安装之前先记录链身份：

```bash
./target/release/hyphen-node --network devnet --print-chain-identity
```

当前 devnet 配置应为：

```text
network=hyphen-devnet-v2
network_magic=48594456
consensus_params_hash=521f6cdc47f4424c1ea7b9f4d6770cf114f620cdff62958060f8c6953cb69de8
genesis_hash=5f7c144f0ef27880259b2429e46ef175685da679916fcc6b80c45f457465e32d
```

如果这几行与你的 peer 公布的不一致，你构建的是另一条链——到此为止。

## 3. 安装

```bash
sudo useradd --system --home /var/lib/hyphen --shell /usr/sbin/nologin hyphen
sudo install -d -o root  -g root   -m 0755 /opt/hyphen /opt/hyphen/bin
sudo install -d -o root  -g root   -m 0755 /etc/hyphen
sudo install -d -o hyphen -g hyphen -m 0750 /var/lib/hyphen

sudo install -o root -g root -m 0755 target/release/hyphen-node /opt/hyphen/bin/hyphen-node
sudo install -o root -g hyphen -m 0640 deploy/systemd/node.env.example /etc/hyphen/node.env
sudo install -o root -g root   -m 0644 deploy/systemd/hyphen-node.service /etc/systemd/system/hyphen-node.service
```

`/var/lib/hyphen/data` 存放 sled 数据库；`/var/lib/hyphen/data/p2p_identity.key` 是节点的 libp2p 私钥，创建权限为 `0600`。这把钥匙就是节点在网络里的身份：丢失或泄露，等于换人或被人冒名。

## 4. 配置

编辑 `/etc/hyphen/node.env`：

```bash
sudoedit /etc/hyphen/node.env
```

- `HYPHEN_NETWORK`——`devnet`、`testnet` 或 `mainnet`。
- `HYPHEN_P2P_PORT`——必须与第 5 节的防火墙规则一致。各网络默认值：mainnet `18334`、testnet `38334`、devnet `48334`。
- `HYPHEN_RPC_PORT`——mainnet `18333`、testnet `38333`、devnet `48333`。
- `HYPHEN_BOOT_NODES`——逗号分隔的 multiaddr，每个都以 `/p2p/<peer-id>` 结尾。没有 peer id 的地址会在启动时被拒绝，因为它无法被认证。devnet/testnet 可以为空；**mainnet 没有至少一个 boot node 就拒绝启动**（首个种子节点改为手工加 `--allow-isolated-mainnet`）。

单元文件把 RPC、模板提供者和区块浏览器留在回环地址，只公开 P2P 端口。请保持这样：这三个服务目前既没有认证，也没有限流。

每次启动都会在日志里打印本机 peer id：

```bash
journalctl -u hyphen-node -n 50 --no-pager | grep 'local peer ID'
```

其他人的节点靠 `/ip4/<你的IP>/tcp/<P2P端口>/p2p/<这个id>` 指向你。

## 5. 防火墙

```bash
# ufw
sudo ufw allow 22/tcp
sudo ufw allow 48334/tcp
sudo ufw enable

# firewalld
sudo firewall-cmd --permanent --add-port=48334/tcp
sudo firewall-cmd --reload
```

**不要**开放 RPC（`48333`）、模板提供者（`3350`）和浏览器（`8080`）。需要远程访问就做隧道：

```bash
ssh -N -L 8080:127.0.0.1:8080 user@server
# 然后在本地打开 http://127.0.0.1:8080
```

## 6. 启动与验证

```bash
sudo systemctl daemon-reload
sudo systemd-analyze verify hyphen-node.service
sudo systemctl enable --now hyphen-node
systemctl status hyphen-node --no-pager
journalctl -u hyphen-node -f
```

正常启动会依次打印：链身份（来自 `ExecStartPre`）、链尖、P2P peer id、模板提供者、RPC 服务器，以及 `Node running. Send SIGINT or SIGTERM to stop.`。

机器可读的健康信号来自浏览器服务：

```bash
curl -fsS http://127.0.0.1:8080/healthz   # 存活探测，不获取链锁
curl -s http://127.0.0.1:8080/api/info     # 链尖与供应量
```

```json
{"height":0,"tip_hash":"…","cumulative_difficulty":"0","network":"hyphen-devnet-v2",
 "block_time_target_secs":30,"current_reward":"…","total_supply":"…","difficulty":1,"…"}
```

要报警的是 `height` 与 `tip_hash` 两个字段。本版本没有 Prometheus 端点；需要历史数据就用自己的检查器抓 `/api/info`。

确认监听端口：

```bash
ss -lntp | grep hyphen
```

## 7. Cloudflare 后的公开浏览器

浏览器保持绑定在 `127.0.0.1:8080`。通过 Cloudflare Tunnel 发布，不要把代理 DNS 记录直接指向
8080 端口：Cloudflare 的 HTTP 代理只接受标准 HTTP/HTTPS 端口。

```bash
cloudflared tunnel --url http://127.0.0.1:8080
```

快速隧道只用于测试。生产环境使用带 credentials 文件和 ingress 规则的命名隧道，指向
`http://127.0.0.1:8080`，并作为独立的 `cloudflared` systemd 服务运行
（见 `deploy/systemd/cloudflared.service.example`）。隧道与节点重启必须相互独立：重启节点
不应要求重建隧道，隧道失效必须能在 `journalctl -u cloudflared` 中看到。

在怀疑 Cloudflare 之前，先证明源站本地可用：

```bash
curl -fsS -D- http://127.0.0.1:8080/healthz
curl -fsS -D- http://127.0.0.1:8080/api/info
ss -lntp | grep 8080
systemctl status hyphen-node --no-pager
journalctl -u hyphen-node -g 'Explorer|panic|ERROR' --since '30 min ago' --no-pager
journalctl -u cloudflared --since '30 min ago' --no-pager
```

`/healthz` 是纯存活响应，不获取链锁；Cloudflare 健康检查和监管进程应使用它。
`/api/info` 还会读取链尖。隧道指向 `127.0.0.1`，不要写 `localhost`：如果 `localhost`
优先解析到 `::1`，而节点只绑定 IPv4，所有请求都会被拒绝。

### 挖矿期间的 Error 1033

Error 1033 的含义是 Cloudflare 找不到这条隧道的活跃连接。它与源站无关：节点探针在 1 ms 内
返回 `/healthz`，页面照样会显示 1033。在同时在挖矿的 devnet 机器上实测，源站处理 400 个并发
请求全部 `200`、延迟个位数毫秒。所以按下面顺序判断：

| 检查 | 含义 |
| --- | --- |
| `systemctl status cloudflared` 不是 `active (running)` | 隧道进程已停止。要用服务运行，不要挂在终端里 |
| `journalctl -u cloudflared` 反复重连 | 出口问题：UDP 7844 被封，或网络断开长连接 QUIC |
| `dmesg -T \| grep -i 'killed process'` 出现 `cloudflared` | OOM killer 杀掉了它，需要给机器留余量 |
| 挖矿时 `uptime` 的负载高于核数 | CPU 饥饿，见下 |
| 本地 `/healthz` 也失败 | 只有这时才是节点的问题 |

`--threads 0` 启动的矿工现在会留一个核给节点、矿池和隧道；在专用矿机上要占满所有核请显式传
`--threads`。

浏览器端口被其他进程占用时，节点现在会在启动阶段以
`bind block explorer …: address in use` 失败，不再带着一个静默失效的公开接口继续运行。如果
端口被旧节点实例占用，`systemctl restart` 不是正确做法——先停止旧进程。

## 8. 停止、重启、升级

`systemctl stop` 发送 `SIGTERM`；节点跳出主循环、flush sled 后退出。前台运行时 `Ctrl+C` 走 `SIGINT`，路径相同。`TimeoutStopSec=90` 只是给 flush 留余量，不是在等待长时间排空。

升级流程：

```bash
sudo systemctl stop hyphen-node
sudo install -o root -g root -m 0755 target/release/hyphen-node /opt/hyphen/bin/hyphen-node
sudo systemctl start hyphen-node
journalctl -u hyphen-node -n 20 --no-pager | grep -E 'network=|consensus_params_hash='
```

如果共识参数变了，节点会拒绝打开旧库：

```text
Failed to open blockchain: block validation failed: consensus parameters differ from genesis —
the chain database was created with different rules; refusing to open to prevent fork
```

这是预期行为，不是要绕过的 bug：配置档改变就是新的链身份，必须换新的数据目录。回滚的办法是装回旧二进制；如果数据目录已被迁移，则从备份恢复。

## 9. 备份与恢复

sled 数据库唯一一致的备份方式是停机拷贝：

```bash
sudo systemctl stop hyphen-node
sudo tar -C /var/lib/hyphen -czf /var/backups/hyphen-$(date +%F).tar.gz .
sudo systemctl start hyphen-node
```

务必连 `p2p_identity.key` 一起复制，否则所有指向本机的 boot node 条目都会失效。

区块历史也可以按归档搬运——只含区块体，接收方按链身份校验：

```bash
sudo systemctl stop hyphen-node
sudo /opt/hyphen/bin/hyphen-node --network devnet \
  --data-dir /var/lib/hyphen/data \
  --export-history /var/backups/hyphen.chain
sudo systemctl start hyphen-node

# 不碰任何数据库，只验证
sudo /opt/hyphen/bin/hyphen-node --network devnet --verify-history /var/backups/hyphen.chain

# 或用它重建一个全新数据目录
sudo /opt/hyphen/bin/hyphen-node --network devnet \
  --data-dir /var/lib/hyphen/restore \
  --replay-history /var/backups/hyphen.chain
```

`--verify-history` 与 `--replay-history` 拒绝超过 512 MiB 的归档；链长超过这个规模就直接搬停机后的数据目录。

## 10. 日志与监控

```bash
journalctl -u hyphen-node --since '1 hour ago' --no-pager
journalctl -u hyphen-node -p warning --no-pager      # 警告及以上
journalctl -u hyphen-node -g 'No peers connected|ban expired|in sync' --no-pager
```

生产环境用 `RUST_LOG=info`。排障时只调高单个目标（`RUST_LOG=info,hyphen_network=debug`），不要把全局拉到 `debug`。

真正需要关注的日志行：

| 日志 | 含义 |
| --- | --- |
| `Chain tip: height=…, hash=…, cum_diff=…` | 逐块进展；`cum_diff` 是分叉选择权重 |
| `No peers connected, retrying Kademlia bootstrap...` | 网络孤立；检查防火墙、boot node 的 multiaddr，以及对方是否在线 |
| `Peer … banned for …` | 十分钟内三次可证过错；见 [../security/peer-policy.md](Security-Peer-Policy) |
| `Peer … ban expired` | 封禁一小时到期，允许重连 |
| `Remote … at height …, local at … – in sync` | 同步响应已应用 |

## 11. 故障排查

| 现象 | 原因与处理 |
| --- | --- |
| `mainnet requires --boot-nodes` | 设置 `HYPHEN_BOOT_NODES`；只有首个种子节点可以孤立运行 |
| `boot node '…' is missing /p2p/<peer-id>` | 补上 peer id；未认证地址一律拒绝 |
| `consensus parameters differ from genesis` | 数据目录属于别的网络或配置档——换新目录 |
| `Address already in use` | 端口被占用；`ss -lntp` 查看 |
| `Address family not supported by protocol` | `RestrictAddressFamilies` 缺少 libp2p 网卡监视所需的 `AF_NETLINK` |
| `/var/lib/hyphen` 下 `Permission denied` | 单元以 `hyphen` 身份运行；修所有者，不要用 root 跑 |
| 服务每 5 秒重启 | `Restart=on-failure`；原因始终在最后一条 journal 错误里 |
| peer 连上又断开 | 时钟不可信（检查出站 UDP 123），或对方已累计过错 |
| `height` 一直为 0 | 没有 peer，或 boot node 处在另一条链身份上 |

## 12. 这套部署没有提供什么

- 没有公开的认证 RPC、没有公开矿池入口、没有限流。
- 没有指标端点；`/healthz` 报告存活，`/api/info` 是唯一的链状态信号。
- 没有实时 P2P 分支接入：reorg 后端已实现并有测试，但针对实时竞争分支的自动 fork-choice 尚未接线。
- 没有货币价值。运行这个节点属于研究与测试活动。
