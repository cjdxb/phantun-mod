# Phantun-mod

基于 [dndx/phantun](https://github.com/dndx/phantun) 的修改版：自动管理防火墙规则、HTTP / SSH 伪装、断线检测与自动重连。
A modified [dndx/phantun](https://github.com/dndx/phantun) with automatic firewall rules, HTTP / SSH obfuscation and dead-connection detection.

**[中文](#中文) | [English](#english)**

---

# 中文

## 目录

* [简介](#简介)
* [相对原版的修改](#相对原版的修改)
* [编译与安装](#编译与安装)
* [快速开始](#快速开始)
* [参数说明](#参数说明)
    * [客户端 phantun_client](#客户端-phantun_client)
    * [服务端 phantun_server](#服务端-phantun_server)
* [功能详解](#功能详解)
    * [自动管理防火墙规则（--iface）](#自动管理防火墙规则--iface)
    * [HTTP 伪装（--fake-http / --http-handshake / --http-payload）](#http-伪装--fake-http----http-handshake----http-payload)
    * [SSH 握手（--ssh-handshake）](#ssh-握手--ssh-handshake)
    * [断线检测与自动重连](#断线检测与自动重连)
* [注意事项](#注意事项)
* [许可证与致谢](#许可证与致谢)

## 简介

Phantun 把 UDP 数据包流伪装成 TCP 连接，用于 UDP 被封锁或限速、而 TCP 可以通过的网络。它只在 UDP 包前加上
IP + TCP 头，不做重传和流控，因此保留了 UDP 的特性（例如允许乱序），开销只有 12 字节。原理、性能数据和与
udp2raw 的对比请参阅[原版 README](https://github.com/dndx/phantun#readme)。

本修改版在原版 v0.8.1 基础上，主要解决三个实际使用中的痛点：

1. 每次部署都要手写 iptables/nftables 规则、手动开启 IP 转发；
2. 纯 TCP 握手后紧跟二进制数据，容易被识别为非常规流量；
3. 客户端在 NAT 后面且公网 IP 变化时，旧连接会“静默死亡”，客户端却一直不知道。

## 相对原版的修改

| 修改 | 涉及端 | 相关参数 | 说明 |
|------|--------|----------|------|
| 自动管理防火墙规则 | 客户端、服务端 | `--iface`、`--fw-backend` | 启动时开启 IP 转发并添加 MASQUERADE / DNAT 规则，退出时自动删除 |
| HTTP 诱饵包 | 仅客户端 | `--fake-http`、`--fake-ttl`、`--fake-repeat`、`--http-host` | 握手时发送只能存活几跳的 HTTP 请求包，让路径上的检测设备看到 HTTP |
| HTTP 握手 | 两端都要开启 | `--http-handshake`、`--http-host` | TCP 握手后先交换一对真实的 HTTP 请求/响应，再开始转发 UDP |
| HTTP 逐包包装 | 两端都要开启 | `--http-payload`、`--http-host`（仅客户端） | 每个 UDP 载荷单独放进一条完整的 HTTP 消息，不重传 |
| SSH 握手 | 两端都要开启 | `--ssh-handshake` | TCP 握手后按真实 SSH 的顺序交换标识串和 KEXINIT，再开始转发 UDP。不能与 HTTP 伪装同时使用 |
| Keepalive 断线检测 | 客户端发起，服务端应答 | 无（自动生效） | 客户端长时间收不到服务端数据时发送探测包，无应答则关闭连接，由下一个 UDP 包重新建连 |
| 优雅退出 | 客户端、服务端 | 无 | 收到 `SIGINT` / `SIGTERM` 时正常退出（用于清理防火墙规则） |

`fake-tcp` 库的相应改动：

* 新增 `Stack::set_fake_packet()`、`build_tcp_packet_with_ttl()`，用于发送指定 TTL 的诱饵包；
* 新增 `Socket::send_keepalive()`，发送与 Linux 内核 TCP keepalive 相同格式的探测包（不带载荷、序号比当前小 1 的 ACK）；
* 空 ACK 不再推进 `ack`；服务端（accept 得到的）socket 对每个空 ACK 立即回复 ACK，客户端 socket 从不回复，避免 ACK 循环；
* 修复了退出时 `Socket::drop` 可能 panic 的问题。

## 编译与安装

需要 Rust 工具链，且只能在 Linux 上运行（依赖 TUN 设备）。

```bash
cargo build --release
sudo install target/release/client /usr/local/bin/phantun_client
sudo install target/release/server /usr/local/bin/phantun_server
```

> **客户端和服务端都必须使用本修改版。** 原版服务端不会应答 keepalive 探测包，也不认识 HTTP / SSH 握手。

## 快速开始

示例假设：服务端公网地址 `10.0.0.1`，在 TCP `4567` 端口接受连接，并把 UDP 转发给本机 `127.0.0.1:1234`
（例如 WireGuard）；客户端在 `127.0.0.1:1234` 接收本地 UDP。两端的公网网卡都是 `eth0`。

**最简用法**（root 运行，防火墙规则全自动）：

```bash
# 服务端
RUST_LOG=info phantun_server --local 4567 --remote 127.0.0.1:1234 --iface eth0

# 客户端
RUST_LOG=info phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567 --iface eth0
```

**开启 HTTP 伪装**：

```bash
# 服务端
RUST_LOG=info phantun_server --local 4567 --remote 127.0.0.1:1234 --iface eth0 --http-handshake

# 客户端
RUST_LOG=info phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567 --iface eth0 \
    --http-host www.example.com --fake-http --http-handshake
```

**开启 SSH 握手**：

```bash
# 服务端
RUST_LOG=info phantun_server --local 4567 --remote 127.0.0.1:1234 --iface eth0 --ssh-handshake

# 客户端
RUST_LOG=info phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567 --iface eth0 --ssh-handshake
```

不使用 `--iface` 时，需要像原版一样手动开启 IP 转发并配置 NAT 规则，见[原版 README 的 Usage 一节](https://github.com/dndx/phantun#usage)。
这种情况下可以用 `setcap cap_net_admin=+pe` 以非 root 用户运行。

日志级别由环境变量 `RUST_LOG` 控制（`error` / `warn` / `info` / `debug`）。

## 参数说明

带 ★ 的是本修改版新增的参数。所有参数都可以用 `-h` 查看。

### 客户端 phantun_client

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-l, --local <IP:PORT>` | 必填 | 本地监听 UDP 的地址和端口。IPv6 写作 `[::1]:1234` |
| `-r, --remote <IP 或域名:PORT>` | 必填 | Phantun 服务端的地址和端口，支持域名（A / AAAA 记录） |
| `--tun <名称>` | 自动分配 | TUN 接口名称，例如 `tun0` |
| `--tun-local <IP>` | `192.168.200.1` | TUN 接口本机端（操作系统侧）IPv4 地址 |
| `--tun-peer <IP>` | `192.168.200.2` | TUN 接口对端（Phantun 侧）IPv4 地址，即 Phantun 发包使用的源地址 |
| `--tun-local6 <IP>` | `fcc8::1` | TUN 接口本机端 IPv6 地址 |
| `--tun-peer6 <IP>` | `fcc8::2` | TUN 接口对端 IPv6 地址 |
| `-4, --ipv4-only` | 关 | 解析 `--remote` 时只用 IPv4 地址；不能与 `--tun-local6` / `--tun-peer6` 同用 |
| `--handshake-packet <文件>` | 无 | TCP 握手后把该文件内容作为第一个数据包发给服务端（单包发送，不能超过 MTU）。同时开启 `--http-handshake` 或 `--ssh-handshake` 时，改为在该握手完成之后发送 |
| ★ `--iface <网卡>` | 无 | 面向互联网的网卡。指定后自动开启 IP 转发、添加 MASQUERADE 规则，退出时删除。需要 root |
| ★ `--fw-backend <auto\|nft\|iptables>` | `auto` | 防火墙后端，`auto` 表示有 `nft` 命令就用 nft。必须配合 `--iface` |
| ★ `--http-host <主机名>` | 无 | HTTP 请求中的 `Host` 头，`--fake-http`、`--http-handshake` 和 `--http-payload` 都需要它 |
| ★ `--fake-http` | 关 | 收到 SYN+ACK 后发送有限 TTL 的 HTTP 请求诱饵包。需要 `--http-host` |
| ★ `--fake-ttl <1-254>` | `3` | 诱饵包离开本机后还能存活的跳数 |
| ★ `--fake-repeat <N>` | `2` | 每个连接发送的诱饵包数量 |
| ★ `--http-handshake` | 关 | TCP 握手后与服务端交换真实的 HTTP 请求/响应，再转发 UDP。服务端也必须开启。需要 `--http-host` |
| ★ `--http-payload` | 关 | 每个 UDP 载荷单独放进一条 HTTP `POST`。服务端也必须开启。需要 `--http-host` |
| ★ `--ssh-handshake` | 关 | TCP 握手后与服务端交换 SSH 标识串和 KEXINIT，再转发 UDP。服务端也必须开启。不能与 `--fake-http`、`--http-handshake`、`--http-payload` 同用 |

### 服务端 phantun_server

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-l, --local <PORT>` | 必填 | 接受客户端 TCP 连接的端口 |
| `-r, --remote <IP 或域名:PORT>` | 必填 | UDP 转发目标的地址和端口，支持域名 |
| `--tun <名称>` | 自动分配 | TUN 接口名称 |
| `--tun-local <IP>` | `192.168.201.1` | TUN 接口本机端 IPv4 地址 |
| `--tun-peer <IP>` | `192.168.201.2` | TUN 接口对端 IPv4 地址，即 DNAT 的目标地址 |
| `--tun-local6 <IP>` | `fcc9::1` | TUN 接口本机端 IPv6 地址 |
| `--tun-peer6 <IP>` | `fcc9::2` | TUN 接口对端 IPv6 地址，即 IPv6 DNAT 的目标地址 |
| `-4, --ipv4-only` | 关 | 不给 TUN 接口分配 IPv6 地址（`--iface` 也只添加 IPv4 规则） |
| `--handshake-packet <文件>` | 无 | TCP 握手后把该文件内容作为第一个数据包发给客户端。同时开启 `--http-handshake` 或 `--ssh-handshake` 时，改为在该握手响应之后发送 |
| ★ `--iface <网卡>` | 无 | 面向互联网的网卡。指定后自动开启 IP 转发、添加 DNAT 规则，退出时删除。需要 root |
| ★ `--fw-backend <auto\|nft\|iptables>` | `auto` | 同客户端 |
| ★ `--http-handshake` | 关 | 要求每个连接先发来开启了 `--http-handshake` 的客户端的 HTTP 请求，并用 HTTP 响应回答。先发其他数据的连接会被关闭 |
| ★ `--http-payload` | 关 | 只接受放在 HTTP `POST` 里的 UDP 载荷，并且把发出的 UDP 载荷放进 HTTP 响应。客户端也必须开启 |
| ★ `--ssh-handshake` | 关 | 每个连接建立后立即发送 SSH 标识串，收到开启了 `--ssh-handshake` 的客户端的标识串后回 KEXINIT。先发其他数据的连接会被关闭。不能与 `--http-handshake`、`--http-payload` 同用 |

## 功能详解

### 自动管理防火墙规则（--iface）

指定 `--iface` 后，Phantun 启动时会：

1. 把 `/proc/sys/net/ipv4/ip_forward` 置为 1（使用 IPv6 时还会设置 `net.ipv6.conf.all.forwarding`）；
2. 添加 NAT 规则：
    * 客户端：从 TUN 进、从 `--iface` 出的流量做 MASQUERADE；
    * 服务端：从 `--iface` 进、目标端口为 `--local` 的 TCP 流量 DNAT 到 `--tun-peer`（及 `--tun-peer6`）。

收到 `SIGINT` / `SIGTERM` 退出时删除这些规则（IP 转发开关保持不变）。如果进程被 `kill -9` 等方式强杀导致规则残留，
下次启动时会先清理旧规则再添加，不会重复。

| 后端 | 规则存放位置 | 备注 |
|------|--------------|------|
| nft | 独立的 `inet phantun_<TUN 名>` 表 | 不影响其他表中的规则 |
| iptables / ip6tables | 带 `phantun_<TUN 名>` 注释的规则 | 额外在 `FORWARD` 链插入对 TUN 接口的 ACCEPT 规则 |

使用 nft 后端时，其他工具（例如通过 iptables 管理规则的 Docker）设置的 `FORWARD` drop 规则不会被绕过，
这种情况请使用 `--fw-backend iptables`。

### HTTP 伪装（--fake-http / --http-handshake / --http-payload）

三个选项相互独立，可以单独或同时使用：

**`--fake-http`（仅客户端）**：客户端收到 SYN+ACK 后，发送 `--fake-repeat` 个 HTTP `GET` 请求诱饵包，
这些包的 TTL 只够存活 `--fake-ttl` 跳。路径上的检测设备会看到一个 HTTP 请求，而诱饵包通常在到达服务端之前就被丢弃。
即使有诱饵包到达服务端，握手阶段也会被忽略。

`--fake-ttl` 的取值：只需大于检测设备所在的跳数即可。建议小于到服务端的跳数（可以用 `traceroute` 查看），
以避免一种罕见情况：被乱序的诱饵包在握手完成后才到达，被当作垃圾 UDP 包转发出去。

**`--http-handshake`（两端）**：TCP 握手完成后，客户端发送一个真实的 HTTP 请求，服务端回复
`HTTP/1.1 200 OK`，之后才开始转发 UDP。客户端等待响应 1 秒，超时重发，最多 3 次，仍失败则放弃该连接。
这两个包由 Phantun 自己消费，不会转发给 UDP 应用。

> 注意：`--http-handshake` 两端必须同时开启或同时关闭。只开客户端会导致握手失败；只开服务端则客户端发来的数据会被拒绝，连接被关闭。

**`--http-payload`（两端）**：每个 UDP 载荷仍然是一个 fake TCP 段，段内是一条完整的 HTTP/1.1 消息。客户端发送带 `Host` 和 `Content-Length` 的 `POST`，服务端发送带 `Content-Length` 的 `HTTP/1.1 200 OK`。对端只取出正文再交给 UDP 应用。长度对不上的段直接丢弃，不缓存、不拼到下一段，因此不需要重传。空的 keepalive ACK，以及 `--http-handshake` 那一对 GET / 无正文的 200，都不走这层包装。

> 注意：`--http-payload` 两端必须同时开启或同时关闭。只开一端时，开启的一端会丢掉对端发来的未包装数据；未开启的一端则把整条 HTTP 消息（含头部）原样转发给 UDP 应用，通常会被应用当作无效包丢弃。`Host` 为 `www.example.com`、正文长度是 4 位数时，上行请求头是 128 字节，下行响应头是 105 字节。

### SSH 握手（--ssh-handshake）

**`--ssh-handshake`（两端）**：按真实 OpenSSH 会话的顺序开场。TCP 握手完成后，服务端和客户端各自立即发送 SSH 标识串 `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5`（Ubuntu 24.04 自带的 OpenSSH）；任一方收到对方的标识串后，回一个 `SSH_MSG_KEXINIT` 包（与该版本一致的 OpenSSH 9.6 默认算法列表，cookie 和填充每次随机）。客户端收到服务端的标识串和 KEXINIT 后才开始转发 UDP。2.5 秒内没收齐，客户端重发标识串，最多 3 次，服务端对每次重发都再回一遍标识串和 KEXINIT；仍失败则放弃该连接。这四段由 Phantun 自己消费，不会转发给 UDP 应用。之后的 UDP 载荷不再包装，线上也不再出现 SSH 报文。

密钥交换停在 KEXINIT：没有真正的密钥协商，也没有加密。只让连接开头看起来像 SSH。不能与 `--fake-http`、`--http-handshake`、`--http-payload` 同时使用。

> 注意：`--ssh-handshake` 两端必须同时开启或同时关闭，并且两端都要是带 KEXINIT 交换的版本。只开客户端会导致握手失败；只开服务端则客户端发来的数据会被拒绝，连接被关闭。应用自己发出的、内容恰好等于标识串，或者格式恰好符合未加密 KEXINIT 包的 UDP 包，也会被当成握手重传吃掉。

### 断线检测与自动重连

客户端在 NAT 后面、公网 IP 或 NAT 映射变化后，旧的伪 TCP 连接会失效：严格的 NAT 会直接丢弃中途出现的包，服务端不会回 RST；
而原版的空闲计时器会被客户端自己发出的流量刷新，因此客户端会一直使用这个已失效的连接。

本修改版的客户端在 **15–25 秒（随机）** 收不到服务端任何数据后，每隔 **3–6 秒（随机）** 发送一个 keepalive 探测包，
**连续 3 个**都没有应答就关闭连接。从连接失效到判定断线共约 24–43 秒。

* 客户端不会主动重连，而是由下一个 UDP 包触发新的握手。如果本地应用持续有流量（例如开启了 `PersistentKeepalive`
  的 WireGuard），判定断线后约一个 RTT 就能恢复。
* 客户端只有收到携带载荷的包才会刷新 180 秒的空闲超时，因此 keepalive 本身不会让空闲连接永远不关闭。
* 服务端对每个空 ACK 立即回复，即使两端序号已不一致也能应答。服务端无需任何配置。

## 注意事项

* **MTU**：Phantun 不做分片，并总是设置 `DF` 位，包长不能超过链路 MTU。承载 WireGuard 时，WireGuard 接口 MTU
  可按 `链路 MTU - IP 头(IPv4 20 / IPv6 40) - TCP 头 20 - WireGuard 开销 32` 计算，例如 1500 的链路用 IPv4 时设为 `1428`。
  使用 `--handshake-packet` 时文件大小同样不能超过 MTU。开启 `--http-payload` 时还要减去 HTTP 头
  （`www.example.com` 的上行请求头为 128 字节，同样的链路上 WireGuard MTU 约为 `1300`）。
* **无加密**：Phantun 只做伪装，不提供加密和防重放，请在上层使用 WireGuard 等加密协议。
* **只能穿过 L3/L4 设备**：无法穿过 HTTP 代理等 L7 代理，HTTP 伪装只是让流量“看起来像”HTTP。
* **权限**：`--iface` 需要 root；不使用 `--iface` 时只需 `cap_net_admin`。

## 许可证与致谢

原项目作者 Datong Sun（[dndx/phantun](https://github.com/dndx/phantun)），原项目以 MIT 或 Apache-2.0 双许可证发布。
本修改版选择其中的 [MIT 许可证](LICENSE-MIT) 发布。

**[⬆ 返回顶部](#phantun-mod)**

---

# English

## Table of Contents

* [Introduction](#introduction)
* [Changes from upstream](#changes-from-upstream)
* [Build and install](#build-and-install)
* [Quick start](#quick-start)
* [Options](#options)
    * [Client: phantun_client](#client-phantun_client)
    * [Server: phantun_server](#server-phantun_server)
* [Features in detail](#features-in-detail)
    * [Automatic firewall rules (--iface)](#automatic-firewall-rules---iface)
    * [HTTP obfuscation (--fake-http / --http-handshake / --http-payload)](#http-obfuscation---fake-http----http-handshake----http-payload)
    * [SSH handshake (--ssh-handshake)](#ssh-handshake---ssh-handshake)
    * [Dead connection detection and reconnection](#dead-connection-detection-and-reconnection)
* [Notes](#notes)
* [License and credits](#license-and-credits)

## Introduction

Phantun turns a stream of UDP packets into a fake TCP connection, for networks where UDP is blocked
or throttled but TCP gets through. It only puts an IP + TCP header in front of each UDP payload, with
no retransmission or flow control, so UDP properties such as out-of-order delivery are kept and the
overhead is only 12 bytes. For the design, benchmarks and comparison with udp2raw, see the
[upstream README](https://github.com/dndx/phantun#readme).

This fork is based on upstream v0.8.1 and addresses three practical pain points:

1. Every deployment needs hand-written iptables/nftables rules and IP forwarding turned on;
2. Binary data right after a bare TCP handshake is easy to flag as unusual traffic;
3. When the client is behind NAT and its public IP changes, the old connection dies silently and the
   client never notices.

## Changes from upstream

| Change | Side | Options | Description |
|--------|------|---------|-------------|
| Automatic firewall rules | Client, server | `--iface`, `--fw-backend` | Enables IP forwarding and adds MASQUERADE / DNAT rules on startup, removes them on exit |
| HTTP decoys | Client only | `--fake-http`, `--fake-ttl`, `--fake-repeat`, `--http-host` | Sends HTTP request packets that survive only a few hops during the handshake, so middleboxes see HTTP |
| HTTP handshake | Both sides | `--http-handshake`, `--http-host` | Exchanges a real HTTP request/response after the TCP handshake, before forwarding UDP |
| HTTP per-packet wrap | Both sides | `--http-payload`, `--http-host` (client only) | Puts each UDP payload in its own complete HTTP message, with no retransmission |
| SSH handshake | Both sides | `--ssh-handshake` | Exchanges SSH identification strings and KEXINIT packets in real SSH order after the TCP handshake, before forwarding UDP. Cannot be combined with HTTP obfuscation |
| Keepalive | Client probes, server answers | None (always on) | When the server has been silent for a while, the client sends probes; if none is answered, the connection is closed and the next UDP packet makes a new one |
| Graceful shutdown | Client, server | None | Exits cleanly on `SIGINT` / `SIGTERM` (so firewall rules can be removed) |

Matching changes in the `fake-tcp` library:

* New `Stack::set_fake_packet()` and `build_tcp_packet_with_ttl()` to send packets with a given TTL;
* New `Socket::send_keepalive()`, which sends a probe in the same format as the Linux kernel's TCP
  keepalive (an empty ACK one byte behind the current sequence number);
* Empty ACKs no longer move `ack`. Server (accepted) sockets answer every empty ACK with an ACK;
  client sockets never answer, so there is no ACK loop;
* Fixed a possible panic in `Socket::drop` on shutdown.

## Build and install

Requires a Rust toolchain. Runs on Linux only (it needs a TUN device).

```bash
cargo build --release
sudo install target/release/client /usr/local/bin/phantun_client
sudo install target/release/server /usr/local/bin/phantun_server
```

> **Both client and server must run this fork.** The upstream server does not answer keepalive
> probes and does not understand the HTTP or SSH handshake.

## Quick start

The examples assume the server's public address is `10.0.0.1`, it accepts connections on TCP port
`4567` and forwards UDP to `127.0.0.1:1234` on the same host (e.g. WireGuard); the client receives
local UDP on `127.0.0.1:1234`. The Internet facing interface on both hosts is `eth0`.

**Minimal setup** (run as root, firewall rules are fully automatic):

```bash
# Server
RUST_LOG=info phantun_server --local 4567 --remote 127.0.0.1:1234 --iface eth0

# Client
RUST_LOG=info phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567 --iface eth0
```

**With HTTP obfuscation**:

```bash
# Server
RUST_LOG=info phantun_server --local 4567 --remote 127.0.0.1:1234 --iface eth0 --http-handshake

# Client
RUST_LOG=info phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567 --iface eth0 \
    --http-host www.example.com --fake-http --http-handshake
```

**With the SSH handshake**:

```bash
# Server
RUST_LOG=info phantun_server --local 4567 --remote 127.0.0.1:1234 --iface eth0 --ssh-handshake

# Client
RUST_LOG=info phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567 --iface eth0 --ssh-handshake
```

Without `--iface`, turn on IP forwarding and set up the NAT rules by hand as with upstream; see the
[Usage section of the upstream README](https://github.com/dndx/phantun#usage). In that case Phantun
can run as a non-root user with `setcap cap_net_admin=+pe`.

The log level is set with the `RUST_LOG` environment variable (`error` / `warn` / `info` / `debug`).

## Options

Options marked with ★ are new in this fork. Run with `-h` to list all options.

### Client: phantun_client

| Option | Default | Description |
|--------|---------|-------------|
| `-l, --local <IP:PORT>` | Required | Address and port to listen on for UDP. IPv6 is written as `[::1]:1234` |
| `-r, --remote <IP or HOST:PORT>` | Required | Address and port of the Phantun server; host names (A / AAAA records) are supported |
| `--tun <NAME>` | Picked by kernel | TUN interface name, e.g. `tun0` |
| `--tun-local <IP>` | `192.168.200.1` | IPv4 address of the OS end of the TUN interface |
| `--tun-peer <IP>` | `192.168.200.2` | IPv4 address of the Phantun end of the TUN interface, i.e. the source address of Phantun's packets |
| `--tun-local6 <IP>` | `fcc8::1` | IPv6 address of the OS end of the TUN interface |
| `--tun-peer6 <IP>` | `fcc8::2` | IPv6 address of the Phantun end of the TUN interface |
| `-4, --ipv4-only` | Off | Use only IPv4 addresses when resolving `--remote`; cannot be used with `--tun-local6` / `--tun-peer6` |
| `--handshake-packet <FILE>` | None | After the TCP handshake, send the content of this file to the server as the first data packet (sent as one packet, must fit in the MTU). With `--http-handshake` or `--ssh-handshake`, send it after that handshake |
| ★ `--iface <IFACE>` | None | Internet facing interface. When set, enables IP forwarding and adds MASQUERADE rules, removed on exit. Requires root |
| ★ `--fw-backend <auto\|nft\|iptables>` | `auto` | Firewall backend; `auto` uses nft when the `nft` command is available. Requires `--iface` |
| ★ `--http-host <HOST>` | None | `Host` header of the HTTP request, required by `--fake-http`, `--http-handshake` and `--http-payload` |
| ★ `--fake-http` | Off | After receiving SYN+ACK, send HTTP request decoys with a limited TTL. Requires `--http-host` |
| ★ `--fake-ttl <1-254>` | `3` | Number of hops the decoys survive after leaving this host |
| ★ `--fake-repeat <N>` | `2` | Number of decoys sent per connection |
| ★ `--http-handshake` | Off | After the TCP handshake, exchange a real HTTP request/response with the server before forwarding UDP. The server must enable it too. Requires `--http-host` |
| ★ `--http-payload` | Off | Send each UDP payload in its own HTTP `POST`. The server must enable it too. Requires `--http-host` |
| ★ `--ssh-handshake` | Off | After the TCP handshake, exchange SSH identification strings and KEXINIT packets with the server before forwarding UDP. The server must enable it too. Cannot be combined with `--fake-http`, `--http-handshake`, or `--http-payload` |

### Server: phantun_server

| Option | Default | Description |
|--------|---------|-------------|
| `-l, --local <PORT>` | Required | Port to accept client TCP connections on |
| `-r, --remote <IP or HOST:PORT>` | Required | Address and port to forward UDP to; host names are supported |
| `--tun <NAME>` | Picked by kernel | TUN interface name |
| `--tun-local <IP>` | `192.168.201.1` | IPv4 address of the OS end of the TUN interface |
| `--tun-peer <IP>` | `192.168.201.2` | IPv4 address of the Phantun end of the TUN interface, i.e. the DNAT target |
| `--tun-local6 <IP>` | `fcc9::1` | IPv6 address of the OS end of the TUN interface |
| `--tun-peer6 <IP>` | `fcc9::2` | IPv6 address of the Phantun end of the TUN interface, i.e. the IPv6 DNAT target |
| `-4, --ipv4-only` | Off | Do not assign IPv6 addresses to the TUN interface (`--iface` then adds IPv4 rules only) |
| `--handshake-packet <FILE>` | None | After the TCP handshake, send the content of this file to the client as the first data packet. With `--http-handshake` or `--ssh-handshake`, send it after that handshake response |
| ★ `--iface <IFACE>` | None | Internet facing interface. When set, enables IP forwarding and adds DNAT rules, removed on exit. Requires root |
| ★ `--fw-backend <auto\|nft\|iptables>` | `auto` | Same as the client |
| ★ `--http-handshake` | Off | Require every connection to start with the HTTP request from a client started with `--http-handshake`, and answer it with an HTTP response. Connections sending other data first are closed |
| ★ `--http-payload` | Off | Accept UDP payloads only inside HTTP `POST` requests, and send each UDP payload inside an HTTP response. The client must enable it too |
| ★ `--ssh-handshake` | Off | Send an SSH identification string as soon as a connection is accepted, and answer the identification string of a client started with `--ssh-handshake` with a KEXINIT packet. Connections sending other data first are closed. Cannot be combined with `--http-handshake` or `--http-payload` |

## Features in detail

### Automatic firewall rules (--iface)

With `--iface`, Phantun does the following on startup:

1. Sets `/proc/sys/net/ipv4/ip_forward` to 1 (and `net.ipv6.conf.all.forwarding` when IPv6 is used);
2. Adds NAT rules:
    * Client: MASQUERADE traffic coming from the TUN interface and leaving through `--iface`;
    * Server: DNAT TCP traffic arriving on `--iface` with destination port `--local` to `--tun-peer`
      (and `--tun-peer6`).

The rules are removed when Phantun exits on `SIGINT` / `SIGTERM` (IP forwarding is left on). If the
process was killed (e.g. `kill -9`) and left rules behind, they are cleaned up on the next start
instead of being duplicated.

| Backend | Where the rules live | Notes |
|---------|----------------------|-------|
| nft | A dedicated `inet phantun_<TUN name>` table | Rules in other tables are untouched |
| iptables / ip6tables | Rules tagged with comment `phantun_<TUN name>` | Also inserts ACCEPT rules for the TUN interface in the `FORWARD` chain |

With the nft backend, `FORWARD` drop rules set by other tools (e.g. Docker via iptables) are not
bypassed; use `--fw-backend iptables` in that case.

### HTTP obfuscation (--fake-http / --http-handshake / --http-payload)

The three options are independent and can be used alone or together:

**`--fake-http` (client only)**: after receiving SYN+ACK, the client sends `--fake-repeat` HTTP `GET`
request decoys whose TTL lets them survive only `--fake-ttl` hops. Middleboxes on the path see an
HTTP request, while the decoys are usually dropped before reaching the server. Decoys that do reach
the server are ignored during the handshake.

Choosing `--fake-ttl`: it only needs to exceed the hop at which inspection happens. Keeping it below
the hop count to the server (check with `traceroute`) avoids a rare case where a reordered decoy
arrives after the handshake and is forwarded as a junk UDP packet.

**`--http-handshake` (both sides)**: after the TCP handshake, the client sends a real HTTP request and
the server replies with `HTTP/1.1 200 OK`; only then does UDP forwarding start. The client waits 1
second for the response and retransmits on timeout, up to 3 times, then gives up on the connection.
Both packets are consumed by Phantun and never forwarded to the UDP application.

> Note: `--http-handshake` must be enabled or disabled on both sides. Enabling it only on the client
> makes the handshake fail; enabling it only on the server rejects the client's data and closes the
> connection.

**`--http-payload` (both sides)**: each UDP payload is still one fake TCP segment, and that segment is one
complete HTTP/1.1 message. The client sends a `POST` with `Host` and `Content-Length`; the server sends
`HTTP/1.1 200 OK` with `Content-Length`. The peer forwards only the body to the UDP application. A
segment whose length does not match is dropped; nothing is buffered for the next segment, so this
needs no retransmission. Empty keepalive ACKs, and the GET / bodyless 200 from `--http-handshake`,
are not wrapped.

> Note: `--http-payload` must be enabled or disabled on both sides. If only one side enables it, the
> enabling side drops the unwrapped data it receives, and the other side forwards each whole HTTP
> message, headers included, to the UDP application, which usually rejects it as invalid. With `Host: www.example.com` and a
> 4-digit body length, the upload request header is 128 bytes and the download response header is
> 105 bytes.

### SSH handshake (--ssh-handshake)

**`--ssh-handshake` (both sides)**: the connection opens in the same order as a real OpenSSH session.
Right after the TCP handshake, the server and the client each send the SSH identification string
`SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5` (the stock OpenSSH of Ubuntu 24.04). Each side that receives the peer's identification string answers with an
`SSH_MSG_KEXINIT` packet (the default OpenSSH 9.6 algorithm lists matching that version, random cookie and padding). UDP forwarding
starts once the client has the server's identification string and KEXINIT. If they do not arrive
within 2.5 seconds, the client sends its identification string again, up to 3 times, and the
server answers each copy with its identification string and KEXINIT; after that the client gives
up on the connection. These four messages are consumed by Phantun and never forwarded to the UDP
application. Later UDP payloads are not wrapped, and no further SSH messages appear on the wire.

The key exchange stops after KEXINIT: there is no key agreement and no encryption. Only the start
of the connection looks like SSH. This option cannot be combined with `--fake-http`,
`--http-handshake`, or `--http-payload`.

> Note: `--ssh-handshake` must be enabled or disabled on both sides, and both sides must run a
> version with the KEXINIT exchange. Enabling it only on the client makes the handshake fail;
> enabling it only on the server rejects the client's data and closes the connection. A UDP
> datagram whose bytes are exactly the identification string, or are shaped exactly like an
> unencrypted KEXINIT packet, is also consumed as a retransmitted handshake message.

### Dead connection detection and reconnection

When the client is behind NAT and its public IP or NAT mapping changes, the old fake TCP connection
stops working: strict NATs silently drop the mid-stream packets, so the server never sends a RST,
and upstream's idle timer is refreshed by the client's own outbound traffic, so the client keeps
using the dead connection forever.

In this fork, after **15–25 seconds (random)** without anything from the server, the client sends a
keepalive probe every **3–6 seconds (random)**, and closes the connection if **none of 3** probes is
answered. It takes about 24–43 seconds from the connection dying to it being closed.

* The client does not reconnect by itself: the next UDP packet starts a new handshake. If the local
  application keeps sending (e.g. WireGuard with `PersistentKeepalive`), the connection recovers
  about one RTT after being declared dead.
* On the client, only packets carrying a payload refresh the 180 second idle timeout, so keepalive alone does not
  keep idle connections open forever.
* The server answers every empty ACK right away, even when sequence numbers no longer match. No
  server configuration is needed.

## Notes

* **MTU**: Phantun does not fragment and always sets the `DF` bit, so packets must fit in the link
  MTU. For WireGuard, set the interface MTU to
  `link MTU - IP header (IPv4 20 / IPv6 40) - TCP header 20 - WireGuard overhead 32`, e.g. `1428` for
  a 1500 link over IPv4. Files passed to `--handshake-packet` must fit in the MTU as well. With
  `--http-payload`, also subtract the HTTP header (`www.example.com` upload header is 128 bytes, so the
  WireGuard MTU on that same link is about `1300`).
* **No encryption**: Phantun only obfuscates; it has no encryption or anti-replay. Use an encrypted
  protocol such as WireGuard on top.
* **L3/L4 only**: it cannot pass through L7 proxies such as HTTP proxies. HTTP obfuscation only makes
  the traffic *look* like HTTP.
* **Privileges**: `--iface` requires root; without it, `cap_net_admin` is enough.

## License and credits

Original project by Datong Sun ([dndx/phantun](https://github.com/dndx/phantun)), dual-licensed under
MIT or Apache-2.0. This fork is distributed under the [MIT license](LICENSE-MIT).

**[⬆ Back to top](#phantun-mod)**
