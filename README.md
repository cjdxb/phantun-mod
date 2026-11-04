# Phantun

A lightweight and fast UDP to TCP obfuscator. / 轻量、高速的 UDP 转 TCP 混淆器。

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/dndx/phantun/rust.yml)
![docs.rs](https://img.shields.io/docsrs/fake-tcp)

**[中文](#中文文档) | [English](#english)**

---

# 中文文档

## 目录

* [最新版本](#最新版本)
* [概述](#概述)
* [使用方法](#使用方法)
    * [1. 开启内核 IP 转发](#1-开启内核-ip-转发)
    * [2. 添加防火墙规则](#2-添加防火墙规则)
        * [客户端 SNAT 规则](#客户端-snat-规则)
        * [服务端 DNAT 规则](#服务端-dnat-规则)
    * [3. 以非 root 用户运行](#3-以非-root-用户运行)
    * [4. 启动 Phantun](#4-启动-phantun)
        * [启动服务端](#启动服务端)
        * [启动客户端](#启动客户端)
    * [自动管理防火墙规则](#自动管理防火墙规则)
    * [HTTP 混淆](#http-混淆)
    * [断线自动重连](#断线自动重连)
* [MTU 开销](#mtu-开销)
    * [WireGuard 的 MTU 计算](#wireguard-的-mtu-计算)
* [版本兼容性](#版本兼容性)
* [开发文档](#开发文档)
* [性能](#性能)
* [未来计划](#未来计划)
* [与 udp2raw 的对比](#与-udp2raw-的对比)
* [许可证](#许可证)

## 最新版本

[v0.8.1](https://github.com/dndx/phantun/releases/tag/v0.8.1)

<details>
  <summary>关于 MIPS 架构支持</summary>

  自 2023 年起，[Rust 对 MIPS 平台仅提供 Tier 3 支持](https://github.com/rust-lang/compiler-team/issues/648)。
  因此 Phantun 的 MIPS 版本使用 nightly 工具链构建，仅尽力提供，不保证可用。
</details>

## 概述

Phantun 将 UDP 数据包混淆成 TCP 连接，目标是以最小的处理和封装开销获得最高性能。

它常用于 UDP 被封锁或限速、但 TCP 可以通过的网络环境。

Phantun 只是把 UDP 数据包流转换为混淆后的 TCP 数据包流。它使用的 TCP 协议栈可以穿过大多数
L3/L4 有状态/无状态防火墙和 NAT 设备，但**无法**穿过 L7 代理。
这种做法的好处是不会出现常见的 UDP over TCP 性能杀手，如重传和流量控制。即使在防火墙/NAT 看来
连接是 TCP，底层 UDP 的特性（例如乱序到达）依然完整保留。

Phantun 意为 Phantom TUN（幽灵 TUN）：它只为 UDP 流量做“刚好足够”的工作，使其能以 TCP 数据包
的形式穿过有状态防火墙/NAT。

Phantun 由 100% safe Rust 编写，针对多核系统做了大量优化，在高速链路上可以充分利用所有 CPU 资源。
基准测试结果见[性能](#性能)一节。

![Phantun benchmark results](images/phantun-vs-udp2raw-benchmark-result.png)
![Traffic flow diagram](images/traffic-flow.png)

## 使用方法

下文示例假设：

* **Phantun 服务端**在 TCP 端口 `4567` 监听客户端连接（服务端的 `--local`），并把 UDP 数据包转发到
  `127.0.0.1:1234` 的 UDP 服务（服务端的 `--remote`）。
* **Phantun 客户端**在 `127.0.0.1:1234` 监听 UDP 数据包（客户端的 `--local`），并连接到位于
  `10.0.0.1:4567` 的 Phantun 服务端（客户端的 `--remote`）。

Phantun 会在客户端和服务端各创建一个 TUN 接口。默认情况下，**客户端**为自己分配 `192.168.200.2`
和 `fcc8::2`，**服务端**分配 `192.168.201.2` 和 `fcc9::2`。因此内核必须开启 IPv4/IPv6 转发，
并配置 iptables/nftables 规则，在物理网卡地址与 Phantun TUN 接口地址之间做 NAT。

TUN 接口名称和地址都可以自定义，运行程序时加 `-h` 查看相关选项。

可以这样理解这个网络拓扑（参见上方示意图）：

* Phantun 客户端相当于路由器后面一台私网 IP（`192.168.200.2`/`fcc8::2`）的机器。要访问互联网，
  需要在流量离开网卡前对私网地址做 SNAT。
* Phantun 服务端相当于路由器后面一台私网 IP（`192.168.201.2`/`fcc9::2`）的服务器。要让互联网访问它，
  需要在路由器上对监听端口做 `DNAT`，把目标地址改成服务端监听的地址。

在这两种情况下，运行 Phantun 的主机（及其 iptables）就扮演那台“路由器”，让 Phantun 用私网地址与外界通信。

自 v0.4.1 起，TCP 和 UDP 两侧都完整支持 IPv6。命令行中的 IPv6 地址写作 `[::1]:1234`，也支持解析
AAAA 记录。运行时加 `-h` 查看控制 IPv6 行为的选项。

> **提示：** 如果以 root 运行，可以跳过第 1、2 步，改用 `--iface` 让 Phantun 自动配置，
> 详见[自动管理防火墙规则](#自动管理防火墙规则)。

### 1. 开启内核 IP 转发

编辑 `/etc/sysctl.conf`，添加 `net.ipv4.ip_forward=1`，然后执行 `sudo sysctl -p /etc/sysctl.conf`。

<details>
  <summary>IPv6 额外配置</summary>

  还需要设置 `net.ipv6.conf.all.forwarding=1`。
</details>

### 2. 添加防火墙规则

#### 客户端 SNAT 规则

客户端只需在物理网卡上开启 SNAT，把 Phantun 的地址转换成物理网络上可用的地址，用 masquerade 即可。

注意：把 `eth0` 换成实际的物理网卡名称。

**nftables：**

```
table inet nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        iifname tun0 oif eth0 masquerade
    }
}
```

上面的规则使用 `inet` 表族，同时适用于 IPv4 和 IPv6。

**iptables：**

```
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

#### 服务端 DNAT 规则

服务端需要把 TCP 监听端口 DNAT 到 Phantun TUN 接口的地址。

注意：把 `eth0` 换成实际的物理网卡名称，把 `4567` 换成 Phantun 服务端实际使用的 TCP 端口。

**nftables：**

```
table inet nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iif eth0 tcp dport 4567 dnat ip to 192.168.201.2
        iif eth0 tcp dport 4567 dnat ip6 to fcc9::2
    }
}
```

**iptables：**

```
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 4567 -j DNAT --to-destination 192.168.201.2
ip6tables -t nat -A PREROUTING -p tcp -i eth0 --dport 4567 -j DNAT --to-destination fcc9::2
```

### 3. 以非 root 用户运行

本步骤可选。不建议以 root 身份运行面向网络的程序。只要具备 `cap_net_admin` 能力，Phantun 就可以
完全以非 root 用户运行：

```
sudo setcap cap_net_admin=+pe phantun_server
sudo setcap cap_net_admin=+pe phantun_client
```

注意：[自动管理防火墙规则](#自动管理防火墙规则)（`--iface`）需要 root 权限。

### 4. 启动 Phantun

运行程序时加 `-h` 可查看全部选项。

#### 启动服务端

`4567` 是 Phantun 监听的 TCP 端口，必须与上面的 DNAT 规则一致；`127.0.0.1:1234` 是新连接要转发到的 UDP 服务。

```
RUST_LOG=info /usr/local/bin/phantun_server --local 4567 --remote 127.0.0.1:1234
```

`--remote` 也可以使用主机名：

```
RUST_LOG=info /usr/local/bin/phantun_server --local 4567 --remote example.com:1234
```

服务端默认会给 TUN 接口同时分配 IPv4 和 IPv6 私网地址。如果不需要 IPv6，跳过上面的 IPv6 DNAT
规则即可，TUN 接口上的 IPv6 地址不会对服务端产生副作用。

#### 启动客户端

`127.0.0.1:1234` 是 Phantun 监听的 UDP 地址和端口；`10.0.0.1:4567` 是要连接的 Phantun 服务端。

```
RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567
```

`--remote` 也可以使用主机名：

```
RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote example.com:4567
```

<details>
  <summary>IPv6 示例</summary>

  ```
  RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote [fdxx::1234]:4567
  ```

  也支持带 AAAA 记录的域名。
</details>

### 自动管理防火墙规则

不想手动执行第 1、2 步时，可以用 `--iface` 指定面向互联网的网卡。Phantun 会在启动时开启 IP 转发并
添加所需的 MASQUERADE（客户端）或 DNAT（服务端）规则，在收到 `SIGINT`/`SIGTERM` 退出时将其删除。
如果进程被强杀导致规则残留，下次启动时会自动替换。此选项需要 root 权限。

```
RUST_LOG=info /usr/local/bin/phantun_server --local 4567 --remote 127.0.0.1:1234 --iface eth0
RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567 --iface eth0
```

| 后端 | 规则存放位置 |
|------|--------------|
| nft（可用时优先） | 独立的 `inet phantun_<tun>` 表 |
| iptables/ip6tables | 带 `phantun_<tun>` 注释的规则 |

可用 `--fw-backend nft|iptables` 强制指定后端（默认 `auto`）。注意：使用 nft 后端时，其他工具
（例如通过 iptables 管理规则的 Docker）设置的 `FORWARD` drop 规则不会被覆盖，这种情况请使用
`--fw-backend iptables`。

### HTTP 混淆

以下两个相互独立的选项可以让伪 TCP 连接看起来像 HTTP，二者都需要配合 `--http-host` 指定 Host 头：

| 选项 | 适用端 | 作用 |
|------|--------|------|
| `--fake-http` | 仅客户端 | 收到 SYN + ACK 后发送 `--fake-repeat`（默认 2）个 HTTP 请求诱饵包，其 TTL 只能存活 `--fake-ttl`（默认 3）跳，让路径上的中间设备看到 HTTP 请求 |
| `--http-handshake` | 两端都要开启 | TCP 握手后，客户端发送真实的 HTTP 请求，并等待服务端的 HTTP 响应后才开始转发 UDP 流量。这两个包由 Phantun 消费，不会被转发 |

关于 `--fake-ttl` 的取值：真正到达服务端的诱饵包在握手阶段会被忽略，因此它只需大于流量检测发生的
跳数即可。让它小于到服务端的跳数，可以避免一种罕见情况：被乱序的诱饵包在握手完成后才到达，
被当作垃圾 UDP 数据报转发出去。

```
RUST_LOG=info /usr/local/bin/phantun_server --local 4567 --remote 127.0.0.1:1234 --http-handshake
RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567 \
    --http-host www.example.com --fake-http --http-handshake
```

[返回目录](#目录)

### 断线自动重连

客户端位于 NAT 之后且公网 IP（或 NAT 映射）发生变化时，旧的伪 TCP 连接会失效。客户端在收不到服务端任何数据
15–25 秒（随机）后，会按 Linux 内核 TCP keepalive 的格式发送探测包（不带载荷、序号比当前小 1 的 ACK），
每隔 3–6 秒（随机）一个，连续 3 个都没有应答就关闭连接，从失效到判定断线共需 24–43 秒。
关闭连接后客户端不会主动重连，而是由下一个 UDP 包触发新的握手；如果本地应用持续有流量（如开启了 PersistentKeepalive 的
WireGuard），判定断线后约一个 RTT 即可恢复，没有流量时则在下次有流量时才建立连接。

服务端对收到的每个空 ACK 都会立即回复一个 ACK（客户端从不回复），因此即使最后的数据包丢失、两端序号不一致，
探测也能得到应答。服务端无需额外配置，但两端都必须使用包含此功能的版本重新编译。

[返回目录](#目录)

## MTU 开销

Phantun 力求把隧道开销降到最低。与普通 UDP 包相比（以 IPv4 为例）：

**普通 UDP 包：** `20 字节 IP 头 + 8 字节 UDP 头 = 28 字节`

**混淆后的包：** `20 字节 IP 头 + 20 字节 TCP 头 = 40 字节`

为了穿过有状态包检测，Phantun 除 IP 和 TCP 头外不添加任何额外头部！

Phantun 的额外开销为 `12 字节`，即使用 Phantun 时 UDP 可用载荷减少 12 字节。这是此类混淆所能达到的最小开销。

![Packet header diagram](images/packet-headers.png)

### WireGuard 的 MTU 计算

使用 Phantun 承载 [WireGuard®](https://www.wireguard.com) UDP 流量时，可按以下公式计算 WireGuard 接口的 MTU：

```
WireGuard MTU = 链路 MTU - IPv4 头 (20 字节) - TCP 头 (20 字节) - WireGuard 开销 (32 字节)
```

或

```
WireGuard MTU = 链路 MTU - IPv6 头 (40 字节) - TCP 头 (20 字节) - WireGuard 开销 (32 字节)
```

例如链路 MTU 为 1500 字节时，WireGuard 接口 MTU 应设置为：

**IPv4：** `1500（链路 MTU）- 20 - 20 - 32 = 1428 字节`

**IPv6：** `1500（链路 MTU）- 40 - 20 - 32 = 1408 字节`

这样生成的 Phantun TCP 数据包为 1500 字节，不会超过接口 MTU。

请注意，**数据包大小超过链路 MTU 时 Phantun 无法正常工作**，因为 Phantun 不做 IP 分片与重组。
出于同样原因，Phantun 总是在 IP 头中设置 `DF`（Don't Fragment）位，防止中间设备对数据包分片。

*强烈建议* WireGuard 隧道两端使用相同的接口 MTU，否则可能出现难以排查的丢包问题。

[返回目录](#目录)

## 版本兼容性

虽然 TCP 协议栈相当稳定，但建议两端运行相同 minor 版本的 Phantun 服务端/客户端，以确保最佳兼容性。

## 开发文档

如需在自己的项目中使用 `fake-tcp` 库，请参阅：[https://docs.rs/fake-tcp](https://docs.rs/fake-tcp)。

## 性能

测试环境为两台 AWS `t4g.xlarge` 实例（4 vCPU，5 Gb/s 网卡，局域网）。使用 `nftables` 把 `iperf3` 的
UDP 流量重定向到两台实例之间的 Phantun/udp2raw 隧道，并调整 MTU 以避免分片。

测试版本为 Phantun `v0.3.2` 和 `udp2raw_arm_asm_aes` `20200818.0`，均为 2022 年 4 月时的最新版本。

测试命令：`iperf3 -c <IP> -p <PORT> -R -u -l 1400 -b 1000m -t 30 -P 5`

| 模式                                                                        | 发送速率       | 接收速率       | 总 CPU 占用                             |
|-----------------------------------------------------------------------------|----------------|----------------|-----------------------------------------|
| 直连（1 条流）                                                              | 3.00 Gbits/sec | 2.37 Gbits/sec | 25%（1 核 100%）                        |
| Phantun（1 条流）                                                           | 1.30 Gbits/sec | 1.20 Gbits/sec | 60%（1 核 100%，3 核 50%）              |
| udp2raw（`cipher-mode=none` `auth-mode=none` `disable-anti-replay`）（1 条流） | 1.30 Gbits/sec | 715 Mbits/sec  | 40%（1 核 100%，1 核 50%，2 核空闲）    |
| 直连（5 条流）                                                              | 5.00 Gbits/sec | 3.64 Gbits/sec | 25%（1 核 100%）                        |
| Phantun（5 条流）                                                           | 5.00 Gbits/sec | 2.38 Gbits/sec | 95%（所有核心均被利用）                 |
| udp2raw（`cipher-mode=none` `auth-mode=none` `disable-anti-replay`）（5 条流） | 5.00 Gbits/sec | 770 Mbits/sec  | 50%（2 核 100%）                        |

关于 Phantun 达到这一性能所用的部分技术，可参阅：[Writing Highly Efficient UDP Server in Rust](https://idndx.com/writing-highly-efficient-udp-server-in-rust/)。

[返回目录](#目录)

## 未来计划

* 将单条 UDP 流负载均衡到多条 TCP 流
* 集成测试

## 与 udp2raw 的对比

[udp2raw](https://github.com/wangyu-/udp2raw-tunnel) 是 [@wangyu-](https://github.com/wangyu-) 开发的另一个流行项目，
功能与 Phantun 非常相似，Phantun 的灵感也来自它。开发 Phantun 的主要原因是 udp2raw 的性能不足
（尤其在树莓派等多核系统上）。不过 Phantun 的目标从来不是像 udp2raw 那样功能齐全，而是只支持最常见的场景：
不支持 UDP over ICMP 和 UDP over UDP 模式，也没有防重放和加密。换来的是整体性能更好，并且由于 TCP 载荷中
没有额外头部，MTU 开销更小。

以下对比可帮助你选择：

|                                    |    Phantun    |      udp2raw      |
|------------------------------------|:-------------:|:-----------------:|
| UDP over FakeTCP 混淆              |       ✅       |         ✅         |
| UDP over ICMP 混淆                 |       ❌       |         ✅         |
| UDP over UDP 混淆                  |       ❌       |         ✅         |
| 多线程                             |       ✅       |         ❌         |
| 吞吐量                             |      更好     |        好         |
| 三层实现方式                       |   TUN 接口    | Raw sockets + BPF |
| 隧道 MTU 开销                      |    12 字节    |      44 字节      |
| 每个 UDP 连接使用独立 TCP 连接     |  客户端/服务端 |     仅服务端      |
| 防重放、加密                       |       ❌       |         ✅         |
| IPv6                               |       ✅       |         ✅         |

[返回目录](#目录)

## 许可证

Copyright 2021-2025 Datong Sun (dndx@idndx.com)

本项目可按你的选择，依据 Apache License 2.0（[LICENSE-APACHE](LICENSE-APACHE) 或
[https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0)）
或 MIT 许可证（[LICENSE-MIT](LICENSE-MIT) 或 [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT)）授权。
未遵守上述条款，不得复制、修改或分发本项目中的文件。

**[⬆ 返回顶部](#phantun)**

---

# English

## Table of Contents

* [Latest release](#latest-release)
* [Overview](#overview)
* [Usage](#usage)
    * [1. Enable kernel IP forwarding](#1-enable-kernel-ip-forwarding)
    * [2. Add required firewall rules](#2-add-required-firewall-rules)
        * [Client SNAT rules](#client-snat-rules)
        * [Server DNAT rules](#server-dnat-rules)
    * [3. Run Phantun binaries as non-root (Optional)](#3-run-phantun-binaries-as-non-root-optional)
    * [4. Start Phantun daemon](#4-start-phantun-daemon)
        * [Start the server](#start-the-server)
        * [Start the client](#start-the-client)
    * [Automatic firewall rules](#automatic-firewall-rules)
    * [HTTP obfuscation](#http-obfuscation)
    * [Automatic reconnection](#automatic-reconnection)
* [MTU overhead](#mtu-overhead)
    * [MTU calculation for WireGuard](#mtu-calculation-for-wireguard)
* [Version compatibility](#version-compatibility)
* [Documentation](#documentation)
* [Performance](#performance)
* [Future plans](#future-plans)
* [Comparison to udp2raw](#comparison-to-udp2raw)
* [License](#license)

## Latest release

[v0.8.1](https://github.com/dndx/phantun/releases/tag/v0.8.1)

<details>
  <summary>MIPS architecture support for Phantun</summary>

  [Rust only provides Tier 3 supports for MIPS based platforms](https://github.com/rust-lang/compiler-team/issues/648)
since 2023. Phantun's MIPS builds are therefore built using nightly Rust toolchain and provided on a best effort basis only.
</details>

## Overview

Phantun is a project that obfuscates UDP packets into TCP connections. It aims to
achieve maximum performance with minimum processing and encapsulation overhead.

It is commonly used in environments where UDP is blocked/throttled but TCP is allowed through.

Phantun simply converts a stream of UDP packets into obfuscated TCP stream packets. The TCP stack
used by Phantun is designed to pass through most L3/L4 stateful/stateless firewalls/NAT
devices. It will **not** be able to pass through L7 proxies.
However, the advantage of this approach is that none of the common UDP over TCP performance killers
such as retransmissions and flow control will occur. The underlying UDP properties such as
out-of-order delivery are fully preserved even if the connection ends up looking like a TCP
connection from the perspective of firewalls/NAT devices.

Phantun means Phantom TUN, as it is an obfuscator for UDP traffic that does just enough work
to make it pass through stateful firewall/NATs as TCP packets.

Phantun is written in 100% safe Rust. It has been optimized extensively to scale well on multi-core
systems and has no issue saturating all available CPU resources on a fast connection.
See the [Performance](#performance) section for benchmarking results.

![Phantun benchmark results](images/phantun-vs-udp2raw-benchmark-result.png)
![Traffic flow diagram](images/traffic-flow.png)

## Usage

For the example below, it is assumed that:

* **Phantun Server** listens for incoming Phantun Client connections at port `4567` (the `--local`
  option for server), and forwards UDP packets to the UDP server at `127.0.0.1:1234` (the `--remote`
  option for server).
* **Phantun Client** listens for incoming UDP packets at `127.0.0.1:1234` (the `--local` option for
  client) and connects to Phantun Server at `10.0.0.1:4567` (the `--remote` option for client).

Phantun creates a TUN interface for both the Client and Server. For **Client**, Phantun assigns itself the IP address
`192.168.200.2` and `fcc8::2` by default.
For **Server**, it assigns `192.168.201.2` and `fcc9::2` by default. Therefore, your kernel must have
IPv4/IPv6 forwarding enabled and set up appropriate iptables/nftables rules for NAT between your physical
NIC address and Phantun's TUN interface address.

You may customize the name of the TUN interface created by Phantun and the assigned addresses. Please
run the executable with the `-h` option to see how to change them.

Another way to help understand this network topology (please see the diagram above for an illustration of this topology):

* Phantun Client is like a machine with private IP address (`192.168.200.2`/`fcc8::2`) behind a router.
  In order for it to reach the Internet, you will need to SNAT the private IP address before its traffic
  leaves the NIC.
* Phantun Server is like a server with private IP address (`192.168.201.2`/`fcc9::2`) behind a router.
  In order to access it from the Internet, you need to `DNAT` its listening port on the router
  and change the destination IP address to where the server is listening for incoming connections.

In those cases, the machine/iptables running Phantun acts as the "router" that allows Phantun
to communicate with outside using its private IP addresses.

As of Phantun v0.4.1, IPv6 is fully supported for both TCP and UDP sides.
To specify an IPv6 address, use the following format: `[::1]:1234` with
the command line options. Resolving AAAA records is also supported. Please run the program
with `-h` to see detailed options on how to control the IPv6 behavior.

> **Tip:** When running as root, you can skip steps 1 and 2 and let Phantun configure them with
> `--iface`. See [Automatic firewall rules](#automatic-firewall-rules).

### 1. Enable kernel IP forwarding

Edit `/etc/sysctl.conf`, add `net.ipv4.ip_forward=1` and run `sudo sysctl -p /etc/sysctl.conf`.

<details>
  <summary>IPv6 specific config</summary>

  `net.ipv6.conf.all.forwarding=1` will need to be set as well.
</details>

### 2. Add required firewall rules

#### Client SNAT rules

Client simply needs SNAT enabled on the physical interface to translate Phantun's address into
one that can be used on the physical network. This can be done simply with masquerade.

Note: change `eth0` to whatever the actual physical interface name is.

**Using nftables:**

```
table inet nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        iifname tun0 oif eth0 masquerade
    }
}
```

Note: The above rule uses `inet` as the table family type, so it is compatible with
both IPv4 and IPv6 usage.

**Using iptables:**

```
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

#### Server DNAT rules

Server needs to DNAT the TCP listening port to Phantun's TUN interface address.

Note: change `eth0` to whatever the actual physical interface name is and `4567` to the
actual TCP port number used by Phantun server.

**Using nftables:**

```
table inet nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iif eth0 tcp dport 4567 dnat ip to 192.168.201.2
        iif eth0 tcp dport 4567 dnat ip6 to fcc9::2
    }
}
```

**Using iptables:**

```
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 4567 -j DNAT --to-destination 192.168.201.2
ip6tables -t nat -A PREROUTING -p tcp -i eth0 --dport 4567 -j DNAT --to-destination fcc9::2
```

### 3. Run Phantun binaries as non-root (Optional)

It is ill-advised to run network facing applications as root user. Phantun can be run fully
as non-root user with the `cap_net_admin` capability.

```
sudo setcap cap_net_admin=+pe phantun_server
sudo setcap cap_net_admin=+pe phantun_client
```

Note: [Automatic firewall rules](#automatic-firewall-rules) (`--iface`) require running as root.

### 4. Start Phantun daemon

**Note:** Run Phantun executable with `-h` option to see full detailed options.

#### Start the server

Note: `4567` is the TCP port Phantun should listen on and must correspond to the DNAT
rule specified above. `127.0.0.1:1234` is the UDP Server to connect to for new connections.

```
RUST_LOG=info /usr/local/bin/phantun_server --local 4567 --remote 127.0.0.1:1234
```

Or use host name with `--remote`:

```
RUST_LOG=info /usr/local/bin/phantun_server --local 4567 --remote example.com:1234
```

Note: Server by default assigns both IPv4 and IPv6 private address to the TUN interface.
If you do not wish to use IPv6, you can simply skip creating the IPv6 DNAT rule above and
the presence of IPv6 address on the TUN interface should have no side effect to the server.

#### Start the client

Note: `127.0.0.1:1234` is the UDP address and port Phantun should listen on. `10.0.0.1:4567` is
the Phantun Server to connect.

```
RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567
```

Or use host name with `--remote`:

```
RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote example.com:4567
```

<details>
  <summary>IPv6 specific config</summary>

  ```
  RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote [fdxx::1234]:4567
  ```

  Domain name with AAAA record is also supported.
</details>

### Automatic firewall rules

Instead of following steps 1 and 2 manually, pass the Internet facing interface with `--iface`.
Phantun then enables IP forwarding, adds the required MASQUERADE (client) or DNAT (server) rules
on startup, and removes them when it exits on `SIGINT`/`SIGTERM`. Rules left behind by a killed
process are replaced on the next start. Running as root is required for this option.

```
RUST_LOG=info /usr/local/bin/phantun_server --local 4567 --remote 127.0.0.1:1234 --iface eth0
RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567 --iface eth0
```

| Backend | Where the rules live |
|---------|----------------------|
| nft (preferred when available) | A dedicated `inet phantun_<tun>` table |
| iptables/ip6tables | Rules tagged with comment `phantun_<tun>` |

Use `--fw-backend nft|iptables` to force one (default: `auto`). Note that with the nft backend,
`FORWARD` drop rules managed by other tools (e.g. Docker via iptables) are not overridden; use
`--fw-backend iptables` in that case.

### HTTP obfuscation

Two independent options make the fake TCP connection look like HTTP. Both require `--http-host`
to set the `Host` header:

| Option | Side | Effect |
|--------|------|--------|
| `--fake-http` | Client only | After receiving SYN + ACK, sends `--fake-repeat` (default 2) HTTP request decoys whose TTL lets them survive only `--fake-ttl` (default 3) hops, so middleboxes on the path see an HTTP request |
| `--http-handshake` | Both sides | After TCP handshake, the client sends a real HTTP request and waits for the server's HTTP response before forwarding any UDP traffic. Both packets are consumed by Phantun and never forwarded |

On choosing `--fake-ttl`: decoys that do reach the server are ignored during the handshake, so
`--fake-ttl` only needs to exceed the hop at which inspection happens. Keeping it below the hop
count to the server avoids a rare case where a reordered decoy arrives after the handshake and
gets forwarded as a junk UDP datagram.

```
RUST_LOG=info /usr/local/bin/phantun_server --local 4567 --remote 127.0.0.1:1234 --http-handshake
RUST_LOG=info /usr/local/bin/phantun_client --local 127.0.0.1:1234 --remote 10.0.0.1:4567 \
    --http-host www.example.com --fake-http --http-handshake
```

[Back to TOC](#table-of-contents)

### Automatic reconnection

When the client is behind NAT and its public IP (or NAT mapping) changes, the old fake TCP
connection stops working. After 15–25 seconds (random) without anything from the server, the
client sends keepalive probes formatted like the Linux kernel's TCP keepalive (an empty ACK one
byte behind the current sequence number), one every 3–6 seconds (random). If none of 3 probes is
answered, the connection is closed, 24–43 seconds after it stopped working in total.

The client does not reconnect by itself: the next UDP packet starts a new handshake. If the local
application keeps sending (e.g. WireGuard with PersistentKeepalive), the connection recovers about
one RTT after being declared dead; otherwise a new one is made when traffic resumes.

The server answers every empty ACK it receives with an ACK right away (the client never answers),
so probes are answered even if the last data packet was lost and sequence numbers no longer match.
No server configuration is needed, but both ends must be rebuilt with this feature.

[Back to TOC](#table-of-contents)

## MTU overhead

Phantun aims to keep tunneling overhead to the minimum. The overhead compared to a plain UDP packet
is the following (using IPv4 below as an example):

**Standard UDP packet:** `20 byte IP header + 8 byte UDP header = 28 bytes`

**Obfuscated packet:** `20 byte IP header + 20 byte TCP header = 40 bytes`

Note that Phantun does not add any additional header other than IP and TCP headers in order to pass through
stateful packet inspection!

Phantun's additional overhead: `12 bytes`. In other words, when using Phantun, the usable payload for
UDP packet is reduced by 12 bytes. This is the minimum overhead possible when doing such kind
of obfuscation.

![Packet header diagram](images/packet-headers.png)

### MTU calculation for WireGuard

For people who use Phantun to tunnel [WireGuard®](https://www.wireguard.com) UDP packets, here are some guidelines on figuring
out the correct MTU to use for your WireGuard interface.

```
WireGuard MTU = Link MTU - IPv4 header (20 bytes) - TCP header (20 bytes) - WireGuard overhead (32 bytes)
```

or

```
WireGuard MTU = Link MTU - IPv6 header (40 bytes) - TCP header (20 bytes) - WireGuard overhead (32 bytes)
```

For example, for a network link with 1500 bytes MTU, the WireGuard interface MTU should be set as:

**IPv4:** `1500 (link MTU) - 20 - 20 - 32 = 1428 bytes`

**IPv6:** `1500 (link MTU) - 40 - 20 - 32 = 1408 bytes`

The resulting Phantun TCP data packet will be 1500 bytes which does not exceed the
interface MTU of 1500.

Please note **Phantun can not function correctly if
the packet size exceeds that of the link MTU**, as Phantun does not perform any IP-fragmentation
and reassembly. For the same reason, Phantun always sets the `DF` (Don't Fragment) bit
in the IP header to prevent intermediate devices performing any fragmentation on the packet.

It is also *strongly recommended* to use the same interface
MTU for both ends of a WireGuard tunnel, or unexpected packet loss may occur and these issues are
generally very hard to troubleshoot.

[Back to TOC](#table-of-contents)

## Version compatibility

While the TCP stack is fairly stable, the general expectation is that you should run same minor versions
of Server/Client of Phantun on both ends to ensure maximum compatibility.

## Documentation

For users who wish to use `fake-tcp` library inside their own project, refer to the documentation for the library at:
[https://docs.rs/fake-tcp](https://docs.rs/fake-tcp).

## Performance

Performance was tested on 2 AWS `t4g.xlarge` instances with 4 vCPUs and 5 Gb/s NIC over LAN. `nftables` was used to redirect
UDP stream of `iperf3` to go through the Phantun/udp2raw tunnel between two test instances and MTU has been tuned to avoid fragmentation.

Phantun `v0.3.2` and `udp2raw_arm_asm_aes` `20200818.0` were used. These were the latest releases of both projects as of Apr 2022.

Test command: `iperf3 -c <IP> -p <PORT> -R -u -l 1400 -b 1000m -t 30 -P 5`

| Mode                                                                            | Send Speed     | Receive Speed  | Overall CPU Usage                                   |
|---------------------------------------------------------------------------------|----------------|----------------|-----------------------------------------------------|
| Direct (1 stream)                                                               | 3.00 Gbits/sec | 2.37 Gbits/sec | 25% (1 core at 100%)                                |
| Phantun (1 stream)                                                              | 1.30 Gbits/sec | 1.20 Gbits/sec | 60% (1 core at 100%, 3 cores at 50%)                |
| udp2raw (`cipher-mode=none` `auth-mode=none` `disable-anti-replay`) (1 stream)  | 1.30 Gbits/sec | 715 Mbits/sec  | 40% (1 core at 100%, 1 core at 50%, 2 cores idling) |
| Direct connection (5 streams)                                                   | 5.00 Gbits/sec | 3.64 Gbits/sec | 25% (1 core at 100%)                                |
| Phantun (5 streams)                                                             | 5.00 Gbits/sec | 2.38 Gbits/sec | 95% (all cores utilized)                            |
| udp2raw (`cipher-mode=none` `auth-mode=none` `disable-anti-replay`) (5 streams) | 5.00 Gbits/sec | 770 Mbits/sec  | 50% (2 cores at 100%)                               |

Writeup on some of the techniques used in Phantun to achieve this performance result: [Writing Highly Efficient UDP Server in Rust](https://idndx.com/writing-highly-efficient-udp-server-in-rust/).

[Back to TOC](#table-of-contents)

## Future plans

* Load balancing a single UDP stream into multiple TCP streams
* Integration tests

## Comparison to udp2raw

[udp2raw](https://github.com/wangyu-/udp2raw-tunnel) is another popular project by [@wangyu-](https://github.com/wangyu-)
that is very similar to what Phantun can do. In fact I took inspirations of Phantun from udp2raw. The biggest reason for
developing Phantun is because of lack of performance when running udp2raw (especially on multi-core systems such as Raspberry Pi).
However, the goal is never to be as feature complete as udp2raw and only support the most common use cases. Most notably, UDP over ICMP
and UDP over UDP mode are not supported and there is no anti-replay nor encryption support. The benefit of this is much better
performance overall and less MTU overhead because of the lack of additional headers inside the TCP payload.

Here is a quick overview of comparison between those two to help you choose:

|                                                  |    Phantun    |      udp2raw      |
|--------------------------------------------------|:-------------:|:-----------------:|
| UDP over FakeTCP obfuscation                     |       ✅       |         ✅         |
| UDP over ICMP obfuscation                        |       ❌       |         ✅         |
| UDP over UDP obfuscation                         |       ❌       |         ✅         |
| Multi-threaded                                   |       ✅       |         ❌         |
| Throughput                                       |     Better    |        Good       |
| Layer 3 mode                                     | TUN interface | Raw sockets + BPF |
| Tunneling MTU overhead                           |    12 bytes   |      44 bytes     |
| Separate TCP connections for each UDP connection | Client/Server |    Server only    |
| Anti-replay, encryption                          |       ❌       |         ✅         |
| IPv6                                             |       ✅       |         ✅         |

[Back to TOC](#table-of-contents)

## License

Copyright 2021-2025 Datong Sun (dndx@idndx.com)

Licensed under the Apache License, Version 2.0 <[LICENSE-APACHE](LICENSE-APACHE) or
[https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0)> or the MIT license
<[LICENSE-MIT](LICENSE-MIT) or [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT)>, at your
option. Files in the project may not be
copied, modified, or distributed except according to those terms.

**[⬆ Back to top](#phantun)**
