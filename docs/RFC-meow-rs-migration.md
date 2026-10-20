# RFC: 内核从 sing-box 迁移至 meow-rs

- **状态**：已实施（Implemented on branch `meow-kernel`，per `docs/spec-meow-migration-A.md` + §13 勘误）
- **日期**：2026-08-28
- **依据版本**：meow-rs `v0.24.0`（`meow-rs/meow-rs` tag；本文 §2–§10 写于 `v0.21.2` 时期，其中 D1 UDP-TPROXY 与 D2 nftables 硬依赖两项阻塞已在 v0.24.0 解除：`listeners[].udp:true` + `firewall:false`），homeproxy_mi `xiaomi` 分支
- **范围**：评估并规划把本项目的代理内核从 sing-box 1.13.x 替换为 meow-rs（mihomo/Clash Meta 的 Rust 实现），覆盖配置生成、防火墙、DNS、订阅、生命周期、Web UI、安装与打包。

---

## 1. 背景与动机

homeproxy_mi 当前以 sing-box 为内核：Lua 生成器把 UCI 配置翻译为 sing-box JSON，iptables/ipset + TPROXY/REDIRECT 做流量接管，自研 CGI API + 静态页做 Web UI，订阅层解析分享链接写入 UCI 节点表。

meow-rs 是 mihomo（Clash Meta）的 Rust 重写（MIT，~3.1MB aarch64-musl 静态二进制，官方 OpenWrt ipk + 内建 Web 面板 + Clash 兼容 REST API）。迁移的潜在收益：

- 二进制体积更小（3.1MB vs sing-box ~12MB），对路由器闪存更友好；
- 内建 fake-ip DNS、规则引擎（GEOSITE/RULE-SET/domain rule-provider）可以把当前"dnsmasq→ipset"的域名分流模型简化；
- Clash 兼容 REST API + 内建 `/ui` 面板，可大幅缩减自研 Web UI；
- 维护方与本项目作者有重叠（aimkiray 为 meow-rs 贡献者），上游协作成本低。

**核心判断：迁移不是"换一个二进制"，而是换配置模型（Clash YAML schema）和透明代理语义（无 UDP TPROXY）。** 本 RFC 逐项核对可行性，并给出分阶段方案。

## 2. meow-rs 能力盘点（已核实）

以 `v0.21.2` 源码与官方文档为准（`docs/gap-analysis.md` 为 2026-04 存档快照，以下以更新的 migration 指南与源码为准）。

### 2.1 发布与平台

| 项 | 状态 |
|---|---|
| 产物 | `meow-v*-aarch64-unknown-linux-musl.tar.gz`（3.1MB 静态）、`meow_*_aarch64_{generic,cortex-a53,a72,a76}.ipk`、`luci-app-meow_*_all.ipk` |
| 架构覆盖 | **仅 aarch64**（OpenWrt 包）。armv7 仅有 gnueabihf（glibc）tar，不能在 musl OpenWrt 上跑；MIPS/32 位无产物，`boring-sys` 不支持 32 位目标（可 `--no-default-features --features full` 自编译，丢 uTLS/ECH/Reality-PQ） |
| 运行时依赖 | 无（musl 静态），需 root/CAP_NET_ADMIN 做透明代理 |
| 构建要求 | Rust ≥1.89（仅自编译时需要） |

### 2.2 Outbound 协议（默认 `full` 构建）

| 协议 | 状态 |
|---|---|
| Shadowsocks（含 AEAD-2022） | ✓ |
| Trojan（TLS + WS/gRPC 等传输） | ✓ |
| VMess（AEAD，tcp/ws） | ✓ |
| VLESS（plain / XTLS-Vision / Reality+uTLS / mlkem768x25519plus PQ） | ✓ |
| Snell v3/v4/v5 | ✓ |
| Hysteria2（QUIC，Salamander 混淆，端口跳跃） | ✓ |
| AnyTLS（含 udp-over-tcp v2） | ✓ |
| HTTP CONNECT / SOCKS5 | ✓ |
| **TUIC / WireGuard / SSH / ShadowsocksR** | **✗ 硬错误（Class A）** |
| Snell v1/v2、`vless flow: xtls-rprx-direct` | ✗ 硬错误 |
| DoQ（`quic://` nameserver） | ✗ 硬错误 |

代理组：`select` / `url-test` / `fallback` / `load-balance` / `relay` 全部支持。

传输层：`tcp | ws | grpc | h2 | httpupgrade`；mux 支持 sing-mux（smux/yamux/h2mux）与 Xray Mux.Cool。

### 2.3 Inbound

| Listener | 状态 | 说明 |
|---|---|---|
| mixed / HTTP / SOCKS5 | ✓ | `mixed-port` 等 |
| **tproxy**（命名误导） | ✓ **TCP-only** | 实为 `SO_ORIGINAL_DST` REDIRECT 语义；源码 `meow-listener/src/tproxy/mod.rs` 只有 TCP accept 路径，无 UDP socket、无 IP_TRANSPARENT |
| tun | ✓（`listener-tun`，含于 `full`） | lwIP 用户态 TCP/IP 栈；`auto-route: fake-ip`（默认）或 `global`（实验，Linux-only，IPv4-only）；`SO_BINDTODEVICE` 防环 |
| shadowsocks（服务端入站） | ✓ | listener 目录存在 `shadowsocks.rs` |
| 其余服务端入站（trojan/vmess/vless/hy2 等） | ✗ | — |

### 2.4 DNS / 规则 / API

- DNS：`udp/tcp/DoH/DoT` nameserver、`default-nameserver`、`nameserver-policy`（含 `geosite:`/`rule-set:` 键）、`fallback-filter`、`hosts`、**fake-ip**（v4/v6 池、filter、持久化）、DNS snooping（redir-host）。
- 规则：全套 classical + `GEOIP`（MaxMind mmdb）+ `GEOSITE`（仅 mrs 格式）+ `RULE-SET` + `SUB-RULE` + `AND/OR/NOT` + `PROCESS-NAME` + `IN-NAME/IN-TYPE/IN-PORT`。
- `rule-providers`：http/file/inline，`behavior: domain|ipcidr|classical`，`format: yaml|text`（**纯文本域名列表可直接消费**），支持 interval 刷新。
- REST API：Clash 面板面兼容（`/proxies`、`PUT` 切换、`/delay`、`/traffic`、`/connections`、`/logs`、`/memory`、`/rules`、providers、`PATCH /configs` 仅 mode/log-level、`PUT /configs` 冷重载）；`secret` Bearer 鉴权**强制生效**；另有 `/api/subscriptions/*`、`/api/proxy-groups/*`、规则 CRUD、`/metrics`、内建 `/ui` 面板。
- 配置：`serde_yaml` 解析（JSON 是 YAML 子集 → 可继续以 JSON 编码输出）；`meow -f cfg -t` 提供配置校验；不支持字段按 Class A（硬错误）/Class B（warn-once）分级。

## 3. 硬障碍与决策点

### D1. UDP 透明代理缺失（阻塞项）

meow 的 tproxy listener **不接收 UDP**。当前 firewall.sh 的 `TPROXY --tproxy-mark` UDP→5332 链路没有接收端。

可选策略：

| 方案 | 说明 | 代价 |
|---|---|---|
| **a) 放弃 UDP 代理**（推荐 v1） | fake-ip + `REJECT udp/443`（逼 QUIC 回退 TCP）；其余 UDP 直连放行 | 游戏语音、局域网 WireGuard/STUN 等 UDP-only 流量不可代理；与 meow 官方 gateway 文档做法一致 |
| b) TUN 承载 UDP | `tun.auto-route: global` 捕获全部流量 | lwIP 用户态栈吞吐/CPU 受限；IPv4-only；实验性；与 iptables TCP 接管并存时模型复杂 |
| c) 上游实现真 TPROXY UDP | recvmsg + `IP_RECVORIGDSTADDR` + `IP_TRANSPARENT` | 大工程量，需上游排期 |

**建议**：v1 采用方案 a，同时向上游提 issue 评估 c；`tun` 模式保留为可选能力（方案 b 的子集）。

### D2. tproxy listener 强依赖 nftables（阻塞项，需上游配合）

`FirewallGuard::setup(...)?` 在 listener 启动时无条件执行 `nft -f -`；MiWiFi 无 `nft` 二进制/内核 → **listener 启动失败**。无配置开关。

选项：

1. **上游 PR**（正解）：`listeners[].firewall: false` / `tproxy-firewall: off`，或 `nft` 缺席时 warn-and-continue。上游活跃且本项目作者为贡献者，可行性高。
2. **本地桩**：ship 一个 `#!/bin/sh\nexit 0` 的 `/usr/bin/nft` 桩。可行但脆弱（污染 nft 命名空间语义，未来真装了 nft 会静默失效）。

**建议**：先提上游 issue/PR；过渡期可用桩脚本验证链路。

### D3. 协议裁剪

WireGuard / TUIC / SSR / SSH 节点在 meow 下为**配置级硬错误**。订阅更新层必须把这类节点**过滤而非写入**，否则整份配置无法加载。现有节点若含上述类型，迁移时需显式删除并在 UI/日志中提示。

### D4. 架构覆盖

仅 aarch64 小米设备（AX3000T/AX6000/AX9000 等 MT798x/IPQ50xx 系）可直接用官方产物；**MIPS 设备（4A/R3G/R3P 等）不在支持面内**。本项目若仍需覆盖 MIPS，只能保留 sing-box 路径做双内核，或放弃这些设备。

## 4. 目标架构设计

### 4.1 配置模型映射（UCI → Clash schema）

生成器仍由 `generate_client.lua` 产出，但输出从 sing-box JSON 改为 mihomo schema。serde_yaml 兼容 JSON 解析，**可继续用 `hp.encode_json` 输出 JSON**，免除 Lua YAML emitter。

| 当前 sing-box 概念 | meow-rs 配置 | 备注 |
|---|---|---|
| `inbounds: mixed` :5330 | `mixed-port: 5330` + `allow-lan` | 平移 |
| `inbounds: redirect` :5331 | `listeners: [{name: tproxy-lan, type: tproxy, listen: '::', port: 5331}]` | 必须 `listen` 非 loopback（REDIRECT 后目的地址为 LAN IP） |
| `inbounds: tproxy` :5332 (UDP) | — | 删除（见 D1） |
| `inbounds: dns` :5333 | `dns: {enable: true, listen: 0.0.0.0:5333}` | 平移 |
| `inbounds: tun` (singtun0) | `tun: {enable, auto-route: fake-ip\|global, dns-hijack: [any:53]}` | 语义变化，见 §4.3 |
| `route.rules` / `route.final` | `rules:` 数组 + `MATCH` 尾规则 | 重写 |
| `outbounds: <节点>` | `proxies:` 数组（mihomo proxy map） | 字段映射重写 |
| `outbounds: urltest/selector` | `proxy-groups:` | 平移 |
| `routing_mark` 逐 outbound | 顶层 `routing-mark: 100` | 语义等价（标记 DIRECT/绕行 socket） |
| `experimental.clash_api` :19290 | `external-controller: 127.0.0.1:19290` | 平移；`secret` 可留空（LAN-bound，与现状一致，meow 会 warn-once） |
| `dns.servers` 表 | `dns.nameserver` / `nameserver-policy` / `default-nameserver` | 重写 |
| 直连/阻断 | `DIRECT` / `REJECT` | 平移 |

`generate_server.lua`：meow 仅提供 shadowsocks 服务端入站。**决策点 D5**：server 功能收缩为"仅 SS 入站"，或保留 sing-box 双内核仅用于 server。

### 4.2 防火墙（firewall.sh 重构）

meow 内建 nft 防火墙全部弃用（且按 D2 需上游开关绕过）。保留并简化现有 iptables/ipset：

- **TCP PREROUTING/OUTPUT**：`REDIRECT --to-ports 5331`（替代当前 TPROXY TCP 路径；meow listener 即 REDIRECT 实现，语义不变）。
- **UDP**：`tproxy`/TPROXY 规则整体移除；按 D1-a 增加可选 `REJECT --reject-with icmp-port-unreachable udp/443`（QUIC 抑制）。
- **DNS 劫持**：`dnsmasq` 的 `server=/…/` 维持现状；额外把 LAN :53 `DNAT`/`REDIRECT` 到 meow `dns.listen`（若启用 fake-ip 则由 meow 全权应答）。
- **ipset**：静态 `china_ip4/6` CIDR 集合继续用于 bypass（IP 级分流与 fake-ip 兼容）；`wan_proxy`/`wan_direct` 等**域名填充动态集合作废**——fake-ip 模式下域名分流发生在 meow 内部规则层，dnsmasq `ipset=/domain/set` 注入删除。
- **mark/路由表**：`ip rule fwmark` + table 100 的 TPROXY 路由可整体移除（无 TPROXY 后不需要）；`routing-mark` 仅保留给 meow 防环语义。
- **tproxy_tun / tun 模式**：若保留 TUN，init.d 不再手建 `singtun0`/策略路由——meow 自管设备与路由（`auto-route`），防火墙只留 DNS 引导与必要的排除规则。

### 4.3 DNS 模型重构（最大设计变更）

现状：dnsmasq 按域名表把 `ipset=` 写入 wan_proxy/wan_direct → 防火墙按目的 IP 分流。

目标（推荐 fake-ip 模式）：

- meow `dns: {enable, listen: 0.0.0.0:5333, enhanced-mode: fake-ip, fake-ip-range: 198.18.0.0/16}`；dnsmasq 上游指向 meow 或直接 DNAT LAN DNS 到 meow。
- 域名分流改为 **meow 规则**：`rule-providers` 直接消费现有文本资源——`china_list.txt`/`gfw_list.txt`（`behavior: domain, format: text`），规则形如 `RULE-SET,gfwlist,<proxy-group>`、`RULE-SET,cn-domain,DIRECT`。
- IP 分流：`GEOIP,CN,DIRECT`（需 Country.mmdb，`update_resources.sh` 改抓 mmdb）或继续依赖 iptables 层 `china_ip4` ipset 旁路（两层皆可，iptables 层更早、更省内核 CPU）。**建议**：iptables 保留 china_ip4 旁路 + meow 内 `GEOIP,CN,DIRECT` 双保险。
- `bypass_mainland_china`/`proxy_mainland_china`/`gfwlist`/`global`/`custom` 五种 routing_mode → 映射为不同的 `rules:` 组合 + `mode: rule`；`global` → `mode: global`。
- 注意 fake-ip 陷阱：`IP-CIDR,198.18.0.0/16,DIRECT` 类规则会吞掉一切未匹配域名，生成器必须禁止用户自定义规则包含 fake-ip 段的 DIRECT 规则。

备选 redir-host 模式：保留"真实 IP 进 ipset"的旧模型，meow 用 snooping 反查域名；兼容 GEOIP/IP-CIDR 规则但有一次上游解析延迟与投毒暴露。作为降级选项保留。

### 4.4 订阅层（update_subscriptions.lua + subscription_parser.lua）

- meow 的 `subscriptions:`/`proxy-providers:` **只认 Clash YAML**，不解析 `ss://`/`vmess://` 分享链 → **本项目解析层继续存在**。
- `subscription_parser.lua`：解析逻辑不变，输出从"sing-box outbound 字段"改为"mihomo proxy map"（字段名差异大：`server/port/cipher/password/uuid/alterId/network/ws-opts/tls/sni/flow/reality-opts` 等）。
- `update_subscriptions.lua`：写入面两种方案——
  - **方案 A（改动小）**：维持 UCI 节点表，生成器二次翻译为 `proxies:`。UCI schema 调整字段名。
  - **方案 B（推荐）**：订阅结果直接写成 Clash YAML 片段文件（`/etc/homeproxy/proxies.d/*.yaml`），生成器只做合并引用——节点不再进 UCI，urltest 组改为 `proxy-groups` 生成。UCI 只保留全局设置。
- 协议白名单收缩：`ss|ss2022|vmess|vless|trojan|hysteria2|snell|anytls|http|socks5`；`wireguard|tuic|ssr|ssh` 解析到即丢弃并计数告警。

### 4.5 Web UI / API

- **保留自研 UI**：Clash API 兼容面已覆盖 UI 用到的 `/proxies`、`PUT` 切换、`/delay`、`/traffic`；`cgi-bin/api` 里对 sing-box 的调用换成 `external-controller` 端点；UCI 写接口（订阅 URL、DNS、list、开关）逻辑不变。**改动小**。
- **或换内建面板**：`external-controller` 监听 LAN + 直接用 meow `/ui`，自研 UI 退化为"服务开关 + UCI 设置"两页。激进但更省维护。
- API 安全基线沿用现有 Origin/Referer+Content-Type 检查；若给 meow 配 `secret`，CGI 需注入 Bearer 头。

### 4.6 生命周期 / 安装 / 打包

- `init.d/homeproxy`：启动命令改 `meow -f $CFG`；前置校验改 `meow -f $CFG -t`；删除 tun 设备/策略路由手工创建（交 meow 或按 D1-a 删除 tun 模式）；`TPROXY` 相关 `ip rule`/table 100 删除。
- `proxy_mode` 取值收缩：`redirect`（TCP 全接管）、`redirect_tun`?→重新定义为 `redirect` + `tun` 组合由两个布尔控制更清晰；或直接 `routing` 三段：`off|redirect|tun`。**决策点 D6**。
- `install.sh`：下载源改 meow release（`aarch64-unknown-linux-musl.tar.gz`）；校验逻辑沿用；`env.sh` 增 `HP_MEOW`。
- `Makefile`：依赖去掉 `kmod-ipt-tproxy`/`iptables-mod-tproxy`（D1-a 下不需要 TPROXY 模块）；保留 `iptables-mod-ipset`+`ipset`；`+sing-box` 改 `+meow`（若走官方 ipk 则独立安装，Makefile 仅包壳层）。
- `update_resources.sh`：资源面改为 `Country.mmdb` + `geosite.mrs`（可选）+ 现有域名文本表（直接复用）。
- CLI：`homeproxy generate` 校验换 `meow -t`；其余 UCI 操作不变。

## 5. 分阶段迁移计划

| 阶段 | 内容 | 出口标准 |
|---|---|---|
| **P0 上游解锁** | 提 issue/PR：tproxy 防火墙可关；评估 UDP TPROXY | 有上游答复；过渡期可用 nft 桩验证 |
| **P1 设备确认** | 确认目标设备 aarch64 + 内核功能 | 明确是否放弃 MIPS |
| **P2 生成器** | `generate_client.lua` 改 Clash schema；订阅输出改 mihomo proxy map；协议白名单 | `meow -t` 通过；真机 TCP 代理通 |
| **P3 防火墙** | UDP TPROXY 移除、REDIRECT 收敛、fake-ip DNS 引导、ipset 收敛 | TCP 接管+CN 旁路真机验证 |
| **P4 DNS** | fake-ip + rule-providers 迁移域名表 | 域名分流正确性真机验证 |
| **P5 生命周期/UI/安装** | init.d、CLI、api、install.sh、Makefile | 端到端 install→subscribe→generate→start |
| **P6 清理** | server 模式决策落地、旧模式迁移 UCI defaults、文档 | migrate_config 覆盖旧配置升级 |

工作量预估：生成器与订阅字段映射是主体（sing-box outbound schema ↔ mihomo proxy map 逐字段翻译）；防火墙反而减负；UI 几乎不动。

## 6. 风险登记册

| 风险 | 等级 | 缓解 |
|---|---|---|
| UDP 代理能力回退（QUIC/游戏） | 高 | D1 决策；fake-ip+REJECT 443；保留上游 TPROXY 诉求 |
| nftables 硬依赖阻塞启动 | 高 | 上游 PR 或 nft 桩；P0 先行 |
| MIPS 设备失支持 | 高 | P1 明确设备面；必要时双内核并存 |
| 用户存量 wireguard/tuic 节点失效 | 中 | 迁移过滤 + UI 明示 + 日志计数 |
| lwIP TUN 吞吐/稳定性（若用） | 中 | 默认不走 tun；真机压测 |
| fake-ip 与既有 dnsmasq ipset 模型冲突 | 中 | §4.3 重构；redir-host 降级路径 |
| meow-rs 年轻项目（v0.21，API 面仍在补齐） | 中 | pin 版本 + `meow -t` 门禁 + 订阅解析容错 |
| `serde_yaml` 对生成 JSON 的边缘差异（键序、锚点） | 低 | 输出纯 JSON 子集；`meow -t` 验证 |
| server 模式仅剩 SS | 低-中 | D5 决策；或双内核 |

## 7. 未决问题（需决策）

- **D1**：UDP 策略（放弃 / tun 承载 / 上游实现）——建议放弃，v1。
- **D2**：nft 依赖处理方式（上游开关 PR / 本地桩）——建议上游 PR。
- **D5**：server 模式收缩为 SS-only 或保留 sing-box 双内核？
- **D6**：`proxy_mode` 取值重新设计（redirect / tun / redirect+tun 组合）？
- **D7**：订阅节点存储（UCI 翻译 vs YAML 片段直接合并）？建议方案 B。
- **D8**：Web UI 保留自研 vs 换 meow `/ui`？建议保留自研（改动小、可控）。

## 8. 附录：文件级改动预估

| 文件 | 改动 |
|---|---|
| `root/usr/lib/homeproxy/generate_client.lua` | 重写输出 schema（中-大改） |
| `root/usr/lib/homeproxy/subscription_parser.lua` | 输出字段映射改 mihomo proxy map（中改） |
| `root/usr/lib/homeproxy/update_subscriptions.lua` | 协议白名单收缩 + （方案 B）写 YAML 片段（中改） |
| `root/usr/lib/homeproxy/generate_server.lua` | 收缩至 SS 或废弃（小-中改） |
| `root/usr/lib/homeproxy/firewall.sh` | 删 UDP TPROXY/mark 路由，收敛 REDIRECT+DNS+ipset（中改） |
| `root/etc/init.d/homeproxy` | 命令/校验/tun 段改写（中改） |
| `root/usr/bin/homeproxy` | `meow -t` 校验、模式取值（小改） |
| `root/etc/homeproxy/web/cgi-bin/api` + `index.html` | Clash API 端点替换（小改） |
| `install.sh` / `Makefile` / `.github/build-ipk.sh` | 下载源/依赖/产物名（小-中改） |
| `root/etc/homeproxy/scripts/update_resources.sh` | 资源改 mmdb/mrs（小改） |
| `root/etc/config/homeproxy` + `migrate_config.lua` | UCI schema 迁移（中改） |
| `tests/*.py` | 解析器断言同步（小改） |
