# HomeProxy × meow-rs 迁移实施规范（候选 A）

- **状态**：候选实施规范（未实施；实施前需评审签字）
- **依据内核**：meow-rs `v0.24.0`（`C:\Users\laevatain\Code\meow-rs` @ `v0.24.0` tag 源码逐条核实）
- **依据前端**：homeproxy_mi @ `meow-kernel` 分支现状（sing-box 版生成器/防火墙/init/CLI/API/安装器）
- **目标环境**：Xiaomi/MiWiFi stock router（OpenWrt 18.06 派生，kernel 5.4，BusyBox/ash，Lua 5.1 + `uci` + `luci.json`，`iptables`/`ip6tables`/`ipset`/`xt_TPROXY`；**无** nftables、fw4、ucode、jq、jsonfilter）

本文是 U1–U8 全部迁移单元的实施规格。所有标注 **[verified v0.24.0]** 的行为均直接读自上游 tag 源码；标注 **[decision]** 的是本规范做出的取舍。

---

## 0. 范围与硬约束

### 0.1 工作单元

| 单元 | 内容 | 对应章节 |
|------|------|----------|
| U1 | 构建、打包、安装（cargo zigbuild / install.sh / Makefile / build-ipk.sh / env.sh） | §2 |
| U2 | UCI schema 与 `migrate_config.lua` 迁移（`tproxy_port`、`proxy_mode`、TUN 选项处置） | §3 |
| U3 | `generate_client.lua`：UCI → meow YAML（节点/组/规则/rule-provider/listener/DNS） | §4 |
| U4 | `generate_server.lua`：UCI `server` 段 → meow 服务端 YAML | §5 |
| U5 | `firewall.sh`：五种 `routing_mode` × 新 `proxy_mode` 语义的 iptables/ip6tables/ipset 规则、策略路由、DNS 劫持、清理 | §6 |
| U6 | DNS 架构：dnsmasq 前置分流 + meow `127.0.0.1:5333` | §7 |
| U7 | 生命周期：init.d/procd、`homeproxy` CLI、CGI API、日志、锁、boot_restore | §8 |
| U8 | 订阅/节点导入/特性探测/资源更新 | §9 |

### 0.2 硬约束（实施中不得违反）

1. Lua 仅 5.1 语法；复用 `root/usr/lib/homeproxy/homeproxy.lua` 的 `hp.*` 助手；JSON 一律经 `hp.encode_json`（YAML 输出=emit JSON，见 §4.1）。
2. Shell 一律 POSIX/ash + `set -u`；禁止 `local` 之外 bashism；防火墙调用一律 best-effort（`2>/dev/null`）。
3. 禁止引入 nft/nftables、fw4、ucode、jq、jsonfilter、`sed` 部署期补丁。
4. 防火墙规则由本仓库完全所有：meow 配置中任何 listener 必须 `firewall: false`（§6.1，verified：为 `true` 时 meow 会调用 nftables/pfctl，stock router 上必然失败）。
5. 生成文件一律 tmp+rename 原子写；旧生成文件必须被清理；验证失败必须可回滚到上一可用配置。
6. 单一内核契约：**只**构建/分发 meow-rs v0.24.0，`aarch64-unknown-linux-musl`，`cargo zigbuild --release --target aarch64-unknown-linux-musl --features "full listener-shadowsocks"`，二进制名 `meow`。规格中所有能力判断以该 feature 集为准，不做多内核抽象。

### 0.3 meow v0.24.0 已核实行为摘要（实施依据）

- `meow -f <yaml>` 运行；`-t` 离线校验（不拉取 provider/订阅网络 I/O，但校验编译 feature 与必填字段）；`--version` 输出版本串；`-d <dir>` 设 home 目录；`--no-external-plugins` 禁外部 SIP003 子进程插件（内置插件不受影响）。
- `listeners:` 命名监听：`{name, type, listen, port, firewall, udp, udp-timeout, max-connections, …}`。`tproxy` 类型 `firewall:false` 时不触碰任何系统防火墙、不收集 bypass-IP、退出不清理。
- `tproxy` + `udp:true`（**要求** `firewall:false`）：同一 TCP 监听 socket 上同时启用 IPv4 UDP TPROXY（`IP_TRANSPARENT` + `IP_RECVORIGDSTADDR`）。**UDP TPROXY 仅 IPv4**：`listen` 必须是 IPv4 字面地址（`::`/双栈被拒绝），fwmark 策略路由由部署方自备。
- TCP 透明代理由外部 REDIRECT 送入，meow 经 `SO_ORIGINAL_DST` 恢复原目的（先 IPv4 后 IPv6 getsockopt）。`tproxy-port` 顶层简写绑死 `127.0.0.1` 且 firewall=managed —— **不可用**，必须用 `listeners:` 命名项 + `listen: "0.0.0.0"`。
- `routing-mark: N` **只**给 `DIRECT` outbound socket 打 `SO_MARK`；proxy adapter 出站不打标（verified）。
- `dns:`：`enable/listen/enhanced-mode/nameserver/nameserver-policy/default-nameserver/proxy-server-nameserver/fallback-filter/fake-ip*`。nameserver 条目支持裸 IP/hostname、`udp://`、`tcp://`、`tls://`、`https://`、`rcode://`；`#PROXY` 后缀**仅**对 plain 形式（裸/`udp://`/`tcp://`）表示"经名为 PROXY 的出站转发"；`tls://`/`https://` 中的 `#` 被解析为 SNI。
- `nameserver-policy` key 支持域名、`geosite:`、`rule-set:`（引用 `rule-providers` 条目）。
- `rule-providers` `type: file` 的 `path` 相对配置 home 目录解析（未传 `-d` 时取配置文件父目录），有 safe-path 包含性检查；`SKIP_SAFE_PATH_CHECK=1` 可关（本规范不依赖）。
- 代理类型（`full`）：`ss/trojan/vless/vmess/snell/http/socks5/anytls/hysteria2/direct`。`smux:`（别名 `mux:`，二者同存时 `smux` 赢）块字段：`enabled/protocol(smux|yamux|h2mux|muxcool)/max-connections/max-streams/min-streams/padding/only-tcp`；标量值报错；`padding+muxcool` 报错；`statistic`/`brutal-opts` warn-and-ignore。
- SS 内置插件名（进程内实现）：`obfs|simple-obfs|v2ray-plugin|gost-plugin|shadow-tls|restls|jls|ech-tls-tunnel|kcptun`；其它名字=外部 SIP003 子进程（被 `--no-external-plugins` 拒绝）。
- API（external-controller）：`GET /proxies` 列表、`GET /proxies/{name}/delay?url=<u>&timeout=<ms>` → `{"delay":<u16>}`；400/404/503/504 语义已核实。`/version` → `{"version":..,"meta":true}`。
- 服务端：仅 `type: shadowsocks` listener（`listener-shadowsocks` feature）；`cipher/password/udp/simple-obfs{enable,mode}`；`rules: [MATCH,DIRECT]` 把入站流量转 DIRECT 出站。

---

## 1. 决策总览（D1–D18）

| # | 决策 | 取值 | 理由/出处 |
|---|------|------|-----------|
| D1 | 内核产物 | `meow` v0.24.0，`aarch64-unknown-linux-musl`，zigbuild，`full+listener-shadowsocks` | 契约固定，§2 |
| D2 | 生成配置 | `/var/run/homeproxy/meow-c.yaml`、`meow-s.yaml`；**JSON 文本**（YAML 1.2 子集，`hp.encode_json` 输出） | 路由器无 YAML emitter；JSON 是合法 YAML |
| D3 | 端口 | mixed `5330`；tproxy listener `5331`（= `infra.redirect_port`）；DNS `127.0.0.1:5333`；ext-ctl `127.0.0.1:19290`；v6 TCP listener `5334`（新增 `infra.v6_port`） | 复用既有端口面 |
| D4 | `infra.tproxy_port` | **删除**。UDP TPROXY 与 TCP REDIRECT 共用 `redirect_port`（meow 单端口双协议） | §3.3；v0.24.0 单 socket 契约 |
| D5 | `config.proxy_mode` | 新词表 `{redirect, tproxy, redirect_tproxy}`；含义=TCP 接管臂 × UDP 接管臂正交组合；**TUN 全部移除** | §3.4 |
| D6 | IPv6 | `ipv6_support=1` → 第二个 TCP-only listener `[::]:5334` + ip6tables REDIRECT 镜像；**IPv6 UDP 一律不接管**（v0.24.0 UDP TPROXY 仅 v4） | §6.5 |
| D7 | 路由器自身流量 | **取消 OUTPUT 链 self-steering**；需要走代理的自身流量显式用 mixed 口 `127.0.0.1:5330`（`curl -x`/`http_proxy`） | meow 无法给 proxy-adapter 出站打标，OUTPUT 接管会产生不可判定的回环风险；§6.4 |
| D8 | DNS | 保留 dnsmasq 前置（域名分流 + ipset 填充）；meow `dns:` 提供解析，`enhanced-mode: redir-host`；走代理的上游只用 `udp://`/`tcp://`+`#main-out` | §7 |
| D9 | `routing-mark` | 仍发 `routing-mark: <self_mark>`（只管 DIRECT socket，advisory）；`self_mark` RETURN 规则保留于链首 | §6.2 |
| D10 | 节点 tag | `cfg-<md5>-out`（materialize）、`main-out`、`main-udp-out`、组同名 | 与现 CLI/API 兼容 |
| D11 | 不支持节点 | 生成期 quarantine：跳过 + stderr warn + `/var/run/homeproxy/unsupported-nodes.json` | §4.6 |
| D12 | 服务端 | 仅 `type=shadowsocks` 段映射为 `listeners:` `type: shadowsocks`；其它 server 类型 skip+warn | §5 |
| D13 | `HP_MATERIALIZE_ALL_NODES` | 保留（默认 1）；`-t` 失败时 retry `=0` | §8.2 |
| D14 | 特性探测 | `singbox-features.json` → `meow-features.json`：`meow -t` 探针 YAML；`with_quic=hysteria2`、`with_utls=client-fingerprint`、`with_hysteria=false` 恒成立 | §9.3 |
| D15 | `update_via_proxy` | 改为显式 `http_proxy=http://127.0.0.1:5330`（curl `-x` / wget env） | 与 D7 配套 |
| D16 | TUN | `singtun0` 及 `infra.tun_*` 全部移除；init stop 保留一次性清理旧设备 | §3.5 |
| D17 | log | `/var/run/homeproxy/meow-c.log`、`meow-s.log`、`homeproxy.log` | §8.1 |
| D18 | API | `GET /status`、`/settings`、`/ping_node` 兼容；version=`meow --version`/`/version`；delay 走 `/proxies/cfg-<md5>-out/delay` | §8.5 |

---

## 2. U1 — 构建、打包与安装

### 2.1 构建契约

```bash
# 唯一受支持的构建方式
cargo zigbuild --release \
  --target aarch64-unknown-linux-musl \
  --features "full listener-shadowsocks"
# 产物：target/aarch64-unknown-linux-musl/release/meow
```

- `full` 已含：ss/trojan/vless(+vision+encryption)/vmess/snell/hysteria2/anytls/http+socks5+tproxy+mixed+tun listener、mux、kcptun、dns(+encrypted)。`listener-shadowsocks` 为单独 feature，**必须显式加**（契约要求）。
- 不构建/不使用 `listener-tun`（即便 full 已含，本设计不发 tun 块；见 D16）。
- 版本钉死 v0.24.0；升级内核须改本规范并重新核实 §0.3。

### 2.2 Makefile（OpenWrt package）

- `DEPENDS`：删 `+sing-box`；**不加** `+meow`（stock MiWiFi 无 meow 源包，二进制经 install.sh 落到 `/data/other_vol/bin/meow`；若上游 OpenWrt 包可用，可改 `+meow`——未决问题 Q3）。
- Title/Description 中 sing-box 字样改 meow-rs。
- 保留 `+lua +luci-lib-json +iptables +iptables-mod-tproxy +kmod-ipt-tproxy +iptables-mod-ipset +kmod-ipt-ipset +ipset +curl +firewall +uhttpd`。

### 2.3 install.sh

- 变量重命名：`HP_SINGBOX`→`HP_MEOW`（下载 URL）；新增 `HP_MEOW_SHA256`（可选，留空跳过校验并保持原行为）；`MEOW_BIN=/data/other_vol/bin/meow`；`MEOW_VER_EXPECT=v0.24.0`。
- 流程不变：下载 → sha256 校验 → 备份现行 `meow` → 原子替换 → `meow --version` 冒烟 → `homeproxy generate && /etc/init.d/homeproxy restart` → 30s 探活失败回滚。
- `need_singbox()` → `need_meow()`：`command -v meow` 缺失或版本串不含 `0.24` 即触发安装。版本串解析：`meow --version` 第一行 `sed -n 's/^meow //p'`（clap `version` 输出形如 `meow 0.24.0`）。
- `env.sh` 生成 `HP_MEOW_BIN=<实际路径>`；`hp.exec_bin`/`init.d`/`CLI` 一律 `${HP_MEOW_BIN:-/usr/bin/meow}`。
- **不**做 setcap：procd 以 root 跑 meow（与现状一致；TPROXY listener 需要 CAP_NET_ADMIN，root 已含）。

### 2.4 `.github/build-ipk.sh`

- 包名/描述中 `sing-box`→`meow`；不再往 ipk 里塞内核二进制（与现 `install.sh` 分发模式一致）。

### 2.5 boot_restore.sh / update_crond.sh

- `pgrep -f "sing-box run"` → `pgrep -f "meow -f /var/run/homeproxy/meow-"`；其余持久化恢复逻辑不变。

---

## 3. U2 — UCI Schema 与配置迁移（`migrate_config.lua`）

### 3.1 `infra` 段

| 选项 | 处置 | 说明 |
|------|------|------|
| `mixed_port` | 保留 `5330` | meow `mixed-port` |
| `redirect_port` | 保留 `5331` | TCP REDIRECT **和** UDP TPROXY 共同目标端口 |
| `tproxy_port` | **删除** | 若曾设置且 ≠ `redirect_port`：迁移时 logwarn `"infra.tproxy_port is removed; UDP TPROXY now shares redirect_port (5331)"`，值被丢弃。UCI 默认文件不再含此项 |
| `dns_port` | 保留 `5333` | meow `dns.listen` |
| `v6_port` | **新增**，默认 `5334` | IPv6 TCP-only tproxy listener 端口（D6） |
| `dns_redirect` | 保留 `1` | dnsmasq 劫持开关 |
| `tun_name/tun_addr4/tun_addr6/tun_mtu/tun_table/tun_mark` | **删除** | TUN 移除；删除前把 `tun_name` 值（默认 `singtun0`）写入 `/var/run/homeproxy/legacy-tun-name` 供 init stop 清理 |
| `table_mark`/`self_mark`/`tproxy_mark` | 保留 `100/100/101` | `routing-mark`、`ip rule fwmark`、`-j MARK` |
| `udp_timeout` | **新增**，默认 `60`（秒，可 `Nm`/`Ns` 后缀，规范化整数秒，`1..86400`） | `listeners[].udp-timeout` |

### 3.2 `config` 段

| 选项 | 处置 |
|------|------|
| `main_node`/`main_udp_node`/`dns_server`/`china_dns_server`/`routing_mode`/`routing_port`/`ipv6_support`/`log_level` | 语义保留 |
| `proxy_mode` | 见 §3.4 重写表 |

### 3.3 `infra.tproxy_port` 迁移细则

```lua
-- migrate_config.lua（伪代码）
local tp = uci:get("homeproxy","infra","tproxy_port")
if tp and tp ~= uci:get("homeproxy","infra","redirect_port") then
    logwarn("infra.tproxy_port=" .. tp .. " discarded; UDP TPROXY shares redirect_port")
end
uci:delete("homeproxy","infra","tproxy_port")
```

### 3.4 `config.proxy_mode` 重写表（幂等）

| 旧值 | 新值 | 语义 |
|------|------|------|
| `redirect` | `redirect` | 仅 TCP REDIRECT→5331 |
| `tproxy` | `redirect_tproxy` | 旧值=TCP+UDP TPROXY；新实现=TCP REDIRECT+UDP TPROXY（语义最接近，TCP 仍被代理） |
| `redirect_tproxy` | `redirect_tproxy` | 不变 |
| `redirect_tun`/`tun`/`tproxy_tun` | `redirect_tproxy` | TUN 移除，回退到能力最强的无 TUN 组合 |
| （新增合法值）`tproxy` | — | 新语义=**仅** UDP TPROXY（TCP 不接管）；仅新配置可写入 |

CLI `homeproxy proxy-mode` 合法值更新为 `{redirect|tproxy|redirect_tproxy}`，help 注明新语义。

### 3.5 TUN 清理

- `migrate_config.lua`：删除全部 `infra.tun_*` 并把旧 `tun_name` 落盘 `legacy-tun-name`（一次性）。
- `init.d stop`/`firewall stop`：若 `legacy-tun-name` 存在或 `ip link show singtun0` 成功 → `ip link del <name>`、`ip rule del fwmark <tun_mark> table <tun_table>`（best-effort），然后删 `legacy-tun-name`。
- 永不向 meow 配置发 `tun:` 块。

---

## 4. U3 — 客户端配置生成（`generate_client.lua` → `meow-c.yaml`）

### 4.1 格式与写出

- **格式**：meow 需要 YAML；路由器无 YAML emitter → **直接输出 JSON**（YAML 1.2 是 JSON 超集，meow 用 serde_yaml 解析，JSON 全兼容）。文件仍命名 `.yaml` 以表达语义。
- 写 `meow-c.yaml.tmp` → `luci.json` `encode` → `rename` 原子替换；同目录旧文件先删。
- `meow -t -f meow-c.yaml` 校验（离线，不拉 provider；file provider 会被 stat 但不网络 I/O）。
- 失败 → 若 `HP_MATERIALIZE_ALL_NODES=1`（默认）则置 0 重生成重校验一次；仍失败 → 保留旧 yaml 不重启，init 报错退出。

### 4.2 顶层骨架（字段序无关，JSON 对象）

```jsonc
{
  "mode": "rule",
  "log-level": "<warn|info|debug|error|trace → 原样；fatal/panic→error>",
  "ipv6": <ipv6_support>,
  "mixed-port": 5330,
  "allow-lan": true,
  "bind-address": "*",
  "external-controller": "127.0.0.1:19290",
  "routing-mark": 100,          // self_mark；仅 DIRECT socket（advisory）
  "strict": false,               // 生成器已做字段校验，runtime 走 warn-and-skip
  "sniffer": { "enable": true }, // 取代 sing-box 的 action:"sniff"
  "dns": { ...§7 },
  "proxies": [ ...§4.4 ],
  "proxy-groups": [ ...§4.5 ],
  "rule-providers": { ...§4.7 },
  "listeners": [ ...§6.3 ],
  "rules": [ ...§4.8 ]
}
```

不发：`tun:`、`tproxy-port`、`tproxy_sni`、`global-client-fingerprint`（逐节点发）、`secret`（ext-ctl 仅 loopback）。

### 4.3 节点 tag 规则

- `cfg-<md5(sect)前8>-out`：每个被 materialize 的节点一一对应（与现 API/CLI tag 兼容，纯 ASCII）。
- `main-out`：main_node 指向节点的**完整复制条目**（同 server/port/凭据，仅 name 不同）；main_node 为 urltest → `proxy-groups` 中 `name: "main-out", type: "url-test"`。
- `main-udp-out`：`main_udp_node` 为独立节点/urltest 时同理；`"same"`→不发。
- meow 不 dedupe，同名冲突必须避免：`main-out`/`main-udp-out`/组名保留字，节点 tag 永不与之碰撞（前缀 `cfg-`）。

### 4.4 UCI `nodes` 段 → `proxies` 映射表

公共裁剪：未知 type → quarantine（§4.6）。`packet_encoding`（sing-box 专有）丢弃不映射。`multiplex`→`smux` 块映射：protocol `{smux,yamux,h2mux→h2mux}`、`max_connections→max-connections`、`min_streams→min-streams`、`max_streams→max-streams`、`padding→padding`、`brutal→brutal-opts`（发则 meow warn-ignore，故 **不映射** brutal 字段）、`only_tcp→only-tcp`。

| UCI `type` | meow `type` | 字段映射 | 拒绝条件（→quarantine） |
|---|---|---|---|
| `shadowsocks` | `ss` | `server,port,cipher=encrypt_method,password,udp:true`;`plugin→plugin`,`plugin_opts→plugin-opts`;`client_fingerprint→client-fingerprint` | `plugin` 不在内置表 §0.3；`encrypt_method` 不在 AEAD 集 |
| `vless` | `vless` | `server,port,uuid,udp,tls,servername,alpn,network,client-fingerprint,flow,encryption`;`tls_reality→reality-opts{public-key,short-id}`;ws/grpc/h2/httpupgrade/xhttp→`ws-opts/grpc-opts/h2-opts/http-upgrade-opts/xhttp-opts` | `flow` 存在且 ≠`xtls-rprx-vision`；`network`∉`{tcp,ws,grpc,h2,httpupgrade,xhttp}`；reality 启用 → 强制 `client-fingerprint`（UCI 无值时补 `chrome`） |
| `vmess` | `vmess` | `server,port,uuid,alterId,cipher=security,udp,tls,skip-cert-verify,servername,alpn,network,client-fingerprint,ws-opts` | `network`∉`{tcp,ws}`（meow vmess 仅 tcp/ws）；`security`∉`{auto,zero,aes-128-gcm,chacha20-poly1305,none}` |
| `trojan` | `trojan` | `server,port,password,sni,skip-cert-verify,udp` | 任何 transport 字段（ws/grpc/http/quic）非空 → quarantine（meow trojan 仅裸 TCP+TLS） |
| `hysteria2` | `hysteria2` | `server,port|ports,password,sni,skip-cert-verify,udp:true,up,down,obfs:{type:salamander,password},hop-interval,fingerprint,fast-open,alpn` | `ports` 无法解析为合法端口集；`port` 与 `ports` 均缺 |
| `anytls` | `anytls` | `server,port,password,sni,skip-cert-verify,udp` | — |
| `snell` | `snell` | `server,port,psk,version,udp,reuse,obfs-opts{mode:http|tls,host}`（v6 才发 `mode`） | `version`∉`{3,4,5,6}`；`obfs` 非 http/tls |
| `socks` | `socks5` | `server,port,username,password,tls,udp` | `socks_version=4` |
| `http` | `http` | `server,port,username,password,tls(=https flag),sni` | — |
| `hysteria`(v1) `tuic` `wireguard` `ssh` `shadowtls` `shadowsocksr` `trusttunnel` | — | — | 恒 quarantine（不在 full 契约/不支持） |
| `urltest` `selector` `direct` `block` `dns` | — | 伪节点不物化 | — |

字段细节：
- `tls_insecure`→`skip-cert-verify`；`tls_sni`/`servername`→`servername`/`sni`（各协议键名见上表）。
- `utls`→`client-fingerprint`，合法值 `{chrome,firefox,safari,ios,android,edge,random,randomized}`；非法值 quarantine。
- `encryption`（vless）：`none`|`mlkem768x25519plus.*` 原样透传；空不发。
- `alpn` UCI 逗号串 → YAML 数组。
- 必填缺失（如 `uuid`/`psk`/`password`）→ quarantine。

### 4.5 组 → `proxy-groups`

```jsonc
// urltest 节点 →
{ "name": "main-out", "type": "url-test",
  "proxies": ["cfg-<a>-out", "cfg-<b>-out"],
  "url": "http://www.gstatic.com/generate_204",
  "interval": <check_interval 秒, 默认300>,
  "tolerance": <tolerance_ms, 默认50>, "lazy": true }
```

- `selector` 节点 → `type: "select"`；`url`/`interval`/`tolerance`/`lazy` 映射同上。
- 组成员递归展开 selector/urltest；被 quarantine 成员剔除并 warn。
- **GLOBAL 组**：`mode: rule` 时 meow 自动建 `GLOBAL`，勿显式发。

### 4.6 不支持节点 quarantine

- 跳过条件：未知 type、必填缺、非法枚举值、feature-gated 字段（见 §4.4 表）。
- 动作：`stderr` warn 一行 + 累积写 `/var/run/homeproxy/unsupported-nodes.json`：`[{"name":"<uci name>","type":"..","reason":".."}]`。
- `main_node`/`main_udp_node` 命中 quarantine → warn + 回退 `direct`（沿用现语义）。
- 该文件供 CLI `homeproxy nodes` 与 API 展示。

### 4.7 `rule-providers`（file 型）

```jsonc
"rule-providers": {
  "china-domain": { "type":"file", "behavior":"domain", "format":"text",
                    "path":"providers/china_list.txt" },
  "gfw-domain":   { "type":"file", "behavior":"domain", "format":"text",
                    "path":"providers/gfw_list.txt" },
  "direct-domain":{ "type":"file", "behavior":"domain", "format":"text",
                    "path":"providers/direct_list.txt" },   // 仅 direct_list 非空时
  "proxy-domain": { "type":"file", "behavior":"domain", "format":"text",
                    "path":"providers/proxy_list.txt" },    // 仅 proxy_list 非空时
  "direct-ip":    { "type":"file", "behavior":"ipcidr","format":"text",
                    "path":"providers/direct_ip.txt" },     // 仅 custom 模式需要
  "proxy-ip":     { ... }                                    // 同上
}
```

- init `start` 前先 `sync_rule_files()`：`cp -f /etc/homeproxy/resources/{china_list,gfw_list,direct_list,proxy_list,china_ip4,china_ip6}.txt /var/run/homeproxy/providers/`（仅复制当前 mode 实际引用者；删多余文件）。相对路径天然落入 config 父目录 `/var/run/homeproxy`，safe-path 检查通过。
- `wan_domain_list`/`wan_ip_list` 属 dnsmasq/防火墙侧，不进 rule-providers。

### 4.8 五种 `routing_mode` 的精确 `rules:` 文本

记 `DU` = `main_udp_node` 为独立节点/urltest（`"same"`/`"nil"` 时 DU 缺省）→ 条件行 `NETWORK,udp,main-udp-out`。
记 `DL` = direct_list 非空、`PL` = proxy_list 非空。

**`bypass_mainland_china`：**
```yaml
rules:
  - RULE-SET,direct-domain,DIRECT          # 仅 DL
  - RULE-SET,china-domain,DIRECT           # 域名级 CN 放行（sniff/DNS 反查命中）
  - NETWORK,udp,main-udp-out               # 仅 DU
  - MATCH,main-out
```

**`proxy_mainland_china`：**
```yaml
rules:
  - RULE-SET,direct-domain,DIRECT          # 仅 DL
  - NETWORK,udp,main-udp-out               # 仅 DU
  - MATCH,main-out
```

**`gfwlist`：**
```yaml
rules:
  - RULE-SET,direct-domain,DIRECT          # 仅 DL
  - RULE-SET,gfw-domain,main-out           # 域名级兜底（IP 未入 gfw ipset 时仍走代理）
  - NETWORK,udp,main-udp-out               # 仅 DU
  - MATCH,main-out
```

**`global`：**
```yaml
rules:
  - RULE-SET,direct-domain,DIRECT          # 仅 DL（"始终直连"白名单仍生效）
  - NETWORK,udp,main-udp-out               # 仅 DU
  - MATCH,main-out
```

**`custom`：**
按 §4.9 翻译 `routing_rule` 段，末行 `MATCH,<default_outbound>`。

注：`china-domain`/`gfw-domain` 域名规则能命中是因为 `enhanced-mode: redir-host` 使 snooping 反查表把 dst-IP 还原为域名；IP 字面量流量（无 DNS 反查）仍按 MATCH 兜底。

### 4.9 `custom` 模式：`routing_rule` 段 → meow 规则字符串

| UCI 字段 | meow 规则 | 不支持/降级 |
|---|---|---|
| `domain` | `DOMAIN,<v>` | — |
| `domain_suffix` | `DOMAIN-SUFFIX,<v>` | — |
| `domain_keyword` | `DOMAIN-KEYWORD,<v>` | — |
| `domain_regex` | `DOMAIN-REGEX,<v>` | — |
| `geosite` | `GEOSITE,<v>` | 无 geodata 文件 → 生成期 quarantine warn（不发 geoip/geosite data） |
| `ip_cidr` | `IP-CIDR,<v>,no-resolve` | — |
| `source_ip_cidr` | `SRC-IP-CIDR,<v>` | — |
| `port`/`port_range`（目的） | `DST-PORT,<v>` | — |
| `source_port*` | `SRC-PORT,<v>` | — |
| `network` tcp/udp | `NETWORK,<v>` | — |
| `rule_set`（自定义 `ruleset` 段） | `RULE-SET,<name>` | name 须匹配 §4.7 生成的 provider |
| `action=route` + `outbound` | 目标=outbound tag | outbound 指向 quarantine 节点 → warn + DIRECT |
| `action=block` | `REJECT` | — |
| `action=resolve` | — | **不支持**：warn 并跳过该条（meow 无 DNS-only 路由动作） |
| `invert`/`rule_set_ip_cidr_match_source` 等 sing-box 专有 | — | warn + 丢弃该修饰 |

复合条件（同段多字段）→ `AND,((cond1),(cond2))` meow 逻辑规则；`NOT`/`OR` 仅出现在显式嵌套结构时翻译，否则 quarantine warn。

---

## 5. U4 — 服务端配置生成（`generate_server.lua` → `meow-s.yaml`）

仅当存在 `enabled=1` 且 `type=shadowsocks` 的 `server` 段才生成并启动服务端实例。

```jsonc
{
  "mode": "rule",
  "log-level": "<同客户端映射>",
  "ipv6": <ipv6_support>,
  "routing-mark": 100,               // 服务端出站=DIRECT socket，打 self_mark（advisory）
  "listeners": [
    { "name": "cfg-<md5>-in",
      "type": "shadowsocks",
      "listen": "::",
      "port": <port>,
      "cipher": "<shadowsocks_encrypt_method>",
      "password": "<password>",
      "udp": true,                    // SS listener udp 默认 true，显式发
      "simple-obfs": { "enable": true, "mode": "http|tls" }  // hysteria_obfs → simple-obfs
    }
  ],
  "rules": [ "MATCH,DIRECT" ]
}
```

- `cipher` 合法集：`aes-128-gcm|aes-256-gcm|chacha20-ietf-poly1305|xchacha20-ietf-poly1305|2022-blake3-aes-128-gcm|2022-blake3-aes-256-gcm|2022-blake3-chacha20-poly1305`（非法→跳过该段+warn）。
- 非 shadowsocks 的 server 段（hysteria/trojan/tuic 等）：**全部 skip+warn**，记入 `unsupported-nodes.json`（`role:"server"`）。
- 无 external-controller（避免与客户端实例抢 19290）。
- `dns:`：`{ "enable": true, "nameserver": ["udp://<wan_dns>"] }`（不发 `listen`；resolver 用于 SS 目标域名解析，wan_dns=系统 resolv.conf 上游）。
- 校验 `meow -t -f meow-s.yaml`；多 server 段 → 多个 `listeners:` 项，`port` 冲突 → 后者 skip+warn。

---

## 6. U5 — 防火墙与流量接管（`firewall.sh`）

### 6.1 总原则

- 规则全部由本脚本安装/清理；meow 配置任何 listener 均 `firewall:false`（D9/§0.3）。
- 保持现有链结构命名（`homeproxy_*`）与 `emit_steering` 顺序：
  `self_mark → wan_proxy → local → lan_global → wan_direct → routing → gaming → catch-all(port-filtered)`。
- `self_mark` 用 **精确 mark 匹配**（`-m mark --mark <v>`），保持"不得 mask"注释。

### 6.2 marks 与策略路由（仅 v4）

```sh
# UDP TPROXY 必备（redirect_tproxy / tproxy 臂开启时）
ip rule add fwmark <tproxy_mark=101> table <table_mark=100> pref 100
ip route add local 0.0.0.0/0 dev lo table <table_mark=100>
# v6 不加任何 ip rule / local 路由（无 v6 UDP TPROXY）
```

`routing-mark: <self_mark>` 发进 meow 配置（D9），防火墙不再为 self_mark 建 OUTPUT 链。

### 6.3 meow listeners（生成进 meow-c.yaml）

```jsonc
"listeners": [
  { "name": "hp-tproxy",
    "type": "tproxy",
    "listen": "0.0.0.0",            // 必须 IPv4 非 loopback（REDIRECT/TPROXY 送达）
    "port": 5331,
    "firewall": false,               // 强制：外部拥有防火墙
    "udp": <udp_tproxy ? true : false>,   // tproxy 臂开启且存在 UDP 需求时
    "udp-timeout": 60
  },
  // 仅 ipv6_support=1 时追加第二个：
  { "name": "hp-tproxy6",
    "type": "tproxy",
    "listen": "::",
    "port": 5334,                    // infra.v6_port
    "firewall": false,
    "udp": false                     // v0.24.0：v6 UDP TPROXY 不支持
  }
]
```

`udp:true` 的判定（与现逻辑一致）：`main_udp_node != "nil"` 或 `routing_mode=="custom"`，且 proxy_mode 含 tproxy 臂。

### 6.4 proxy_mode → 接管臂（新语义）

| proxy_mode | TCP 臂 | UDP 臂 |
|---|---|---|
| `redirect` | nat PREROUTING `REDIRECT --to-ports 5331`（tcp） | 无 |
| `tproxy` | 无 | mangle PREROUTING `TPROXY --on-ip 0.0.0.0 --on-port 5331 --tproxy-mark 101/0xffffffff`（udp） |
| `redirect_tproxy` | TCP 臂同上 | UDP 臂同上 |

- **不再有 OUTPUT 链**（nat OUTPUT / mangle OUTPUT / `PREROUTING -i lo` re-entry 全部删除；D7）。
- ipset 成员：保留现有 `homeproxy_{wan_direct,wan_proxy,gfw,china_ip4,china_ip6,local,gaming}_*`；新增 `homeproxy_direct_domain4/6`、`homeproxy_proxy_domain4/6` 的填充仍由 dnsmasq `ipset=/` 行完成（§7）。
- `routing_port=common|all` 与 `gaming_ports` 过滤逻辑不变。
- QUIC 兜底：`bypass_mainland_china`/`gfwlist` 且 UDP 臂开启时保留 `udp dport {80,443} DROP`（mangle 链内，仅 v4；v6 UDP 本就不接管，不投该规则）。

### 6.5 IPv6 矩阵

| | IPv4 | IPv6 |
|---|---|---|
| TCP | nat REDIRECT→`redirect_port` | nat REDIRECT→`v6_port`（`ip6tables`，链结构镜像 v4） |
| UDP | mangle TPROXY→`redirect_port` mark 101 | **不接管，全直连**（含 QUIC；v6 无 DROP 规则） |
| DNS 劫持 | nat `REDIRECT --to-ports 53`→dnsmasq（`dns_redirect=1`） | 同左（`ip6tables`，沿用现状） |
| ipset | `homeproxy_*4` | `homeproxy_*6` |

`ipv6_support=0` → 不发 `hp-tproxy6` listener，不装任何 ip6tables 接管规则，`ipv6:false` 进 meow 配置。

### 6.6 清理顺序（stop/reload）

1. `iptables/ip6tables -t nat|mangle` 删 `homeproxy_*` 链跳转与链本体（flush→delete，先 PREROUTING 跳点后链）。
2. `ipset destroy homeproxy_*`（best-effort）。
3. `ip rule del fwmark 101 table 100`（幂等 drain）；`ip route flush table 100`。
4. `ip link del <legacy-tun-name>`（若存在）。
5. 移除 dnsmasq 生成 conf 段并 SIGHUP dnsmasq（若曾写入）。
6. 删 `meow-c.yaml`/`meow-s.yaml`/`unsupported-nodes.json`（保留 log）。

---

## 7. U6 — DNS 架构

### 7.1 拓扑（保持 dnsmasq 前置）

```
LAN client → dnsmasq :53
   ├─ 本地域名/静态 lease → 本地应答
   ├─ 分流命中（server=/domain/…） → meow DNS 127.0.0.1:5333  或  直连上游
   └─ 默认 → meow DNS 127.0.0.1:5333（bypass/global/custom）或 china 上游（gfw/proxy_mainland 未命中项）
meow DNS → 按 nameserver-policy 选 udp://china_dns（直连）或 udp://dns_server#main-out（经代理）
```

dnsmasq 继续承担：**按域名分流**与 **ipset 填充**（`ipset=/<domain>/<set4>,<set6>`），这是 meow 替代不了的（meow 不操作 ipset）。

### 7.2 meow `dns:` 块（进 meow-c.yaml）

```jsonc
"dns": {
  "enable": true,
  "listen": "127.0.0.1:5333",
  "enhanced-mode": "redir-host",     // 真实 IP + snooping 反查表 → 域名规则可命中
  "default-nameserver": ["udp://<wan_dns>"],        // bootstrap（DoH host / 节点域名初解）
  "proxy-server-nameserver": ["udp://<wan_dns>"],   // 节点 server 域名恒直连解析，防环
  "nameserver": [ <按 mode，见 §7.3 > ],
  "nameserver-policy": { <按 mode，见 §7.3 > }
}
```

`use-hosts`/`fake-ip*`/`fallback-filter` 不发（dnsmasq 已处理本地名；fake-ip 会打乱 ipset 填充，禁用）。

### 7.3 各 mode 的 nameserver 与 dnsmasq 生成项

记 `CD=china_dns_server`（默认 `223.5.5.5`），`RS=dns_server`（默认 `8.8.8.8`）。`https://`/`tls://` 型 `dns_server` **降级**为 `udp://<host>#main-out` 并 warn（`#` 仅 plain 形式有效；`tls://x#p` 的 `#` 会被当 SNI）。

| mode | meow `nameserver` | meow `nameserver-policy` | dnsmasq conf 追加 |
|---|---|---|---|
| bypass_mainland_china | `["udp://<RS>#main-out"]` | `"rule-set:china-domain":"udp://<CD>"`; `"rule-set:direct-domain":"udp://<CD>"`(DL) | `server=127.0.0.1#5333`（全局转发）；`ipset=` china_ip4/6 已含 |
| proxy_mainland_china | `["udp://<RS>#main-out"]` | `"rule-set:direct-domain":"udp://<CD>"`(DL) | 仅 `server=/domain(china_list)/127.0.0.1#5333`；默认走 resolv.conf 直连 |
| gfwlist | `["udp://<RS>#main-out"]` | 同左 | `server=/domain(gfw_list)/127.0.0.1#5333` + `ipset=/…/homeproxy_gfw4,homeproxy_gfw6` |
| global | `["udp://<RS>#main-out"]` | `"rule-set:direct-domain":"udp://<CD>"`(DL) | `server=127.0.0.1#5333` |
| custom | `dns_rule`/`dns_server` 段翻译（§7.4） | 同左 | 按 UCI `dns_rule` 生成 |

`china_dns_server` 出现在 `proxy-server-nameserver`/`default-nameserver` 时用 `wan_dns`（系统上游，恒直连），不用 CD（CD 本身可能也是需要解析的域名时由 default-nameserver 兜底，防环同 meow 语义）。

### 7.4 `custom` DNS

- `dns_server` 段 → nameserver 池：`udp://<addr>`（或 `<addr>` 裸 IP）；`detour` 字段 → `#<outbound-tag>` 后缀。
- `dns_rule` 段 → `nameserver-policy`：domain/suffix/keyword/regex → 同名 key；`rule_set` → `rule-set:<provider>`；`server` → 池名。
- sing-box 专有（`rule_set_ip_cidr*`、`strategy`、`client_subnet`、reverse）→ warn-skip。
- `default_server`/`default_outbound_dns` → `nameserver` 末位兜底。

### 7.5 DNS 劫持开关

`infra.dns_redirect=1`（默认）→ 防火墙 nat PREROUTING `:53 REDIRECT` 到 dnsmasq（**不**直接到 meow；保持 dnsmasq 前置分流语义）。`=0` → 不装劫持，dnsmasq conf 也不写 `server=`/`ipset=` 追加（用户自管）。

---

## 8. U7 — 生命周期 / CLI / API

### 8.1 init.d/procd

```
start:
  1. migrate_config.lua（幂等）
  2. uci load + sync_rule_files()（§4.7）
  3. generate_client.lua → meow-c.yaml.tmp → mv
  4. meow -t -f meow-c.yaml ；失败→ materialize=0 retry 一次；再失败→abort（保留旧 yaml）
  5. 有 server 段 → generate_server.lua → meow-s.yaml → meow -t
  6. 装策略路由（§6.2）+ firewall apply
  7. procd instance meow-c: respawn, command "/usr/bin/meow -f /var/run/homeproxy/meow-c.yaml --no-external-plugins",
     env: HP_MATERIALIZE_ALL_NODES（透传）, stdout/stderr → meow-c.log
  8. （可选）procd instance meow-s 同理 → meow-s.log
stop:
  procd kill → firewall cleanup（§6.6）→ dnsmasq 复原 → 删生成物 → legacy-tun 清理
reload: 等价 restart（生成物已原子替换）
```

- `$PROG`=`${HP_MEOW_BIN:-/usr/bin/meow}`；procd `respawn` 参数沿用现状（`3600 5 5`）。
- `firewall include`（`firewall_include.sh`）保持：fw3 reload 时若服务在跑则重挂规则。

### 8.2 `homeproxy generate`

- 生成 + `meow -t` 校验；`HP_MATERIALIZE_ALL_NODES` env 保留（默认 1）。
- 输出 quarantine 汇总（unsupported-nodes.json 条数）。

### 8.3 CLI（`root/usr/bin/homeproxy`）

| 命令 | 变化 |
|---|---|
| `status` | `pgrep -f "meow -f /var/run/homeproxy/meow-"`；version=`meow --version` 或 `/version` API |
| `generate` | 目标文件 meow-*.yaml |
| `proxy-mode` | 合法值 `{redirect,tproxy,redirect_tproxy}` |
| `nodes`/`add`/`set`/`main-node`/`log` | 读 unsupported-nodes.json 标注 quarantine；log 指向 meow-*.log |
| `check` | `meow -t -f` |
| 其它 | 不变 |

### 8.4 进程/版本探测统一表

| 用途 | 命令 |
|---|---|
| 客户端存活 | `pgrep -f "meow -f /var/run/homeproxy/meow-c.yaml"` |
| 服务端存活 | `pgrep -f "meow -f /var/run/homeproxy/meow-s.yaml"` |
| 版本 | `meow --version`（首行）或 `GET 127.0.0.1:19290/version` → `.version` |
| 特性缓存签名 | `meow --version` 完整输出 + bin 路径 mtime |

### 8.5 CGI API（`root/etc/homeproxy/web/cgi-bin/api`）

| 端点 | 语义（对外不变） | 内部实现 |
|---|---|---|
| `GET /status` | `{running,version,main_node,routing_mode,proxy_mode,lan_proxy_mode}` | running=pgrep；version=`meow --version` 解析；proxy_mode 返回**新词表值** |
| `GET /settings` | UCI 全量回读 | 已删选项（tproxy_port/tun_*）不再出现 |
| `GET /ping_node?name=<n>` | `{delay:<ms>}` / `{error}` | `GET /proxies/cfg-<md5(n)>-out/delay?url=<u>&timeout=5000`；404→`{error:"node not found"}`；504→`{error:"timeout"}`；503→`{error:"unreachable"}` |
| `GET /ping_all` | 逐节点延迟表 | 批量调 delay；`main-out`/组名也可测 |
| POST 类（set 等） | 不变 | 经 uci 改写 + restart |

URL 编码：tag 为 ASCII，无需转义；`url`/`timeout` 参数校验正整数与非空（meow 400 on malformed）。

### 8.6 日志与锁

- procd stdout/stderr → `meow-c.log`/`meow-s.log`；`clean_log.sh` 轮名单更新。
- `homeproxy.log` 保留给 Lua/shell 自身的 logwarn。
- `/var/run/homeproxy/homeproxy.lock`（flock）沿用，覆盖 generate+restart 临界区。

---

## 9. U8 — 订阅、节点导入与特性探测

### 9.1 `update_subscriptions.lua` / `subscription_parser.lua`

- 解析器语义不变（ss/trojan/vless/vmess/hysteria2/anytls/snell/socks/http 分享链接 + SIP008）。
- 新增：解析产物先过 §4.4 映射表的**合法性预检**（同一份 Lua 校验函数供生成器与订阅复用），不合格节点仍写入 UCI 但标记 `hp_quarantine=1` 或直接跳过写 UCI（实现选后者，记 unsupported-nodes.json 于下次 generate 生成）。
- `filter_nodes` blacklist/whitelist 语义不变；拉取失败/截断 → 保持现有"不删旧节点"保护。

### 9.2 `add_nodes.lua`

- 手动 import 走同一校验；不支持的 type/参数 → 明确回显原因，不落 UCI。

### 9.3 特性探测（`meow-features.json`）

```sh
# 签名 = sha256(bin_path + meow --version 输出)
# 各特性用最小探针 YAML + `meow -t` 判定（与现 sing-box 探针同构）
features = {
  with_quic      = probe(hysteria2 最小 proxies 块),
  with_utls      = probe(vless + client-fingerprint),
  with_hysteria  = false,            # 恒 false：meow 无 hysteria v1
  with_ss_listener = probe(listeners:[type:shadowsocks]),
  snell/anytls/trojan/vmess/ss = probe(对应最小 proxies 块)
}
```

- 缓存路径 `/var/run/homeproxy/meow-features.json`；签名不匹配重探。
- 订阅过滤：v1 hysteria/tuic/wireguard/…节点直接跳过（§4.4 quarantine 表同标准）。

### 9.4 `update_via_proxy`（D15）

- `=1`：curl 加 `-x http://127.0.0.1:5330`；wget 设 `http_proxy=http://127.0.0.1:5330 https_proxy=…`；**不再**依赖 OUTPUT 透明接管。
- 连通性自检（google 204）同理显式走 mixed 口。

### 9.5 `update_resources.sh`

- `pgrep -f "sing-box run"` → `pgrep -f "meow -f /var/run/homeproxy/meow-"`；下载后 restart 逻辑不变；资源文件落 `/etc/homeproxy/resources/`（由 init `sync_rule_files` 复制进 RUN_DIR providers/）。

---

## 10. 旧 → 新 总映射表

| 类别 | sing-box 现状 | meow 目标 |
|---|---|---|
| 二进制 | `/usr/bin/sing-box` | `/usr/bin/meow` 或 `/data/other_vol/bin/meow` |
| 客户端配置 | `/var/run/homeproxy/sing-box-c.json` | `/var/run/homeproxy/meow-c.yaml`（JSON 文本） |
| 服务端配置 | `sing-box-s.json` | `meow-s.yaml` |
| 日志 | `sing-box-c/s.log` | `meow-c/s.log` |
| 校验 | `sing-box check --config` | `meow -t -f` |
| 运行 | `sing-box run --config` | `meow -f` |
| 进程探测 | `pgrep -f "sing-box run"` | `pgrep -f "meow -f /var/run/homeproxy/meow-"` |
| 特性缓存 | `singbox-features.json` | `meow-features.json` |
| 透明 TCP | `redirect`/`tproxy` inbound | `listeners:[tproxy]` + nat REDIRECT |
| 透明 UDP | `tproxy` inbound | `listeners:[tproxy] udp:true` + mangle TPROXY（v4 only） |
| TUN | `tun` inbound `singtun0` | **移除** |
| ext API | `clash_api` | `external-controller`（同端口/端点形状） |
| DNS | sing-box dns 模块 | `dns:` + dnsmasq 前置不变 |
| 域名集 | sing-box rule_set（本地文件） | `rule-providers` file/text/domain |
| outbound tag | `main-out`/`cfg-*-out` | 同名 proxies/groups |
| env 变量 | `HP_SINGBOX` | `HP_MEOW`/`HP_MEOW_BIN`/`HP_MEOW_SHA256` |

---

## 11. 验收标准（实施完成后逐条可验证）

- AC-1：`cargo zigbuild --target aarch64-unknown-linux-musl --features "full listener-shadowsocks"` 产出 `meow`；`meow --version` 含 `0.24.0`。
- AC-2：`homeproxy generate` 产出合法 `meow-c.yaml`；`meow -t` 返回 0；文件为有效 JSON。
- AC-3：五种 `routing_mode` × 三种 `proxy_mode` 组合下，`iptables-save`/`ip6tables-save` 规则与 §6 文本一致；UDP 臂仅在 v4 mangle；无 OUTPUT 链。
- AC-4：v4 LAN TCP 流量按 ipset 分流到 5331（CN→直连，非 CN→代理）；v4 UDP 在 tproxy 臂开启时经 mark 101 → lo → 5331。
- AC-5：`ipv6_support=1` 时 v6 TCP 重定向到 5334；v6 UDP（含 QUIC）直连、`iptables -L` 无 v6 UDP 规则。
- AC-6：dnsmasq 正常启动，按 mode 生成 `server=`/`ipset=` 行；`nslookup google.com @127.0.0.1 -p=5333` 经 meow 返回真实 IP；CN 域名走 china_dns。
- AC-7：`curl -x http://127.0.0.1:5330 https://www.gstatic.com/generate_204` 返回 204（代理通）；`GET /proxies/cfg-<x>-out/delay?url=…&timeout=5000` 返回 `{"delay":…}`。
- AC-8：旧配置升级一次后 `uci show homeproxy` 无 `tproxy_port`/`tun_*`/`proxy_mode` 旧值；`pgrep` 无 `sing-box`；`ip link` 无 `singtun0`。
- AC-9：把 main_node 指向 quarantine 节点 → generate warn + 回退 direct + `unsupported-nodes.json` 有记录；`-t` 通过。
- AC-10：stop 后 `iptables-save` 无 `homeproxy_` 链、`ipset list` 无 `homeproxy_*`、`ip rule` 无 101 表项、`ls /var/run/homeproxy/meow-*.yaml` 不存在。
- AC-11：install.sh 在无 meow 或版本非 0.24 时触发下载→校验→替换→探活；探活失败回滚旧二进制。
- AC-12：`HP_MATERIALIZE_ALL_NODES=0` 与 `=1` 两条生成路径均通过 `-t`；API `/ping_all` 在 `=1` 下覆盖全部 cfg-*-out。
- AC-13：server 段（ss）启动后 `meow-s.yaml` 通过 `-t`，`ss-local` 测试客户端可连通。
- AC-14：订阅更新写入 UCI；hysteria v1/tuic 链接跳过并记录原因；`update_via_proxy=1` 时订阅请求走 5330。
- AC-15：`strict` 非开启时单个坏 rule/provider 不阻塞启动（warn）；生成器自身保证不产出非法字段。

## 12. 未决问题（实施前需确认）

- Q1：`infra.v6_port` 命名与默认值 5334 是否与前端偏好一致（备选 `redirect_port_v6`）。
- Q2：路由器自身流量取消 OUTPUT 接管后，是否存在依赖"路由器 egress 透明代理"的用户场景（opkg/ntpd 走代理）——若有，需加回 OUTPUT+bypass-ipset 方案并接受 §0.3 所述回环风险。
- Q3：是否提供上游 OpenWrt `+meow` 包依赖（stock MiWiFi 无源，目前 install.sh 分发制）。
- Q4：meow `--version` 输出确切格式（`meow 0.24.0` 假定自 clap `version=env!("MEOW_VERSION")`；实施时确认首行解析式）。
- Q5：vless `encryption` 值集是否全量透传（`mlkem768x25519plus` 系列命名随版本漂移）。
- Q6：hysteria2 `ports` 端口跳跃语法（`20000-30000,40000` 混合）与 UCI 现格式对齐细节。
- Q7：`sniffer` 端口范围是否需按 routing_port 收敛（v0.24.0 默认行为待确认，不影响功能正确性，仅性能）。
- Q8：server 模式 `dns.enable=true` 无 `listen` 是否会被 warn（预计合法；若报错则改发 `listen: 127.0.0.1:0` 或 stub resolver）。

## 13. 实施勘误（v0.24.0 二进制 + 源码实测，覆盖上文冲突表述）

1. §4.2 `sniffer`：必须发完整 `sniff` map——`{enable:true}` 单独存在时 v0.24.0 `meow -t` 硬错（meow-config lib.rs）。实现：`sniffer={enable=true,sniff={TLS={ports={443}},HTTP={ports={80}}}}`。
2. §4.3 tag 口径：实际为 `cfg-<UCI段名>-out`（段名本身即 md5 标签），非 `md5(sect)前8`。
3. §4.4 字段集修正：vmess cipher 集删 `zero`（meow ADR-0002 硬拒）；snell `version` 集为 `{3,4,5,6}`（v6 实测通过；v6+obfs-opts 非法，生成器 quarantine）。
4. §5 cipher 集删 `xchacha20-ietf-poly1305`：`-t` 不验 cipher 但 runtime bind 拒绝（shadowsocks-crypto `v1-aead-extra` 未编）→ 走 quarantine，与出站集对齐。
5. §3.4 `proxy_mode` 归一化：旧值 `tproxy` 的改写以 `legacy_infra`（`tproxy_port`/`tun_*` 存在）为门——否则新词表的合法 `tproxy` 每次 migrate 会被误改。
6. `log-level` 合法集 `{debug,info,warning,warn,error,silent}` 无 `trace`——`trace`→`debug`。
7. `unsupported-nodes.json` 三写方分区 merge：`role="client"`/`role="server"`/`source="subscription"`，各写方只重写自己分区。
8. 策略路由（`ip rule fwmark 101`+table 100 local route）单 owner = firewall.sh（fw3 reload 不经 init.d）；init.d 仅 stop 兜底 drain。
9. server 零-listener（全 quarantine）契约：生成器 `os.exit(2)`，init.d/CLI 据此"跳过 meow-s"而非中止。
10. `legacy-tun-name` 文件格式：`"<name> <tun_mark>"` 双字段（单字段旧文件兼容，mark 兜底 102）。
11. 上游 release 二进制不含 `listener-shadowsocks` feature（不在 `full` 内）——SS 服务端须用契约构建产物（`full listener-shadowsocks`），经 `file://`+本地编译部署。
12. Q4 已确认：`meow --version` → `meow 0.24.0` 单行；Q8 已确认：dns.enable 无 listen 合法（-t rc=0）。
