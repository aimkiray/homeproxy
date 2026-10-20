# HomeProxy(meow 内核)断网自愈 / 恢复加固实施规范(候选 B)

- **状态**:候选实施规范(未实施;实施前需评审签字)
- **依据前端**:homeproxy_mi @ `meow-kernel` 分支现状(`meow-c` 监听 mixed 5330 / tproxy 5331 / DNS 5333 / v6 5334 / ext-ctl `127.0.0.1:19290`;`meow-s` 为可选 ss server)
- **依据审计**:`docs/RECOVERY.md` §"已知缺口(审计 RR1/RR2)"列出的 G0/G1/G2/G3/G4/G5/G9/G10
- **目标环境**:Xiaomi/MiWiFi stock router(OpenWrt 18.06 派生,kernel 5.4,BusyBox/ash,Lua 5.1 + `uci` + `luci.json`,`iptables`/`ip6tables`/`ipset`/`xt_TPROXY`;**无** nftables、fw4、ucode、jq、jsonfilter;`pgrep`/`flock`/`timeout` 等 applet **不保证存在**,一律需 fallback)
- **总目标**:把 "meow 死后 = LAN 持久断网" 降级为 "meow 死后 = 自动回退直连",并把手动恢复路径(Web/CLI/SSH/安装回滚)逐一做实。

> 术语:**接管状态(takeover)** = firewall.active 存在 / `homeproxy_*` 链在跳点上 / dnsmasq conf 已写入三者之一或以上;**降级(degrade)** = 撤回接管状态但不碰 UCI 配置、不杀 meow 进程的止血动作(§2.4)。

---

## 1. 硬约束与既有契约(全部改动不得违反)

1. Shell 一律 POSIX/ash + `set -u`;禁止使用 bash 扩展;BusyBox applet 缺失必须 fallback(`pgrep`→`ps w | grep`、`flock`→`mkdir` 锁、可参考 `install.sh` `proc_running()` 与 `boot_restore.sh` 锁模式)。
2. Lua 仅 5.1 语法;UCI 操作复用 `homeproxy.lua`(`hp.*`);不新增外部依赖。
3. 禁止 nft/nftables/fw4/ucode/jq;禁止部署期 `sed` 补丁(env.sh 机制保持不变)。
4. 所有新文件头保留 `SPDX-License-Identifier: GPL-2.0-only`。
5. **既有契约名一律不变**:
   - 二进制:`PROG="${HP_MEOW_BIN:-/usr/bin/meow}"`(MiWiFi 上 env.sh 指向 `/data/other_vol/bin/meow`)。
   - 库目录:`HP_LUA_DIR="${HP_LIB_DIR:-/usr/lib/homeproxy}"`(MiWiFi:`/data/other_vol/homeproxy/lib`)。
   - `RUN_DIR=/var/run/homeproxy`(tmpfs,重启即失);`LOG_PATH=$RUN_DIR/homeproxy.log`。
   - `firewall.active` flag:`$RUN_DIR/firewall.active`,由 init.d `start` 在 `firewall.sh start` 成功后写入,唯一消费者是 `firewall_include.sh`(fw3 include,flag 不在则 `exit 0`)。
   - dnsmasq conf:`/tmp/dnsmasq.d/homeproxy_*.conf`(tmpfs;由 init.d `start` 写、`stop` 删 + `dnsmasq restart`)。
   - 进程探测:`pgrep -f "meow -f /var/run/homeproxy/meow-"`(缺 pgrep 时 `ps w | grep -q '[m]eow -f /var/run/homeproxy/meow-'`)。
   - crontab 标记注释:`#homeproxy_autosetup`(auto_update)已有;新增 `#homeproxy_watchdog`(§2)。
   - "预期运行 meow-c" 判定(三处现有实现必须保持同源):`routing_mode != "custom"` → `config.main_node != nil`;`routing_mode == "custom"` → `routing.default_outbound` 非空且 `!= "nil"`;或 `server` 段任一 `enabled=1`(后者仅意味 meow-s,不需要 meow-c)。现有三处:init.d L143-159、install.sh L496-507、firewall.sh L274-279。
   - 生成器 rc 约定:`generate_server.lua` 已用 `os.exit(2)` 表示"启用段全部 quarantine、不产 yaml 但不算失败"——本规范沿用"**rc=2 = 定义内的空跑/跳过**"语义(§6)。

---

## 2. G0 — meow 看门狗(自愈核心)

### 2.0 决策

**新增 cron 驱动的独立看门狗脚本 `scripts/watchdog.sh`(每分钟一次):仅在 "meow-c 预期运行 ∧ 接管状态真实存在" 时生效;连续失败先 `init.d restart` 一次,仍死则执行"降级"(先删 `firewall.active` → `firewall.sh stop` → 删 dnsmasq conf → `dnsmasq restart`),置 sticky 标记后停止自愈,等待人工 `homeproxy restart`。不做端到端节点探测、不做自动回切。**

### 2.1 新文件:`root/etc/homeproxy/scripts/watchdog.sh`

```sh
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# HomeProxy watchdog (MiWiFi port). Runs from cron every minute.
# Watches the meow client instance that LAN steering depends on; on
# persistent death it first tries one service restart, then degrades the
# box to direct-only (firewall teardown + dnsmasq restore) and stays out
# of the way until a human restarts the service.
# Usage: watchdog.sh [tick|degrade]
#   tick     one watchdog cycle (default; called by cron)
#   degrade  unconditional teardown right now (CLI firewall-stop backend)

set -u
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

RUN_DIR=/var/run/homeproxy
LOG_PATH=$RUN_DIR/homeproxy.log
STATE=$RUN_DIR/hp_watchdog.state        # "fails=N restarts=N"
DEGRADED=$RUN_DIR/hp_watchdog.degraded  # sticky marker
LOCK=/var/run/hp_watchdog.lock
API=http://127.0.0.1:19290              # meow external-controller (生成端写死)

FAILS_BEFORE_RESTART=2   # 连续 N 次探测失败 -> 服务级 restart 一次
FAILS_BEFORE_DEGRADE=3   # restart 后再连续 N 次失败 -> degrade

mkdir -p "$RUN_DIR" 2>/dev/null
log() { echo "$(date '+%H:%M:%S') [hp-watchdog] $*" >>"$LOG_PATH" 2>/dev/null; }
uci_get() { uci -q get "homeproxy.$1" 2>/dev/null; }

# --- env + firewall.sh 解析(G2 同款 fallback 链,见 §3.2)-----------------
[ -f /etc/homeproxy/env.sh ] && . /etc/homeproxy/env.sh || true
HP_LUA_DIR="${HP_LIB_DIR:-/usr/lib/homeproxy}"
resolve_fw() {
    for f in "$HP_LUA_DIR/firewall.sh" \
             /data/other_vol/homeproxy/lib/firewall.sh \
             /usr/lib/homeproxy/firewall.sh; do
        [ -f "$f" ] && { printf '%s\n' "$f"; return 0; }
    done
    return 1
}
```

#### 2.1.1 `degrade` 子命令(G4 的共用后端)

```sh
do_degrade() {
    # 顺序固定(§3.3):先撤 flag 再清规则——否则 fw3 include 可能在半清空
    # 状态上 reload,留下孤儿跳点。
    rm -f "$RUN_DIR/firewall.active"
    local fw
    if fw=$(resolve_fw); then
        local out
        out=$(sh "$fw" stop 2>&1)   # 不挂文件重定向:RUN_DIR 不可写也不能
        [ -n "$out" ] && printf '%s\n' "$out" >>"$LOG_PATH" 2>/dev/null   # 阻断 teardown(G1)
    else
        log "WARN: firewall.sh not found; skipped rule teardown."
    fi
    if ls /tmp/dnsmasq.d/homeproxy_*.conf >/dev/null 2>&1; then
        rm -f /tmp/dnsmasq.d/homeproxy_*.conf
        /etc/init.d/dnsmasq restart >/dev/null 2>&1
    fi
    : > "$DEGRADED"
    log "DEGRADED to direct-only (firewall.active removed, rules + dnsmasq confs cleared). Run 'homeproxy restart' to restore."
}
[ "${1:-tick}" = "degrade" ] && { do_degrade; exit 0; }
```

#### 2.1.2 门控(幂等性;不满足任一条件即 `exit 0`,不写状态文件)

```sh
[ "$(uci_get config.enabled)"   = "0" ] && exit 0          # G5 总开关
[ "$(uci_get infra.watchdog)"   = "0" ] && exit 0          # 看门狗 opt-out(默认 1)

# meow-c 预期判定(与 init.d/install.sh 同一公式)
routing_mode=$(uci_get config.routing_mode); routing_mode=${routing_mode:-bypass_mainland_china}
if [ "$routing_mode" = "custom" ]; then
    outbound_node=$(uci_get routing.default_outbound)
else
    outbound_node=$(uci_get config.main_node)
fi
outbound_node=${outbound_node:-nil}
[ "$outbound_node" = "nil" ] && { rm -f "$STATE"; exit 0; }  # meow-c 不该在跑

# sticky degraded:已降级状态下,只有人工 restart(flag 重新出现)才解除
if [ -f "$DEGRADED" ]; then
    [ -f "$RUN_DIR/firewall.active" ] && rm -f "$DEGRADED" || exit 0
fi

# 有接管事实才有降级对象(不误伤:dns_redirect=0 / lan_proxy_mode=disabled
# / 纯 server 部署时,meow-c 死了也不影响 LAN,看门狗全程静默)
lan_proxy_mode=$(uci_get control.lan_proxy_mode); lan_proxy_mode=${lan_proxy_mode:-disabled}
stakes=0
[ "$lan_proxy_mode" != "disabled" ] && [ -f "$RUN_DIR/firewall.active" ] && stakes=1
ls /tmp/dnsmasq.d/homeproxy_*.conf >/dev/null 2>&1 && stakes=1
[ "$stakes" = "0" ] && exit 0
```

> 注:`firewall.active` 在 `lan_proxy_mode=disabled` 时也会被 init.d 置上(server filter accepts 需要它过 fw3 reload),所以 stakes 判定必须**同时**看 lan_proxy_mode —— 只看 flag 会让纯 server/disabled 部署被看门狗"降级"掉 server accepts,违背"不误伤"。

#### 2.1.3 探测(双条件 AND;进程存在 ∧ 事件循环应答)

```sh
proc_running() {   # install.sh 同款 pgrep/ps 双 fallback
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -f "meow -f $RUN_DIR/meow-c.yaml" >/dev/null 2>&1
    else
        ps w 2>/dev/null | grep -q "[m]eow -f $RUN_DIR/meow-c.yaml"
    fi
}
api_alive() {
    command -v curl >/dev/null 2>&1 || return 0   # 无 curl 退化为纯进程探测
    curl -sf --max-time 3 "$API/version" >/dev/null 2>&1
}
```
- `proc_running` 覆盖"崩溃 + respawn 用尽";`api_alive` 覆盖"进程活着但事件循环挂死(listener 不响应)"——RECOVERY.md 死法表的第 1、2 行。
- **不**做经 5330 的端到端 204 探测:上游节点死 ≠ 内核死,把"换节点"场景误降级为直连会掩盖真实故障(见"不做的事"第 4 条;G10 的安装窗探测才有此语义)。

#### 2.1.4 自愈补充:规则被 fw3 冲掉但 meow 健康

```sh
# meow 活着且 flag 在,但 PREROUTING 上已没有 homeproxy 跳点(fw3 reload
# 而 include 未生效/被删)——当场重挂一次。失败不累计 fails。
if [ "$lan_proxy_mode" != "disabled" ] && [ -f "$RUN_DIR/firewall.active" ]; then
    iptables -t nat -S PREROUTING 2>/dev/null | grep -q ' -j homeproxy_' || {
        log "steering jumps missing while meow is alive -- re-applying firewall."
        fw=$(resolve_fw) && sh "$fw" start >>"$LOG_PATH" 2>&1
    }
fi
```

#### 2.1.5 状态机(tick)

```text
fails/restarts 从 $STATE 读入(缺省 0/0);文件是 tmpfs,重启自然清零。

探测 = proc_running && api_alive
├─ 通过 → fails=0; 保留 restarts; 写回 state; exit 0
└─ 失败 → fails++
    ├─ restarts==0 && fails>=FAILS_BEFORE_RESTART(2)
    │     → log; 执行一次服务级 restart; restarts=1; fails=0; 写回; exit 0
    │       (/etc/init.d/homeproxy 缺时回退
    │        /data/other_vol/homeproxy/init.d/homeproxy;
    │        `command -v timeout` 存在则 `timeout 120` 包裹防挂死 cron)
    └─ restarts>=1 && fails>=FAILS_BEFORE_DEGRADE(3)
          → do_degrade; rm -f $STATE; exit 0
    其余 → 写回 state; exit 0
```

时间线(1min tick,最坏):死亡 → ~2min debounce → restart(数十秒)→ ~3min 复探仍死 → **degrade,全程约 5-6min 回直连**。比 procd 只重试不接管(现状永不恢复)和"立即拆"(重启期误伤)都更稳。

#### 2.1.6 并发与防重入

复用 `boot_restore.sh` 的双模锁:`flock -n` 可用则 flock `/var/run/hp_watchdog.lock`,否则 `mkdir /var/run/hp_watchdog.lock.d` + `trap rmdir EXIT`。restart/degrade 在锁内执行,cron 分钟粒度 + 锁足以互斥。

### 2.2 cron 接线(init.d 管理,非 install.sh)

`start_service()` 在写 `#homeproxy_autosetup` 行附近(现 L238-240 块之后)追加,**无条件保证存在**(运行时门控在脚本内,改 `infra.watchdog=0` 无需重启即可静默):

```sh
if ! grep -q "#${CONF}_watchdog" /etc/crontabs/root 2>/dev/null; then
    echo "* * * * * [ -x $HP_DIR/scripts/watchdog.sh ] && $HP_DIR/scripts/watchdog.sh #${CONF}_watchdog" >> "/etc/crontabs/root"
    /etc/init.d/cron restart >/dev/null 2>&1
fi
```

`stop_service()` 里用与 autosetup 相同的 grep-门控 sed 删除 `#${CONF}_watchdog` 行(avoid 多余 cron restart)。`[ -x ... ]` 内联守卫使 MiWiFi 开机早期(`/etc/homeproxy` symlink 尚未由 boot_restore 重建)的那几次 tick 静默退出而非刷 cron 错误。

> 为什么不让 install.sh 管这行:标准包安装没有 install.sh 路径;init.d 写删与 autosetup 同构,且 stop 即摘除——"被停止的服务不应再被看门狗拉起"这一语义免费获得。

### 2.3 验收标准

- AC-G0-1:LAN 接管生效时(`firewall.active`+跳点均在),`killall -9 meow`(或等效让 meow-c 退出并使 procd respawn 耗尽)后 ≤ FAILS_BEFORE_RESTART 个 tick 日志出现 restart 记录;meow 恢复后 fails 清零、不再 degrade。
- AC-G0-2:构造 meow 不可恢复(如 `$PROG` 换成必崩的 stub 或 `-t` 恒失败的配置):看门狗在 restart 后 FAILS_BEFORE_DEGRADE 次失败内执行 degrade;执行后 `iptables-save|grep homeproxy_` 为空、`/tmp/dnsmasq.d/homeproxy_*.conf` 不存在、`firewall.active` 不存在、`$DEGRADED` 存在,LAN 客户端直连恢复。
- AC-G0-3:degraded 后手工 `homeproxy restart` → flag 重建 → 下一 tick 自动清 `$DEGRADED`,看门狗恢复监视。
- AC-G0-4(不误伤):`control.lan_proxy_mode=disabled` ∧ 无 dnsmasq conf 时杀掉 meow-c:看门狗每 tick 退出、**不**删 `firewall.active`、**不**动 `homeproxy_in` accepts;`infra.dns_redirect=0`(无 conf)且 lan_proxy≠disabled 时 degrade 仍清规则但不 restart dnsmasq(无 conf 可删)。
- AC-G0-5:`config.enabled=0` 或 `infra.watchdog=0` 时连续多次 tick 无任何日志/状态写入。
- AC-G0-6:`sh -n` 通过;`shellcheck`(若跑)无新告警;脚本在缺 `pgrep`/`flock`/`timeout` 的 busybox 下全路径可达(fallback 验证)。

### 2.4 风险

- **降级摘除 server accepts**:degrade 是全量 `firewall.sh stop`,co-resident 的 meow-s 监听口 INPUT accept 一并撤掉(进程仍活)。仅当"meow-c 预期 ∧ 有接管"才触发,纯 server 部署免疫;混合部署接受此 collateral——目标是恢复 LAN 出口,且 restart 后全量恢复。已在日志明示。
- **restart 风暴防护**:`init.d restart` 内部重跑 migrate+生成+`-t`,若上游配置损坏则反复失败——但 restarts 最多 1 次/episodes,不会循环重启。
- **api 探针瞬态误判**:meow 大配置加载/高危 GC 时 3s 超时可能偶发失败——`fails>=2` debounce 吸收;restart 后 fails 清零重新计。
- **`/etc/crontabs/root` 写入竞态**:与 autosetup 共用 sed/grep 模式,最坏丢一行(cron 文件镜像由 MiWiFi 管)。

---

## 3. G1 + G2 — init.d `stop_service` teardown 双保险 + 顺序修正

### 3.0 决策

**`stop_service` 中 (a) `rm -f firewall.active` 提前到一切清理之前(关 include 竞态窗口);(b) `firewall.sh stop` 改为命令替换捕获输出,彻底摆脱 `2>>$LOG_PATH` 失败即跳过 teardown 的隐患;(c) `firewall.sh` 路径加 `/data/other_vol` → `/usr/lib` fallback 链,env.sh 失效时仍能找到脚本。**

### 3.1 问题定位

- init.d L389 已加 `mkdir -p "$RUN_DIR"`(修掉"RUN_DIR 不存在"半数的 G1),但 `sh "$HP_LUA_DIR/firewall.sh" stop 2>>"$LOG_PATH"`(L392)在 **RUN_DIR 不可写/LOG_PATH 打不开**时,shell 在 exec 前就因重定向失败放弃整条命令——iptables/ipset/策略路由全部不清,LAN 黑洞保留(G1)。
- `$HP_LUA_DIR` 来自 `env.sh`(L14-15);MiWiFi 上 `/etc/homeproxy` symlink 断裂 ⇒ env.sh 读不到 ⇒ 回落 `/usr/lib/homeproxy/firewall.sh`,而该路径在 MiWiFi 布局下不存在 ⇒ teardown 同样被跳过(G2)。
- L392-393 顺序:`firewall.sh stop` 完成后才删 flag。中间的任意一次 `/etc/init.d/firewall reload` 都会让 `firewall_include.sh` 看到 flag 还在 → `firewall.sh reload` 在半清空的链上重挂部分规则 → teardown 结束后留下孤儿跳点(G2 竞态窗口)。

### 3.2 实现规格(`root/etc/init.d/homeproxy`)

在文件顶部工具区新增(与 §2.1 `resolve_fw`/`fw_log` 同源):

```sh
resolve_fw() {
    local f
    for f in "$HP_LUA_DIR/firewall.sh" \
             /data/other_vol/homeproxy/lib/firewall.sh \
             /usr/lib/homeproxy/firewall.sh; do
        [ -f "$f" ] && { printf '%s\n' "$f"; return 0; }
    done
    return 1
}
# 输出捕获到变量再尽力落盘:tee/文件重定向失败绝不能阻断 teardown(G1)。
run_fw() {   # $1 = start|stop|...
    local fw out rc=0
    if ! fw=$(resolve_fw); then
        log "WARN: firewall.sh not found in any known path; skipping '$1'."
        return 1
    fi
    out=$(sh "$fw" "$1" 2>&1) || rc=$?
    [ -n "$out" ] && printf '%s\n' "$out" >>"$LOG_PATH" 2>/dev/null
    return $rc
}
```

`stop_service()` 改为(顺序即契约):

```sh
stop_service() {
    ...现有 cron autosetup/watchdog 行清理...

    # 1) 先撤 flag:fw3 include(firewall_include.sh)只认它,先删即关掉
    #    "teardown 中途被 fw3 reload 重挂"的竞态窗口。
    rm -f "$RUN_DIR/firewall.active"
    # 2) firewall.sh stop —— 日志失败/路径缺失都不再阻断清理(G1/G2)
    run_fw stop
    # 3) 其后保持现状:dnsmasq conf 清理 + 策略路由兜底 drain +
    #    生成物删除 + cleanup_legacy_tun(顺序照 spec 6.6)
    ...
}
```

`start_service()` L252 的 `firewall.sh start` 同步改用 `run_fw start`(成功才置 flag,逻辑不变;env.sh 缺失的 MiWiFi 场景 start 同样受益,虽非本缺口范围)。

### 3.3 新顺序的全局契约

> **任何"撤接管"路径(init.d stop、看门狗 degrade、CLI firewall-stop、install.sh cleanup/rollback)都必须按同一次序:先 `rm -f firewall.active` → 再 `firewall.sh stop` → 再 dnsmasq conf 删 + `dnsmasq restart`**。理由:flag 是 include 的唯一闸门,后删就把"teardown vs fw3 reload"的竞态窗口留在整个 teardown 期间。

### 3.4 验收标准

- AC-G1-1:`chmod 0555 /var/run/homeproxy`(或 RUN_DIR 只读等价物)下 `/etc/init.d/homeproxy stop`:`iptables-save|grep homeproxy_` 为空、ipset 全清、`firewall.active` 不存在;日志缺失但 teardown 完成(对比修复前:全留)。
- AC-G2-1:`rm /etc/homeproxy`(断 symlink)后 stop:teardown 经 `/data/other_vol/...` fallback 完成(MiWiFi 布局);三者皆缺时仅 WARN,flag/dnsmasq/策略路由仍被清。
- AC-G2-2:`( /etc/init.d/homeproxy stop & sleep 0.2; /etc/init.d/firewall reload )` 类竞态 100 次不重现孤儿跳点:结束后 `-j homeproxy_` 数为 0。
- AC-G2-3:`firewall.active` 缺失而链残留(手工构造)→ `/etc/init.d/firewall reload` 后 include **不**重挂(flag 先行删除语义成立)。

### 3.5 风险

- 命令替换捕获会攒整个 `firewall.sh` 输出于内存——输出仅数行 echo,可忽略;但**不可**改回 `|`/文件重定向(破坏 G1 修复)。
- start 路径换 `run_fw` 后 stdout/stderr 时序合并进一行缓冲,日志先后微差;不影响 `-t` 判定逻辑。
- flag 先删意味着:`firewall.sh stop` 自身极慢时,flag 消失早于规则清理——include 不再重挂,这正是目的;无反向风险。

---

## 4. G3 — dnsmasq conf 增加 `lan_proxy_mode != disabled` 门控

### 4.0 决策

**`start_service` 写 dnsmasq conf 的条件追加 `lan_proxy_mode != disabled`;不满足时走与 `dns_redirect=0` 相同的"删残留 + 按需 restart"分支。另把 stale-conf 清理提升为无条件动作,覆盖 `outbound_node=nil` 早退路径(现行代码在 L157 早退后根本到不了清理块)。**

### 4.1 真值表(是否写 `/tmp/dnsmasq.d/homeproxy_*.conf`)

| `outbound_node` | `infra.dns_redirect` | `control.lan_proxy_mode` | 写 conf | 备注 |
|---|---|---|---|---|
| `nil` | * | * | 否 | 无 meow-c;残留必须删除(现行漏清) |
| ≠nil | `0` | * | 否(删残留) | 现状不变 |
| ≠nil | `1` | `disabled` | **否(删残留)** | **G3 本缺口**:接管臂不装时把 DNS 转给 meow 纯增风险(meow 死 = LAN DNS 死),且 ipset 不存在、`ipset=` 行本就因 set 缺失而不发 |
| ≠nil | `1` | `only_proxy`/`listed_only`/`except_listed` | 是 | 现状不变 |
| ≠nil | `1` | `global`/其它新值 | 是 | 同"非 disabled" |

(之后是否写 `server=`/`ipset=` 仍按现有 routing_mode 分支 + ipset 存在性探测,不变。)

### 4.2 实现规格(`root/etc/init.d/homeproxy`)

抽公共助手并在**早退之前**定义:

```sh
drop_dnsmasq_confs() {
    if ls /tmp/dnsmasq.d/homeproxy_*.conf >/dev/null 2>&1; then
        rm -f /tmp/dnsmasq.d/homeproxy_*.conf
        /etc/init.d/dnsmasq restart >/dev/null 2>&1
    fi
}
```

1. L157-159 早退分支(`outbound=nil && server=0`)改为:
   ```sh
   if [ "$outbound_node" = "nil" ] && [ "$server_enabled" = "0" ]; then
       drop_dnsmasq_confs          # G3:nil 早退也不得留旧 conf(残→SERVFAIL)
       return 2                    # G9,见 §6
   fi
   ```
2. DNS 块(L308-315)改为:
   ```sh
   local dns_redirect lan_proxy_mode
   config_get_bool dns_redirect "infra" "dns_redirect" "1"
   config_get      lan_proxy_mode "control" "lan_proxy_mode" "disabled"
   if [ "$dns_redirect" != "1" ] || [ "$lan_proxy_mode" = "disabled" ]; then
       drop_dnsmasq_confs          # 合并的"不写"分支(含 G3 新门控)
   elif [ "$outbound_node" != "nil" ]; then
       ...现有 conf 生成不变...
   fi
   ```
3. G5 新增 `enabled=0` 早退分支(§7.2)同样先 `drop_dnsmasq_confs`。

### 4.3 验收标准

- AC-G3-1:`lan_proxy_mode=disabled` + `dns_redirect=1` + 有效节点 → restart 后 `ls /tmp/dnsmasq.d/homeproxy_*` 无文件;`nslookup google.com <lan-ip>` 走系统上游成功(与 meow 存活无关)。
- AC-G3-2:同一条件先 `lan_proxy_mode=except_listed` 启动产生 conf,再切 `disabled` restart → conf 被删且 dnsmasq 已 restart(`logread` 见 dnsmasq 重启)。
- AC-G3-3:`main_node=nil` + `server.enabled=0` + 手工预置 `/tmp/dnsmasq.d/homeproxy_redirect_dns.conf` → `/etc/init.d/homeproxy start` 后该文件被删。
- AC-G3-4:`dns_redirect=0` 行为逐字节不变(回归)。

### 4.4 风险

- 用户若用 `lan_proxy_mode=disabled` 但有意让 LAN DNS 走 meow(如仅用域名分流不改路由)——该配置在接管臂全缺时本就无法生效(ipset 不存在),门控只削风险不削功能;文档(RECOVERY.md B 节点)同步更新文案。
- `dnsmasq restart` 触发条件与现状一致(仅当删了文件才 restart),不增加重启次数。

---

## 5. G9 — Web/CLI "nil 恢复"误报消除

### 5.0 决策

**选"rc 语义修正"而非新增 stop 端点:init.d `start_service` 把"outbound=nil 且 server 全关"的合法空跑从 `return 1` 改为 `return 2`(复用 `generate_server.lua` 的 rc=2="定义内跳过"契约);`api` 的 `do_restart`/restart 端点把 rc∈{0,2} 视为成功;boot_restore 同样把 2 视为非错误。不新增 `stop` 端点。**

理由:
1. nil+restart 是 RECOVERY.md B1 钦定的恢复动作,"返回失败"纯粹是 rc 语义错位——修语义,不是加通道。
2. 新 stop 端点修不了同一早退在 `homeproxy restart` CLI、`set_routing_mode`→nil 等其它调用方上的同型误报;rc=2 一处改、处处生效。
3. rc=2 与 rc=1 仍区分真实失败(生成失败/`-t` 失败仍 1),web 不误放行。
4. API 面不膨胀(无认证 LAN 端点,少一个少一份面)。

### 5.1 实现规格

- `root/etc/init.d/homeproxy`:L157-159 早退 `return 1` → `return 2`(连带 §4.2 的 `drop_dnsmasq_confs`)。`enabled=0` 早退(§7.2)同样 `return 2`。
- `root/etc/homeproxy/web/cgi-bin/api`:
  ```sh
  do_restart() {
      "$INIT" restart >/dev/null 2>&1
      local rc=$?
      # rc=2 = "nothing to run"(nil outbound / enabled=0):定义内成功态。
      [ "$rc" = "0" ] || [ "$rc" = "2" ] || "$INIT" start >/dev/null 2>&1
  }
  ```
  (start 兜底分支同样接受 rc=2——在 `||` 链里把 `$?` 也按 0/2 判定。)
- `boot_restore.sh` L91:`"$INITD/homeproxy" start` 的 `|| log "returned $?"` 改为 `rc=$?; [ "$rc" -gt 2 ] && log ...`。
- `usr/bin/homeproxy`:`start|stop|restart|reload` 透传 rc 不变;在 `restart` rc=2 时补一行提示 `echo "nothing to run (no outbound/server) -- config saved"`(可选,web 已自足)。
- `docs/RECOVERY.md`:删 B1 的"⚠ 会弹 service restart failed——误报"注记。

### 5.2 验收标准

- AC-G9-1:web `main_node=nil` + Apply → `{"ok":true}`,无 "restart failed";iptables/ipset/dnsmasq 全清。
- AC-G9-2:`homeproxy restart` 在 nil 状态下 rc=2;在"生成器必失败"状态下 rc=1(错误路径不被吞)。
- AC-G9-3:正常节点 restart rc=0;全部 set_* 端点在 nil/非 nil 下行为一致。

### 5.3 风险

- 依赖 rc.common 把 `start_service` 的返回值透传到 `/etc/init.d/homeproxy restart` 的退出码——OpenWrt 18.06 rc.common 满足;实施时以 `; echo $?` 实测确认(未决点 Q1)。
- 未来若有人在早退路径上加真实副作用,rc=2 仍合法(语义是"无事可跑"而非"失败")。

---

## 6. G4 — CLI 一键接管拆除子命令

### 6.0 决策

**新增 `homeproxy firewall-stop`(别名不接受,唯一名):执行与看门狗 degrade 完全同序的"撤接管"四步(flag → firewall.sh stop → dnsmasq conf → restart),不杀 meow 进程、不改 UCI;后端委托 `watchdog.sh degrade` 单一实现,缺脚本时内联同序 fallback。**

命名取舍:`firewall-stop` 与现有 `firewall.sh stop` 语义直译、在断网应急心智下最不易记错;`teardown`/`panic` 含义偏散;不挂在 `stop` 下是刻意区分"停服务(杀 meow)"与"仅撤接管(保留混合口/API 供诊断)"。

### 6.1 实现规格(`root/usr/bin/homeproxy`)

```sh
firewall-stop)
    # 撤接管而不动 procd 实例/UCI:meow 若活着,mixed/API 口仍可用于诊断。
    WD=""
    for f in /etc/homeproxy/scripts/watchdog.sh \
             /data/other_vol/homeproxy/scripts/watchdog.sh; do
        [ -f "$f" ] && { WD="$f"; break; }
    done
    if [ -n "$WD" ]; then
        sh "$WD" degrade
    else
        # 内联同序 fallback(§3.3 契约):绝不让"找不到脚本"变成"拆不掉"。
        rm -f "$RUN_DIR/firewall.active"
        for f in "$LUA_DIR/firewall.sh" \
                 /data/other_vol/homeproxy/lib/firewall.sh \
                 /usr/lib/homeproxy/firewall.sh; do
            [ -f "$f" ] && { sh "$f" stop; break; }
        done
        if ls /tmp/dnsmasq.d/homeproxy_*.conf >/dev/null 2>&1; then
            rm -f /tmp/dnsmasq.d/homeproxy_*.conf
            /etc/init.d/dnsmasq restart >/dev/null 2>&1
        fi
        : > "$RUN_DIR/hp_watchdog.degraded"
    fi
    echo "firewall teardown done (service untouched). 'homeproxy restart' to restore."
    ;;
```

同时更新帮助块(L5-27)加一行;RECOVERY.md C4 手动补刀步骤改为 `homeproxy firewall-stop`。

### 6.2 验收标准

- AC-G4-1:运行态执行 `homeproxy firewall-stop` → flag/ipsets/跳点/dnsmasq conf 全清,`pgrep -f meow` 仍在;`homeproxy restart` 完整还原。
- AC-G4-2:`watchdog.sh` 被删时内联路径完成同样的四步。
- AC-G4-3:连续两次执行幂等,第二次无错、无多余 dnsmasq restart。

### 6.3 风险

- 与看门狗共享 degrade 代码路径意味着 watchdog.sh 必须存在于 `scripts/`(install.sh 的显式安装清单需加入,§9.2);fallback 保证缺失时不致命。
- 命令不读 `enabled`:这是止血工具,语义上"拆"永远合法。

---

## 7. G5 — `config.enabled` 总开关(默认 1)

### 7.0 决策

**新增 `homeproxy.config.enabled`(默认 `'1'`):`init.d start_service` 在最前尊重它(rc=2 早退并做防御性撤接管);`boot_restore.sh` 重建 init 脚本后按它决定是否拉起;`homeproxy disable` 改为 `uci set config.enabled=0 && commit && /etc/init.d/homeproxy stop`(在 MiWiFi 上真正生效);`enable` 对称置 1(不自动 start)。rc.d enable/disable 机制保留为附加动作(标准包安装仍有用)。**

### 7.1 schema

- `root/etc/config/homeproxy` `config` 段加 `option enabled '1'`。
- `migrate_config.lua` `config` 段默认值区加 `ensure("config", "enabled", "1")`——老配置升级即得默认值,幂等。
- `infra` 段新增 `option watchdog '1'` + `ensure("infra", "watchdog", "1")`(G0 opt-out;放 infra 与 `dns_redirect` 等管道开关同层)。

### 7.2 实现规格

`init.d start_service`(config_load 之后、所有生成之前,与 migrate 后值一致):

```sh
local enabled
config_get_bool enabled "config" "enabled" "1"
if [ "$enabled" != "1" ]; then
    log "config.enabled=0 -- disabled; ensuring teardown and skipping start."
    rm -f "$RUN_DIR/firewall.active"          # 先撤 flag(§3.3 契约)
    run_fw stop                              # 幂等;无规则时 no-op
    drop_dnsmasq_confs
    return 2                                  # G9:"定义内空跑"
fi
```

`boot_restore.sh` §4 启动块:

```sh
if [ "$need_start" = 1 ]; then
    if [ "$(uci -q get homeproxy.config.enabled 2>/dev/null)" = "0" ]; then
        log "homeproxy disabled (config.enabled=0) -- init scripts restored, service NOT started."
    else
        log "starting homeproxy + homeproxy-web."
        "$INITD/homeproxy" start >/dev/null 2>&1 || ...
    fi
    "$INITD/homeproxy-web" start >/dev/null 2>&1 || ...   # web 不受 enabled 门控:它是恢复通道
fi
```

`usr/bin/homeproxy`:

```sh
enable)
    "$INIT" enable 2>/dev/null          # rc.d 链接(标准包安装仍生效)
    uci_set "config.enabled" "1" || die "uci set failed"
    echo "Enabled $CONF at boot (run 'homeproxy start' to start now)." ;;
disable)
    "$INIT" disable 2>/dev/null
    uci_set "config.enabled" "0" || die "uci set failed"
    "$INIT" stop >/dev/null 2>&1        # 立即止血
    echo "Disabled $CONF (boot_restore will not restart it)." ;;
```

`cmd_status` 增加一行 `enabled: $(uci_get config.enabled)`。API `state` JSON 增加 `"enabled"` 字段;`config|settings` 投影的 `KEEP.config` 白名单加 `enabled=1`(供 UI 显示"已禁用"而非只显示 stopped)。

### 7.3 验收标准

- AC-G5-1:`homeproxy disable` 后 `reboot`(或手工跑 `boot_restore.sh` 且删掉 init 脚本模拟开机):`/etc/init.d/homeproxy` 被重建但服务**未**启动,`pgrep meow` 空;`homeproxy-web` 已起。
- AC-G5-2:`enabled=0` 下 `/etc/init.d/homeproxy start` rc=2;接管状态被防御性清掉。
- AC-G5-3:`enabled` 不存在的老配置经 migrate 后 `uci get homeproxy.config.enabled` = 1;重启行为与现状逐点一致(回归)。
- AC-G5-4:`homeproxy enable` 只置位不启动;文档化的组合 `enable && start` 正常。

### 7.4 风险

- **与 rc.d 机制的双轨**:MiWiFi 开机路径是 `auto_start.sh`→`boot_restore.sh`(非 rc.d),`$INIT disable` 在 MiWiFi 上删的是无用 symlink;保留调用是为标准包安装不回归——务必在 help 注明真正语义已迁移到 UCI。
- `update_resources.sh`/订阅流的"服务在跑才 restart"判定不受影响(enabled=0 ⇒ 无 meow 进程 ⇒ 不会 restart)。
- 若用户在 enabled=0 下手工 `firewall.sh start` 残留规则:stop/disable 的防御性清理与看门狗 stakes 检查均能兜底;不新增拦截逻辑。

---

## 8. G10 — install.sh 验证窗内连通性探测

### 8.0 决策

**`meow_expected=1` 分支在"进程出现"后追加经 `127.0.0.1:$mixed_port` 的 `generate_204` 探测(自有 TIMEOUT 窗口,复用 `HP_CONFIRM_TIMEOUT`);连续至超时无 2xx/3xx → 走既有失败路径(upgrade→rollback,fresh→cleanup_volatile)。`meow_expected=0` 不探测(保持 web-UI 探针)。新增 `HP_INSTALL_SKIP_CONN=1` 逃逸开关与 `HP_PROBE_URL` 覆盖。**

### 8.1 实现规格(`install.sh` L519-555 验证块)

```sh
PROBE_URL=${HP_PROBE_URL:-http://www.gstatic.com/generate_204}
mixed_port=$(uci -q get homeproxy.infra.mixed_port 2>/dev/null); mixed_port=${mixed_port:-5330}

conn_probe() {   # 经 mixed 口的端到端:meow + 节点 + 上游 全链路
    command -v curl >/dev/null 2>&1 || return 1
    code=$(curl -s -o /dev/null --max-time 8 -x "http://127.0.0.1:$mixed_port" \
        -w '%{http_code}' "$PROBE_URL" 2>/dev/null) || return 1
    case "$code" in 2[0-9][0-9]|3[0-9][0-9]) return 0 ;; *) return 1 ;; esac
}
```

`meow_expected=1` 流程改为两段:

```text
段1(现状):进程探针循环 ≤ TIMEOUT 秒 → 未出现 → 失败路径
段2(新增):[HP_INSTALL_SKIP_CONN=1 → skip] 进程已出现后重置计时,
         每 2s 一次 conn_probe ≤ TIMEOUT 秒;进程中途死掉不算失败,
         继续等 respawn+探测 → 全窗无 2xx/3xx → ok=0 → 失败路径
```

日志区分 `FAILED: meow process never appeared` 与 `FAILED: meow up but no proxied connectivity (${PROBE_URL})`(便于区分"内核没起"与"节点黑")。`curl` 缺失时段2直接判失败(warn 明示;`+curl` 本就在 DEPENDS)。

### 8.2 验收标准

- AC-G10-1:upgrade 到一个"进程能起但 outbound 全黑"的版本(如 stub 节点)→ 30s 内自动回滚,旧版恢复运行。
- AC-G10-2:正常升级 → 进程 + 204 双通过,DONE=1,`BACKUP_TAR` 清理照旧。
- AC-G10-3:`meow_expected=0` fresh install 不发起任何 5330 探测。
- AC-G10-4:`HP_INSTALL_SKIP_CONN=1` 行为=旧版纯进程探针(回归)。
- AC-G10-5:`HP_PROBE_URL=https://...` 覆盖生效(https 经 mixed 口 CONNECT)。

### 8.3 风险

- **节点死 ≠ 版本坏**:发布时恰好上游节点故障 → 好版本被回滚。缓解:探测窗给满 TIMEOUT;文档明示 `HP_INSTALL_SKIP_CONN=1`;设计意图本就倾向"宁滚勿黑"(G10 缺口定义)。
- 探测 URL 单一(默认 gstatic)在 CN-only 可达的节点上恒失败 → 同上逃逸开关;不把 Baidu 直连腿纳入判定(直连不代表代理通)。
- 最坏验证时长 TIMEOUT×2(进程段+连通段)——`HP_CONFIRM_TIMEOUT` 文档同步。

---

## 9. 文件归属清单(实施改动面)

| 文件 | 动作 | 缺口 |
|---|---|---|
| `root/etc/homeproxy/scripts/watchdog.sh` | **新增**(755) | G0,G4(后端) |
| `root/etc/init.d/homeproxy` | `resolve_fw`/`run_fw`/`drop_dnsmasq_confs` 助手;start:`enabled` 门控(rc=2)、nil 早退 rc=2+清 conf、`run_fw start`、watchdog cron 行;stop:flag 先行、`run_fw stop`、watchdog 行清理 | G1,G2,G3,G5,G9,G0-接线 |
| `root/etc/homeproxy/scripts/boot_restore.sh` | `need_start` 块按 `config.enabled` 门控 homeproxy(web 仍起);start rc=2 视为非错 | G5,G9 |
| `root/usr/bin/homeproxy` | `firewall-stop` 子命令;`enable|disable` 改语义;`status` 加 enabled;帮助文本 | G4,G5 |
| `root/etc/homeproxy/web/cgi-bin/api` | `do_restart` 接受 rc 0/2;`state`/`config` 投影加 `enabled` | G9,G5 |
| `root/etc/config/homeproxy` | `config.enabled '1'`、`infra.watchdog '1'` | G5,G0 |
| `root/usr/lib/homeproxy/migrate_config.lua` | `ensure("config","enabled","1")`、`ensure("infra","watchdog","1")` | G5,G0 |
| `install.sh` | 验证段加连通探测;脚本安装清单(L444-446)加 `watchdog.sh` | G10,G0 |
| `Makefile` | `Package/homeproxy/install` 加 `watchdog.sh` 的 `INSTALL_BIN` | G0 |
| `docs/RECOVERY.md` | B1 删误报注记;C4 改 `firewall-stop`;C5 改 `homeproxy disable`;缺口表 G0-G10 状态更新 | 全部 |
| `firewall_include.sh` | **不改**(flag 语义不变,只是删的时机提前) | — |
| `firewall.sh` | **不改**(teardown 顺序属调用方契约,见 §3.3) | — |

## 10. 不做的事(本批次明确排除)

1. **不做 degrade 后的自动回切/自愈恢复**:degraded 是 sticky 终态,只能由人工 `homeproxy restart`/`start` 解除(防 flap;判定依据见 §2.1.2)。
2. **不做经上游节点的端到端连通性看门狗探测**:"节点死"交给换节点/订阅流程;把节点死降级为直连会掩盖故障且有语义争议(用户显式选了代理)。仅 G10 安装窗例外。
3. **不看护 meow-s**:它不承载 LAN 接管,死了由 procd respawn 负责。
4. **不引入常驻守护进程**:cron(1min)+ tmpfs 状态文件够用;不碰 procd instance 模型(respawn 参数不变)。
5. **不新增 web `stop` 端点 / `enabled` 写端点**(G9 已选 rc 方案;`enabled` 仅经 CLI/UCI 写,web 只读显示——LAN 无认证面上不做"一键永久禁用"按钮)。
6. **不改链结构/不新增 OUTPUT 接管**;`firewall.sh` 本体零改动。
7. **不动 `update_via_proxy`/`sync_rule_files`/生成器**;`HP_MATERIALIZE_ALL_NODES` 语义不变。
8. **不做跨机高可用/通知**(短信/syslog 推送降级事件不做——写 `homeproxy.log` 即止)。

## 11. 未决点(实施前需确认)

- **Q1**:rc.common 对 `start_service` 返回 2 的透传——18.06 实测 `/etc/init.d/homeproxy start; echo $?`(预计透传;若不透传,G9 退路=web 在 `set_main_node` 收到 `nil` 时改调 `"$INIT" stop` + 直接判成,作为方案 B 备选)。
- **Q2**:看门狗三常量(`FAILS_BEFORE_RESTART=2`/`FAILS_BEFORE_DEGRADE=3`/tick 1min)是否需暴露为 `infra.watchdog_*` UCI 调参——本规范建议**不暴露**(少面少错),按需复议。
- **Q3**:`config.enabled=0` 时 `service_triggers` 的 wan-up `reload` 仍会触发 start_service(rc=2 空跑,无实际副作用)——是否接受每次 wan flap 记一行 disabled 日志;备选=reload 前先查 enabled 直接 exit。
- **Q4**:degrade 是否应同时 `kill` 挂死的 meow-c 进程(当前规格不杀,留给 procd 与人工 restart;杀掉可省内存但让"进程级诊断"消失)。
- **Q5**:G10 的 `PROBE_URL` 是否应同时记录 direct 腿(Baidu)供日志区分"上游挂"vs"出口全挂"——仅日志增强,不判回滚。

---

## 12. 实施勘误与追加决策（评审+复验期裁决）

> 状态：已由 CTO 批准并按此实施（修复波次落地），本文件为存档。

1. **§5.1 rc 判定笔误**：`[ rc -gt 2 ]` 会吞掉 rc=1 真失败 → 实施为 `rc!=0 && rc!=2`（boot_restore/api/CLI 同语义）。
2. **§6.1 内联 fallback**：`:` 是 POSIX special builtin，`: > file` 重定向失败会中止整脚本 → marker 写入前必 `mkdir -p "$RUN_DIR"`，watchdog.sh 同模式（子壳包裹或 `|| true`）。
3. **§8.1 段2窗口**：按"每 2s 一次共 TIMEOUT 秒"实现实际最坏 ~5×TIMEOUT（单次 curl --max-time 8 不计入）→ 实施为 `date +%s` deadline 墙钟循环。
4. **§7.2 补遗**：`index.html` `loadState` 渲染 `enabled=0 → "disabled"` badge（原规格漏派 UI 侧；api `state` 已投影）。
5. **§2.1.4 重挂探针**：`iptables -t nat` 单表探测在 `proxy_mode=tproxy`（跳点全在 mangle）下恒误触发 → 实施为按 proxy_mode 求"应在"跳点（nat/mangle/dns 逐跳点名校验），任一缺失才重挂。
6. **布尔拼写归一**：`config.enabled`/`infra.watchdog`/`control.lan_proxy_mode` 的"关"判定统一为 `0|no|off|false|disabled`（对齐 `config_get_bool`），watchdog/boot_restore 均已 case 化。
7. **看门狗状态机增补**（评审驱动，不改变对外契约）：state 改键值解析（去 source 注入面）；mkdir 锁内写 PID+`kill -0` 回收 stale；连续 2 个健康 tick 复位 `restarts`（episode 语义）。
8. **init.d 防御清理扩散**：`outbound=nil` 早退臂与 `enabled=0` 臂同样执行 §3.3 拆除序（flag→run_fw stop→drop_dnsmasq_confs），覆盖"运行中 uci 直改 nil + 裸 start"残留黑洞路径；`stop_service` 末尾 `return 0` 防幽灵 rc。
9. **未决项处置**：Q1 保留真机实测项（RW2 论证：MiWiFi rc.common 实际透传 rc，且掩码后 2→0 仍兼容成功集）；Q2 不暴露调参；Q4 degrade 不杀进程维持原决策。
