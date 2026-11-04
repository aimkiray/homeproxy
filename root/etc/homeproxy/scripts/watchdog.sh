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
STATE=$RUN_DIR/hp_watchdog.state        # "fails=N restarts=N healthy=N"
DEGRADED=$RUN_DIR/hp_watchdog.degraded  # sticky marker
LOCK=/var/run/hp_watchdog.lock
API=http://127.0.0.1:19290              # meow external-controller (生成端写死)

FAILS_BEFORE_RESTART=2    # 连续 N 次探测失败 -> 服务级 restart 一次
FAILS_BEFORE_DEGRADE=3    # restart 后再连续 N 次失败 -> degrade
DEGRADE_LOCK_WAIT=130     # degrade 等锁上限(秒);须大于 restart 的 timeout 120

MEM_WARN_KB=81920         # 连续 2 tick MemAvailable < 80MB -> restart meow-c
MEM_CRIT_KB=49152         # MemAvailable < 48MB -> 立即 restart meow-c + meow-los
MEM_RESTART_COOLDOWN=600  # 两次内存触发的 restart 全局最小间隔(秒,防抖)
MEM_BOOT_GRACE=180        # 开机 3min 内不检查(启动期分配未稳定)
MEMLOW_COUNT=/tmp/hp_memlow.count    # 连续低水位 tick 计数
MEMRESTART_TS=/tmp/hp_memrestart.ts  # 上次内存触发 restart 的 epoch

mkdir -p "$RUN_DIR" 2>/dev/null
log() { echo "$(date '+%H:%M:%S') [hp-watchdog] $*" >>"$LOG_PATH" 2>/dev/null; }
uci_get() { uci -q get "homeproxy.$1" 2>/dev/null; }
# config_get_bool 同款"关"词表(W1-6):uci 布尔拼写不只字面 0。
bool_off() { case "$1" in 0|no|off|false|disabled) return 0 ;; *) return 1 ;; esac }

# --- env + firewall.sh 解析(G2 同款 fallback 链,见 spec §3.2)--------------
[ -f /etc/homeproxy/env.sh ] && . /etc/homeproxy/env.sh || true
HP_LUA_DIR="${HP_LIB_DIR:-/usr/lib/homeproxy}"
resolve_fw() {
	local f
	for f in "$HP_LUA_DIR/firewall.sh" \
	         /data/other_vol/homeproxy/lib/firewall.sh \
	         /usr/lib/homeproxy/firewall.sh; do
		[ -f "$f" ] && { printf '%s\n' "$f"; return 0; }
	done
	return 1
}

# --- 探测(§2.1.3):进程存在 AND 事件循环应答。不做经 5330 的端到端探测——
#     上游节点死 != 内核死(spec §10.2)。
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

# --- 内存水位防线(U4):vm.panic_on_oom=2 + kernel.panic=3 —— OOM 即
#     panic+3s 重启、零日志。监视 MemAvailable,抢在内核 OOM-killer 之前
#     重启耗内存的 meow 实例。只用 /proc/meminfo+logger+init.d,不新增依赖;
#     任何一步失败不得中断 tick 其余检查(函数内全程容错,调用点按 rc 分流)。
mem_restart_service() {   # $1=init 脚本(-x):rc.common 靠 shebang 分发,
	                      # `sh script restart` 是静默 no-op(2026-11 实测)
	                      # ——必须直接 exec;9>&- 不把锁 fd 漏进服务链。
	if command -v timeout >/dev/null 2>&1; then
		timeout 120 "$1" restart >>"$LOG_PATH" 2>&1 9>&-
	else
		"$1" restart >>"$LOG_PATH" 2>&1 9>&-
	fi
}
mem_guard() {
	local up avail now last count cooling f init_c init_l did _k _v

	# 开机宽限:启动期分配未稳定,此时重启服务只会放大抖动。
	up=$(cut -d. -f1 /proc/uptime 2>/dev/null)
	case "$up" in ''|*[!0-9]*) return 0 ;; esac
	[ "$up" -lt "$MEM_BOOT_GRACE" ] && return 0

	# 纯 shell 读 /proc/meminfo(直接重定向,不进子壳);无该字段即放弃。
	avail=""
	while read -r _k _v _; do
		[ "$_k" = "MemAvailable:" ] && { avail=$_v; break; }
	done </proc/meminfo 2>/dev/null
	case "$avail" in ''|*[!0-9]*) return 0 ;; esac

	# 回到 warn 水位之上=已恢复:连续低水位计数清零,本轮无动作。
	if [ "$avail" -ge "$MEM_WARN_KB" ]; then
		rm -f "$MEMLOW_COUNT" 2>/dev/null
		return 0
	fi

	# 全局冷却:距上次内存触发的 restart <10min 本轮只计数不动作。
	now=$(date +%s 2>/dev/null || echo 0)
	case "$now" in ''|*[!0-9]*) now=0 ;; esac
	last=$(cat "$MEMRESTART_TS" 2>/dev/null || echo 0)
	case "$last" in ''|*[!0-9]*) last=0 ;; esac
	cooling=0
	[ "$now" -gt 0 ] && [ "$last" -gt 0 ] \
		&& [ $((now - last)) -lt "$MEM_RESTART_COOLDOWN" ] && cooling=1

	init_c=""
	for f in /etc/init.d/homeproxy /data/other_vol/homeproxy/init.d/homeproxy; do
		[ -x "$f" ] && { init_c=$f; break; }
	done

	if [ "$avail" -lt "$MEM_CRIT_KB" ]; then
		# crit 水位:立即动作(不计数)——meow-c 与 meow-los(init 存在才动)
		# 一起重启;冷却期内跳过。
		[ "$cooling" = "1" ] && return 0
		init_l=""
		for f in /etc/init.d/meow-los /data/other_vol/meow-los/init.d/meow-los; do
			[ -x "$f" ] && { init_l=$f; break; }
		done
		# init 全缺时不写冷却戳、不误报 restarted——凭空 arm 10min 冷却
		# 会压住随后真正可执行的 restart;记一行日志说明本轮放弃。
		if [ -z "$init_c" ] && [ -z "$init_l" ]; then
			log "mem crit (${avail}kB) but no init script found -- restart skipped, no cooldown armed."
			return 0
		fi
		logger -t homeproxy-watchdog "mem crit: ${avail}kB, restarting meow services" 2>/dev/null || true
		echo "$now" >"$MEMRESTART_TS" 2>/dev/null || true
		rm -f "$MEMLOW_COUNT" 2>/dev/null
		did=""
		[ -n "$init_c" ] && { mem_restart_service "$init_c" || log "WARN: meow-c restart rc=$?"; did="meow-c"; }
		[ -n "$init_l" ] && { mem_restart_service "$init_l" || log "WARN: meow-los restart rc=$?"; did="${did:+$did + }meow-los"; }
		log "mem crit (${avail}kB): restarted $did"
		return 10
	fi

	# warn 水位:连续 2 tick 低于才动作;恢复即清零见上面的 warn 分支。
	count=$(cat "$MEMLOW_COUNT" 2>/dev/null || echo 0)
	case "$count" in ''|*[!0-9]*) count=0 ;; esac
	count=$((count + 1))
	echo "$count" >"$MEMLOW_COUNT" 2>/dev/null || true
	[ "$count" -lt 2 ] && return 0
	[ "$cooling" = "1" ] && return 0
	# init 缺失同上:不写冷却戳、不误报 restarted。
	if [ -z "$init_c" ]; then
		log "mem low (${avail}kB) on $count consecutive ticks but no init script -- restart skipped."
		return 0
	fi
	logger -t homeproxy-watchdog "mem low: ${avail}kB, restarting meow" 2>/dev/null || true
	echo "$now" >"$MEMRESTART_TS" 2>/dev/null || true
	rm -f "$MEMLOW_COUNT" 2>/dev/null
	mem_restart_service "$init_c" || log "WARN: meow-c restart rc=$?"
	log "mem low (${avail}kB) on $count consecutive ticks: restarted meow-c"
	return 10
}

# --- degrade(§3.3 撤接管契约顺序:flag -> firewall.sh stop -> dnsmasq)------
do_degrade() {
	# 顺序固定:先撤 flag 再清规则——否则 fw3 include 可能在半清空状态上
	# reload,留下孤儿跳点。
	rm -f "$RUN_DIR/firewall.active"
	local fw out
	if fw=$(resolve_fw); then
		# 命令替换捕获输出:RUN_DIR 不可写/日志打不开也不能阻断 teardown(G1)。
		# 9>&-: 别把 watchdog 锁 fd 漏进 firewall.sh 的常驻子进程(supervisor)。
		out=$(sh "$fw" stop 2>&1 9>&-)
		[ -n "$out" ] && printf '%s\n' "$out" >>"$LOG_PATH" 2>/dev/null
	else
		log "WARN: firewall.sh not found; skipped rule teardown."
	fi
	if ls /tmp/dnsmasq.d/homeproxy_*.conf >/dev/null 2>&1; then
		rm -f /tmp/dnsmasq.d/homeproxy_*.conf
		/etc/init.d/dnsmasq restart >/dev/null 2>&1 9>&-
	fi
	# W1-8:marker 写失败不再静默——降级事实已生效,缺标记只会让后续
	# tick 重复走 degrade 幂等路径,记 WARN 供排查。
	# 子壳包裹是刻意的:`:' 是 special builtin,重定向失败会中止整个
	# 脚本(dash/ash 实测),裸 `||' 根本轮不到执行;子壳只死自己。
	( : >"$DEGRADED" ) 2>/dev/null \
		|| log "WARN: cannot write $DEGRADED -- degraded marker missing (RUN_DIR unwritable?)"
	log "DEGRADED to direct-only (firewall.active removed, rules + dnsmasq confs cleared). Run 'homeproxy restart' to restore."
}

# --- 并发与防重入(§2.1.6;boot_restore.sh 同款双模锁)----------------------
USE_FLOCK=0
if command -v flock >/dev/null 2>&1 && exec 9>"$LOCK" 2>/dev/null; then
	USE_FLOCK=1
fi
LOCKD="$LOCK.d"
mkdir_lock() {
	mkdir "$LOCKD" 2>/dev/null || return 1
	echo $$ >"$LOCKD/pid" 2>/dev/null    # W1-3:stale 检测靠它
	trap 'rm -f "$LOCKD/pid" 2>/dev/null; rmdir "$LOCKD" 2>/dev/null' EXIT
	return 0
}
LOCK_PEER=""
lock_try() {
	local lp
	if [ "$USE_FLOCK" = "1" ]; then
		flock -n 9 2>/dev/null
		return
	fi
	mkdir_lock && return 0
	# W1-3:锁目录里有 holder PID——kill -0 验活,死则回收重试一次;
	# 无/脏 PID(holder 恰在 mkdir 与写 pid 之间,或写失败)走与其它锁点
	# 一致的 120s mtime 兜底——无 pid 不等于"仍活",stat 失败仍按活处理。
	local lp _ino _mt
	lp=$(cat "$LOCKD/pid" 2>/dev/null)
	case "$lp" in ''|0|*[!0-9]*) lp="" ;; esac   # '0' 也是脏值:kill -0 0 恒真
	LOCK_PEER=$lp
	if [ -n "$lp" ]; then
		kill -0 "$lp" 2>/dev/null && return 1
	else
		_mt=$(stat -c %Y "$LOCKD" 2>/dev/null) || _mt=0
		{ [ "${_mt:-0}" -eq 0 ] || [ $(($(date +%s) - _mt)) -le 120 ]; } && return 1
	fi
	# 只回收被判死的那个目录本体:竞态新建的锁目录 inode 不同。
	_ino=$(stat -c %i "$LOCKD" 2>/dev/null)
	[ -n "$_ino" ] && [ "$(stat -c %i "$LOCKD" 2>/dev/null)" = "$_ino" ] \
		&& { rm -f "$LOCKD/pid" 2>/dev/null; rmdir "$LOCKD" 2>/dev/null; }
	mkdir_lock && { log "reclaimed stale watchdog lock${lp:+ (dead pid $lp)}."; return 0; }
	return 1
}

# --- degrade 子命令(G4 共用后端;不读 enabled——止血永远合法)---------------
if [ "${1:-tick}" = "degrade" ]; then
	# 与在飞的 tick/restart 互斥:等满 restart 的 timeout 窗口,仍持锁则
	# 止血优先,强行执行。
	i=0
	while ! lock_try; do
		i=$((i+1))
		if [ "$i" -ge "$DEGRADE_LOCK_WAIT" ]; then
			log "WARN: watchdog lock still held after ${i}s -- running degrade anyway."
			break
		fi
		sleep 1
	done
	do_degrade
	exit 0
fi

# --- tick:并发互斥 -------------------------------------------------------
lock_try || { log "WARN: watchdog lock held${LOCK_PEER:+ by pid $LOCK_PEER}; exiting."; exit 0; }

# --- 门控(§2.1.2;不满足任一即 exit 0,不写状态文件)-----------------------
bool_off "$(uci_get config.enabled)" && exit 0            # G5 总开关
bool_off "$(uci_get infra.watchdog)" && exit 0            # 看门狗 opt-out(默认 1)

# meow-c 预期判定(与 init.d/install.sh/firewall.sh 同一公式)
routing_mode=$(uci_get config.routing_mode); routing_mode=${routing_mode:-bypass_mainland_china}
if [ "$routing_mode" = "custom" ]; then
	outbound_node=$(uci_get routing.default_outbound)
else
	outbound_node=$(uci_get config.main_node)
fi
outbound_node=${outbound_node:-nil}
[ "$outbound_node" = "nil" ] && { rm -f "$STATE"; exit 0; }   # meow-c 不该在跑

# sticky degraded:已降级状态下,只有人工 restart(flag 重新出现)才解除
if [ -f "$DEGRADED" ]; then
	[ -f "$RUN_DIR/firewall.active" ] && rm -f "$DEGRADED" || exit 0
fi

# --- 内存水位防线:每个启用 tick 都跑(与 meow-c 健康状态无关)-------------
#     rc=10 = 本轮已执行内存触发的 restart:刚拉起的服务必然后续探活失败,
#     继续本 tick 只会污染 fails 甚至误入 degrade——直接收尾。其它 rc
#     (含函数内单点失败)照常落入既有检查。
#     位置刻意在 sticky-degraded 门之后:degraded 是"等人工介入"状态,内存
#     触发的整服务 restart 会重挂 firewall.active,下一 tick 静默清掉
#     DEGRADED 标记——看门狗自己解除降级,违背"stays out of the way until
#     a human restarts"契约。代价是降级期间放弃内存防线,可接受:能进
#     degraded 说明服务级 restart 已失败一次,meow-c 多半已死/无救,真正
#     的内存压力不在它身上;panic_on_oom 仍是兜底。
mem_guard
[ "$?" = "10" ] && exit 0

# 有接管事实才有降级对象(不误伤:dns_redirect=0 / lan_proxy_mode=disabled /
# 纯 server 部署时,meow-c 死了也不影响 LAN,看门狗全程静默)。
# firewall.active 在 lan_proxy_mode=disabled 时也会被 init.d 置上(server
# accepts 需要它过 fw3 reload),故 stakes 判定必须同时看 lan_proxy_mode。
lan_proxy_mode=$(uci_get control.lan_proxy_mode); lan_proxy_mode=${lan_proxy_mode:-disabled}
stakes=0
bool_off "$lan_proxy_mode" || { [ -f "$RUN_DIR/firewall.active" ] && stakes=1; }
ls /tmp/dnsmasq.d/homeproxy_*.conf >/dev/null 2>&1 && stakes=1
[ "$stakes" = "0" ] && exit 0

# --- 状态机(§2.1.5;$STATE 是 tmpfs,重启自然清零)--------------------------
fails=0; restarts=0; healthy=0
# W1-5:键值解析而非 `. $STATE`——state 文件不再是可执行代码注入面。
state_get() { tr ' ' '\n' <"$STATE" 2>/dev/null | grep "^$1=" | head -n 1 | cut -d= -f2; }
if [ -f "$STATE" ]; then
	fails=$(state_get fails)
	restarts=$(state_get restarts)
	healthy=$(state_get healthy)
fi
case "$fails"    in ''|*[!0-9]*) fails=0    ;; esac
case "$restarts" in ''|*[!0-9]*) restarts=0 ;; esac
case "$healthy"  in ''|*[!0-9]*) healthy=0  ;; esac
write_state() { printf 'fails=%s restarts=%s healthy=%s\n' "$fails" "$restarts" "$healthy" >"$STATE" 2>/dev/null; }

p_ok=0; a_ok=0
if proc_running; then
	p_ok=1
	api_alive && a_ok=1
fi

if [ "$p_ok" = "1" ] && [ "$a_ok" = "1" ]; then
	# §2.1.4 自愈补充 + W1-1/W1-2:meow 活着 + flag 在,但"应在"的
	# PREROUTING 跳点已被 fw3 冲掉(include 未生效/被删)——当场重挂一次;
	# 不累计 fails。"应在"判定与 firewall.sh arm 决策同词表:
	#   proxy_mode=redirect          -> nat 的 homeproxy_redir_lanac
	#   proxy_mode=tproxy            -> mangle 的 homeproxy_mangle_lanac
	#                                    (仅 udp_want:main_udp_node!=nil 或 custom)
	#   redirect_tproxy/非法值收敛   -> 两者
	#   dns_redirect=1 且 dnsmasq 未自劫、端口有效 -> nat 的 homeproxy_dns
	# 按具体跳点名查:残留的 homeproxy_dns 不能冒充 redir 臂(W1-2);
	# 任一"应在却不在"即触发重挂,全在则不动。
	if ! bool_off "$lan_proxy_mode" && [ -f "$RUN_DIR/firewall.active" ] \
		&& command -v iptables >/dev/null 2>&1; then
		need_nat=0; need_mangle=0; need_dns=0
		proxy_mode=$(uci_get config.proxy_mode); proxy_mode=${proxy_mode:-redirect_tproxy}
		case "$proxy_mode" in
			redirect) need_nat=1 ;;
			tproxy)   need_mangle=1 ;;
			*)        need_nat=1; need_mangle=1 ;;   # redirect_tproxy + legacy/未知值收敛(firewall.sh 同款)
		esac
		main_udp_node=$(uci_get config.main_udp_node); main_udp_node=${main_udp_node:-nil}
		[ "$main_udp_node" = "nil" ] && [ "$routing_mode" != "custom" ] && need_mangle=0
		dns_redirect=$(uci_get infra.dns_redirect); dns_redirect=${dns_redirect:-1}
		if [ "$dns_redirect" = "1" ] \
			&& [ "$(uci -q get dhcp.@dnsmasq[0].dns_redirect 2>/dev/null)" != "1" ]; then
			dnsmasq_port=$(uci -q get dhcp.@dnsmasq[0].port 2>/dev/null); dnsmasq_port=${dnsmasq_port:-53}
			case "$dnsmasq_port" in
				''|*[!0-9]*) ;;
				*) [ "$dnsmasq_port" -gt 0 ] 2>/dev/null && need_dns=1 ;;
			esac
		fi
		missing=""
		[ "$need_nat" = "1" ] \
			&& ! iptables -t nat -S PREROUTING 2>/dev/null | grep -q ' -j homeproxy_redir_lanac' \
			&& missing="$missing redir(nat)"
		[ "$need_mangle" = "1" ] \
			&& ! iptables -t mangle -S PREROUTING 2>/dev/null | grep -q ' -j homeproxy_mangle_lanac' \
			&& missing="$missing tproxy(mangle)"
		[ "$need_dns" = "1" ] \
			&& ! iptables -t nat -S PREROUTING 2>/dev/null | grep -q ' -j homeproxy_dns' \
			&& missing="$missing dns(nat)"
		if [ -n "$missing" ]; then
			log "steering jump(s) missing ($missing ) while meow is alive -- re-applying firewall."
			# [C-B2-1] reload=stop_fw keep_ipsets+重建:此路径 firewall.active
			# 已在、meow 活着,仅跳点被 fw3 冲掉;start 会销毁 ipset 使
			# dnsmasq 已学动态成员蒸发。
			fw=$(resolve_fw) && {
				# 9>&-: 同上,reload 路径同样会 spawn NTP supervisor。
				out=$(sh "$fw" reload 2>&1 9>&-)
				[ -n "$out" ] && printf '%s\n' "$out" >>"$LOG_PATH" 2>/dev/null
			}
		fi
	fi
	fails=0
	healthy=$((healthy+1))
	# W1-7:连续 >=2 个健康 tick 才算走出本 episode,复位 restarts 允许
	# 下一次死亡 episode 再做一次服务级 restart。
	[ "$healthy" -ge 2 ] && restarts=0
	write_state
	exit 0
fi

fails=$((fails+1)); healthy=0
log "meow-c probe failed (proc=$([ "$p_ok" = "1" ] && echo up || echo down), api=$([ "$a_ok" = "1" ] && echo up || echo down)) fails=$fails restarts=$restarts"

if [ "$restarts" -eq 0 ] && [ "$fails" -ge "$FAILS_BEFORE_RESTART" ]; then
	INIT=""
	for f in /etc/init.d/homeproxy /data/other_vol/homeproxy/init.d/homeproxy; do
		[ -x "$f" ] && { INIT="$f"; break; }
	done
	log "meow-c dead for $fails consecutive ticks -- restarting service once."
	if [ -n "$INIT" ]; then
		# 必须直接 exec init 脚本本体(mem_restart_service 同款):rc.common
		# 靠 `#!/bin/sh /etc/rc.common` shebang 分发 start/stop/restart,
		# `sh script restart` 把 shebang 当注释 -> 只跑变量赋值,静默
		# no-op(2026-11 实测:此路径 restart 从未生效,死亡 episode 只能
		# 滑向 degrade)。9>&-:持锁 spawn 的服务链(最终到 ntp_responder
		# 的永生 supervisor)不得继承 hp_watchdog.lock。
		if command -v timeout >/dev/null 2>&1; then
			timeout 120 "$INIT" restart >>"$LOG_PATH" 2>&1 9>&-
		else
			# W1-4:无 timeout applet(busybox 可不提供)时规格允许裸跑。
			# init.d 若挂死会占住本 tick,但 degrade 子命令的
			# DEGRADE_LOCK_WAIT 上限仍保证止血可以插队执行。
			"$INIT" restart >>"$LOG_PATH" 2>&1 9>&-
		fi
	else
		log "WARN: no init script (/etc/init.d/homeproxy or /data/other_vol fallback); restart skipped."
	fi
	restarts=1
	fails=0
	write_state
	exit 0
fi

if [ "$restarts" -ge 1 ] && [ "$fails" -ge "$FAILS_BEFORE_DEGRADE" ]; then
	log "meow-c still dead $fails ticks after service restart -- degrading to direct-only."
	do_degrade
	rm -f "$STATE"
	exit 0
fi

write_state
exit 0
