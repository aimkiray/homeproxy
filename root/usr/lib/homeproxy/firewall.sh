#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# HomeProxy firewall glue for legacy iptables (fw3) routers without nftables/fw4.
# Usage: firewall.sh {start|stop|restart|reload}
# Builds ipsets + iptables/ip6tables rules to steer LAN traffic into meow
# (TCP redirect, IPv4-only UDP tproxy, DNS hijack) honoring routing_mode and
# LAN control. meow owns NO firewall state (every listener is firewall:false);
# router-self egress is NOT intercepted (no OUTPUT hooks -- meow cannot mark
# proxy-adapter sockets, so OUTPUT capture risks an unbreakable loop), and no
# TUN arm exists anymore.

set -u

CFG=homeproxy
HP_DIR=/etc/homeproxy
RES_DIR="$HP_DIR/resources"
RUN_DIR=/var/run/homeproxy

uci_get() { uci -q get "$CFG.$1" 2>/dev/null; }

# --- config ---------------------------------------------------------------
routing_mode=$(uci_get "config.routing_mode"); routing_mode=${routing_mode:-bypass_mainland_china}
proxy_mode=$(uci_get "config.proxy_mode");      proxy_mode=${proxy_mode:-redirect_tproxy}
# meow vocabulary: redirect = TCP REDIRECT arm only; tproxy = UDP TPROXY arm
# only; redirect_tproxy = both. Legacy/unknown values (removed TUN modes,
# and the old "tproxy" = TCP+UDP-TPROXY meaning) degrade to redirect_tproxy,
# the strongest surviving combination. The formal migration is
# migrate_config's job; this is only the defensive fallback.
case "$proxy_mode" in
	redirect|tproxy|redirect_tproxy) ;;
	*)
		echo "homeproxy: WARNING: unknown/legacy proxy_mode='$proxy_mode' -- treating as redirect_tproxy." >&2
		proxy_mode=redirect_tproxy
		;;
esac
ipv6=$(uci_get "config.ipv6_support");          ipv6=${ipv6:-0}
routing_port=$(uci_get "config.routing_port")

redirect_port=$(uci_get "infra.redirect_port"); redirect_port=${redirect_port:-5331}
v6_port=$(uci_get "infra.v6_port");             v6_port=${v6_port:-5334}
tproxy_mark=$(uci_get "infra.tproxy_mark");     tproxy_mark=${tproxy_mark:-101}
table_mark=$(uci_get "infra.table_mark");       table_mark=${table_mark:-100}
self_mark=$(uci_get "infra.self_mark");         self_mark=${self_mark:-100}
common_port=$(uci_get "infra.common_port");     common_port=${common_port:-22,53,80,143,443,465,587,853,873,993,995,5222,8080,8443,9418}

lan_proxy_mode=$(uci_get "control.lan_proxy_mode"); lan_proxy_mode=${lan_proxy_mode:-disabled}
dns_redirect=$(uci_get "infra.dns_redirect"); dns_redirect=${dns_redirect:-1}

# LAN interface + subnet
# Interfaces to steer: control.listen_interfaces (UCI list) takes priority,
# otherwise auto-detect the LAN bridge. Only existing interfaces are used.
LAN_IFS=$(uci_get "control.listen_interfaces")
if [ -z "$LAN_IFS" ]; then
	lan_if=$(uci -q get network.lan.device 2>/dev/null); [ -z "$lan_if" ] && lan_if=$(uci -q get network.lan.ifname 2>/dev/null)
	# MiWiFi exposes bridge member lists (space separated) here; use the bridge.
	case "$lan_if" in
		*" "*|*"	"*) lan_if=br-lan ;;
	esac
	[ -z "$lan_if" ] && lan_if=br-lan
	[ -n "$lan_if" ] && ! ip link show "$lan_if" >/dev/null 2>&1 && lan_if=""
	LAN_IFS="$lan_if"
fi
# Keep only interfaces that actually exist.
LAN_IFS_EXIST=""
for _li in $LAN_IFS; do
	ip link show "$_li" >/dev/null 2>&1 && LAN_IFS_EXIST="$LAN_IFS_EXIST $_li"
done
LAN_IFS=$(echo $LAN_IFS_EXIST)

lan_ip=$(uci -q get network.lan.ipaddr 2>/dev/null)
lan_mask=$(uci -q get network.lan.netmask 2>/dev/null)
lan_net=""
if [ -n "$lan_ip" ] && [ -n "$lan_mask" ]; then
	lan_net=$(ipcalc.sh "$lan_ip" "$lan_mask" 2>/dev/null | awk -F= '/^NETWORK=/{n=$2}/^PREFIX=/{p=$2}END{if(n!=""&&p!="")print n"/"p}')
fi
[ -z "$lan_net" ] && lan_net="192.168.31.0/24"

# LAN IPv6 prefix (best-effort) for v6 skip rules; empty when ipv6 disabled.
lan_net6=""
if [ "$ipv6" = "1" ]; then
	for _li in $LAN_IFS; do
		lan_net6=$(ip -6 addr show "$_li" 2>/dev/null | awk '/inet6/ && $0 ~ /scope global/ {print $2; exit}')
		[ -n "$lan_net6" ] && break
	done
fi

list_ipv4() { uci_get "control.lan_proxy_ipv4_ips"; }
list_ipv6() { uci_get "control.lan_proxy_ipv6_ips"; }
list_mac()  { uci_get "control.lan_proxy_mac_addrs"; }
direct_ipv4() { uci_get "control.lan_direct_ipv4_ips"; }
direct_ipv6() { uci_get "control.lan_direct_ipv6_ips"; }
direct_mac()  { uci_get "control.lan_direct_mac_addrs"; }
wan_proxy_ipv4() { uci_get "control.wan_proxy_ipv4_ips"; }
wan_proxy_ipv6() { uci_get "control.wan_proxy_ipv6_ips"; }
wan_direct_ipv4() { uci_get "control.wan_direct_ipv4_ips"; }
wan_direct_ipv6() { uci_get "control.wan_direct_ipv6_ips"; }
lan_global_ipv4() { uci_get "control.lan_global_proxy_ipv4_ips"; }
lan_global_ipv6() { uci_get "control.lan_global_proxy_ipv6_ips"; }
lan_global_mac()  { uci_get "control.lan_global_proxy_mac_addrs"; }
lan_gaming_ipv4() { uci_get "control.lan_gaming_mode_ipv4_ips"; }
lan_gaming_ipv6() { uci_get "control.lan_gaming_mode_ipv6_ips"; }
lan_gaming_mac()  { uci_get "control.lan_gaming_mode_mac_addrs"; }

# dnsmasq listen port: the iptables DNS redirect forces clients using a custom
# DNS server back to local dnsmasq, which then applies the conf-dir steering
# rules (written by init.d). dnsmasq itself decides which domains go to
# meow's DNS; we never redirect DNS straight to meow here.
dnsmasq_port=$(uci -q get dhcp.@dnsmasq[0].port 2>/dev/null); dnsmasq_port=${dnsmasq_port:-53}
# A non-numeric or 0 port (dnsmasq DNS disabled) would emit a broken
# `--to-ports` REDIRECT -- cleared here, the DNS arm below then skips+warns.
case "$dnsmasq_port" in
	''|*[!0-9]*) dnsmasq_port="" ;;
	*) [ "$dnsmasq_port" -gt 0 ] 2>/dev/null || dnsmasq_port="" ;;
esac

IP4=iptables
IP6=ip6tables

# All chains we may have created -- including ones only older revisions emit
# (homeproxy_tun*/homeproxy_mangle_out/_mark from the removed TUN and
# TCP-TPROXY arms) -- so stop_fw can flush+delete them unconditionally.
ALL_CHAINS_NAT="homeproxy_dns homeproxy_redir homeproxy_redir_port homeproxy_redir_act homeproxy_redir_lanac"
ALL_CHAINS_MANGLE="homeproxy_mangle homeproxy_mangle_port homeproxy_mangle_act homeproxy_mangle_lanac homeproxy_mangle_mark homeproxy_mangle_out homeproxy_tun homeproxy_tun_mark homeproxy_tun_lanac"
ALL_IPSETS="homeproxy_cn4 homeproxy_cn6 homeproxy_gfw4 homeproxy_gfw6 homeproxy_wan_proxy4 homeproxy_wan_proxy6 homeproxy_wan_direct4 homeproxy_wan_direct6"

# --- teardown -------------------------------------------------------------
# One-shot cleanup of the removed TUN arm (D16). migrate_config writes the
# old infra.tun_name AND tun_mark as "name mark" into
# $RUN_DIR/legacy-tun-name before deleting the UCI keys (files written by
# older revisions carry the name alone -- the mark field is then absent).
# tun_mark/tun_table are gone from the schema, so they are resolved
# best-effort: a value still present in UCI (unmigrated config) wins, then
# the recorded mark, then the historical defaults. Runs on every
# start/stop/reload; everything is a no-op once clean.
cleanup_legacy_tun() {
	local tfile="$RUN_DIR/legacy-tun-name" tname="" tmark_file="" tmark ttable _t _n
	if [ -s "$tfile" ]; then
		set -- $(cat "$tfile" 2>/dev/null)
		tname=${1:-}
		tmark_file=${2:-}
	fi
	tmark=$(uci_get "infra.tun_mark");   tmark=${tmark:-${tmark_file:-102}}
	ttable=$(uci_get "infra.tun_table"); ttable=${ttable:-102}
	# Drain tun fwmark rules from BOTH tables: older revisions shared
	# table_mark for tun and tproxy rules before tun_table existed.
	for _t in "$ttable" "$table_mark"; do
		while ip rule del fwmark "$tmark" lookup "$_t" 2>/dev/null; do :; done
		while ip -6 rule del fwmark "$tmark" lookup "$_t" 2>/dev/null; do :; done
	done
	for _n in $tname singtun0; do
		[ -n "$_n" ] || continue
		ip link show "$_n" >/dev/null 2>&1 || continue
		ip route del default dev "$_n" table "$ttable" 2>/dev/null
		ip -6 route del default dev "$_n" table "$ttable" 2>/dev/null
		ip link set "$_n" down 2>/dev/null
		ip tuntap del mode tun name "$_n" 2>/dev/null || ip link del "$_n" 2>/dev/null
	done
	rm -f "$tfile"
}

# Remove every jump into homeproxy_* chains from the built-in chains (any
# table/hook/interface, including older revisions' OUTPUT and `-i lo`
# re-entry hooks), then flush+delete the chains, destroy the ipsets, drain
# the UDP-TPROXY policy routing and remove the legacy tun device -- in the
# spec cleanup order: chains -> ipsets -> ip rule/route -> tun device.
# Best-effort; missing rules/chains are ignored.
# $1 = "keep_ipsets" (fw3 reload path): the sets are rebuilt right after and
# dnsmasq still answers from its cache without re-adding learned entries, so
# destroying wan_proxy/wan_direct/gfw sets would drop dynamic domain steering
# until every name re-resolves.  Full start/stop destroys them as before.
stop_fw() {
	for ip in $IP4 $IP6; do
		# Remove every jump into our chains from the built-in chains, whatever
		# interface/proto or older revision created it. Deleting only for the
		# CURRENT LAN_IFS leaves orphan jumps behind when the interface was
		# renamed or the layout changed between runs.
		for tbl in nat mangle filter; do
			for hook in PREROUTING INPUT FORWARD OUTPUT; do
				$ip -t "$tbl" -S "$hook" 2>/dev/null | while read -r _line; do
					case "$_line" in
						*" -j homeproxy_"*)
							set -- $_line; shift  # drop "-A"
							$ip -t "$tbl" -D "$@" 2>/dev/null ;;
					esac
				done
			done
		done
		# Two passes: flush every chain (drops cross-chain jumps), then delete.
		for _ch in $ALL_CHAINS_NAT; do $ip -t nat -F "$_ch" 2>/dev/null; done
		for _ch in $ALL_CHAINS_NAT; do $ip -t nat -X "$_ch" 2>/dev/null; done
		for _ch in $ALL_CHAINS_MANGLE; do $ip -t mangle -F "$_ch" 2>/dev/null; done
		for _ch in $ALL_CHAINS_MANGLE; do $ip -t mangle -X "$_ch" 2>/dev/null; done
		$ip -F homeproxy_in 2>/dev/null;  $ip -X homeproxy_in 2>/dev/null
		$ip -F homeproxy_fwd 2>/dev/null; $ip -X homeproxy_fwd 2>/dev/null
	done
	[ "${1:-}" = "keep_ipsets" ] || {
		for _s in $ALL_IPSETS; do ipset destroy "$_s" 2>/dev/null; done
	}
	# UDP-TPROXY policy routing. The v6 rule/route drains cover what pre-meow
	# revisions installed for ipv6_support; `route flush` clears anything
	# left in the table (e.g. a stale tun default route sharing it).
	while ip rule del fwmark "$tproxy_mark" table "$table_mark" 2>/dev/null; do :; done
	while ip -6 rule del fwmark "$tproxy_mark" table "$table_mark" 2>/dev/null; do :; done
	ip route flush table "$table_mark" 2>/dev/null
	ip -6 route flush table "$table_mark" 2>/dev/null
	cleanup_legacy_tun
}

# --- filter-table accepts (mirror upstream firewall_pre.uc) -------------
# Self-contained: must also run when LAN steering is disabled (pure server
# deployments still need their listen ports accepted). Inserted at the TOP
# of INPUT because MiWiFi's own chains may end with a blanket REJECT/DROP
# that a tail-appended rule never reaches.
apply_fw_pre() {
	local ip="$1" need_in=0 sect
	for sect in $(uci -q show "$CFG" 2>/dev/null | sed -n "s/^homeproxy\.\([^.]*\)=server/\1/p"); do
		[ "$(uci -q get "$CFG.$sect.enabled")" = "1" ] && [ "$(uci -q get "$CFG.$sect.firewall")" = "1" ] && need_in=1
	done
	[ "$need_in" = "1" ] || return 0
	$ip -N homeproxy_in 2>/dev/null || $ip -F homeproxy_in
	for sect in $(uci -q show "$CFG" 2>/dev/null | sed -n "s/^homeproxy\.\([^.]*\)=server/\1/p"); do
		[ "$(uci -q get "$CFG.$sect.enabled")" = "1" ] || continue
		[ "$(uci -q get "$CFG.$sect.firewall")" = "1" ] || continue
		local port; port=$(uci -q get "$CFG.$sect.port"); [ -n "$port" ] || continue
		$ip -A homeproxy_in -p tcp --dport "$port" -j ACCEPT 2>/dev/null
		$ip -A homeproxy_in -p udp --dport "$port" -j ACCEPT 2>/dev/null
	done
	$ip -D INPUT -j homeproxy_in 2>/dev/null
	$ip -I INPUT -j homeproxy_in 2>/dev/null
}

cmd=${1:-}
[ "$cmd" = "stop" ] && { stop_fw; exit 0; }
# start AND restart both purge first: stale PREROUTING jumps bound to
# interfaces that were renamed/removed would otherwise keep steering the
# old iface into the rebuilt chains forever (hook_prerouting only -D's the
# CURRENT LAN_IFS).
# "reload" is what the fw3 include runs on firewall reloads: identical to
# start except the ipsets (and their dnsmasq-learned members) survive.
case "$cmd" in
	start|restart) stop_fw ;;
	reload)        stop_fw keep_ipsets ;;
	*) echo "usage: $0 {start|stop|restart|reload}" >&2; exit 2 ;;
esac

# Validate routing_mode (M18): unknown value silently proxies everything.
case "$routing_mode" in
	bypass_mainland_china|proxy_mainland_china|gfwlist|global|custom) ;;
	*)
		echo "homeproxy: invalid routing_mode='$routing_mode' -- aborting." >&2
		stop_fw; exit 1
		;;
esac

mkdir -p "$RUN_DIR"

# Server filter accepts must exist even with LAN steering off, so they are
# applied before the lan_proxy_mode gate.
apply_fw_pre "$IP4"
[ "$ipv6" = "1" ] && apply_fw_pre "$IP6"

if [ "$lan_proxy_mode" = "disabled" ]; then
	echo "homeproxy: LAN proxy disabled; only server filter accepts applied." >&2
	exit 0
fi

# Effective outbound the takeover arms would steer into (same source init.d
# uses): custom routes via routing.default_outbound, every other mode via
# config.main_node. nil == server-only deployment: installing the
# redirect/tproxy arms would blackhole LAN traffic into a nonexistent
# proxy, so warn and skip them (their mode ipsets are skipped too -- an
# empty-set abort must not tear down a pure-server box). The server filter
# accepts above and the dnsmasq DNS hijack below still run.
outbound_node=$(uci_get "config.main_node")
[ "$routing_mode" = "custom" ] && outbound_node=$(uci_get "routing.default_outbound")
outbound_node=${outbound_node:-nil}
if [ "$outbound_node" = "nil" ]; then
	echo "homeproxy: WARNING: no outbound configured (main_node/default_outbound=nil) -- LAN steering arms skipped; only server filter accepts + DNS hijack applied." >&2
fi

# --- ipsets ---------------------------------------------------------------
# Populate a temp set then swap it into place. ipset swap works even when the
# target is still referenced by live iptables rules (destroy would fail with
# EBUSY and the recreate with EEXIST), so `start` stays idempotent on re-run
# and across fw3 reloads.
build_ipset() {
	local name="$1" file="$2" fam="$3"
	local tmp="${name}_new"
	ipset destroy "$tmp" 2>/dev/null
	ipset create "$tmp" hash:net family "$fam" maxelem 65536 2>/dev/null || return 1
	if [ -n "$file" ] && [ -f "$file" ]; then
		awk -v n="$tmp" 'NF && !/^#/ {print "add "n" "$0}' "$file" 2>/dev/null | ipset restore -exist 2>/dev/null
	fi
	if ! ipset create "$name" hash:net family "$fam" maxelem 65536 -exist 2>/dev/null; then
		# -exist only succeeds for a same-type set: a stale set with a
		# different type/family must be replaced outright (rules were already
		# torn down by stop_fw, so destroy cannot hit EBUSY here).
		ipset destroy "$name" 2>/dev/null
		ipset create "$name" hash:net family "$fam" maxelem 65536 2>/dev/null \
			|| { ipset destroy "$tmp" 2>/dev/null; return 1; }
	fi
	ipset swap "$tmp" "$name" 2>/dev/null \
		|| { ipset destroy "$tmp" 2>/dev/null; return 1; }
	ipset destroy "$tmp" 2>/dev/null
}
# dynamic set (no file) -- dnsmasq populates it. -exist keeps entries on a
# re-apply instead of wiping what dnsmasq already learned.
build_ipset_empty() {
	local name="$1" fam="$2" type="${3:-hash:net}"
	ipset create "$name" "$type" family "$fam" maxelem 65536 -exist 2>/dev/null && return 0
	# A same-named set of a different type/family makes -exist fail: replace
	# it. Dynamic members are unusable under the wrong type anyway, and
	# missing the referenced rules entirely is worse than re-learning them.
	ipset destroy "$name" 2>/dev/null
	ipset create "$name" "$type" family "$fam" maxelem 65536 2>/dev/null || return 1
}
load_list_ipset() {
	# $1=ipset-name $2=family $3=space-separated-cidr-list
	# No flush: dnsmasq adds learned IPs to wan_proxy sets via ipset=/
	# directives and never re-adds answers already in its cache -- a flush
	# would drop those entries until the next fresh resolution. Stale static
	# entries linger until a full teardown, which is the safer trade-off.
	local name="$1" fam="$2" list="$3"
	build_ipset_empty "$name" "$fam" || return 1
	[ -n "$list" ] || return 0
	local cidr
	for cidr in $list; do ipset add -exist "$name" "$cidr" 2>/dev/null; done
}

if [ "$outbound_node" != "nil" ] && { [ "$routing_mode" = "bypass_mainland_china" ] || [ "$routing_mode" = "proxy_mainland_china" ]; }; then
	build_ipset homeproxy_cn4 "$RES_DIR/china_ip4.txt" inet || {
		echo "homeproxy: FATAL: failed to create CN ipset (ipset binary or kmod missing?). Aborting." >&2
		stop_fw; exit 1
	}
	if [ "$ipv6" = "1" ] && ! build_ipset homeproxy_cn6 "$RES_DIR/china_ip6.txt" inet6; then
		echo "homeproxy: WARNING: v6 CN ipset missing -- rules referencing it will not be installed (v6 falls through to the catch-all)." >&2
	fi
	cn_cnt=$(ipset list homeproxy_cn4 2>/dev/null | awk '/Number of entries/{print $4}')
	[ -z "$cn_cnt" ] && cn_cnt=0
	[ "$cn_cnt" -le 0 ] && {
		if [ "$routing_mode" = "bypass_mainland_china" ]; then
			echo "homeproxy: WARNING: CN ipset empty ($RES_DIR/china_ip4.txt) -- bypass_mainland_china will PROXY ALL traffic." >&2
		elif [ "$routing_mode" = "proxy_mainland_china" ]; then
			echo "homeproxy: FATAL: CN ipset empty -- proxy_mainland_china would PROXY NOTHING (all direct). Aborting." >&2
			stop_fw; exit 1
		fi
	}
	if [ "$ipv6" = "1" ]; then
		cn6_cnt=$(ipset list homeproxy_cn6 2>/dev/null | awk '/Number of entries/{print $4}')
		[ -z "$cn6_cnt" ] && cn6_cnt=0
		[ "$cn6_cnt" -le 0 ] && {
			if [ "$routing_mode" = "bypass_mainland_china" ]; then
				echo "homeproxy: WARNING: v6 CN ipset empty -- bypass_mainland_china will proxy all v6 traffic." >&2
			elif [ "$routing_mode" = "proxy_mainland_china" ]; then
				echo "homeproxy: WARNING: v6 CN ipset empty -- proxy_mainland_china will proxy no v6 traffic (all direct)." >&2
			fi
		}
	fi
fi

if [ "$outbound_node" != "nil" ] && [ "$routing_mode" = "gfwlist" ]; then
	# A missing gfw4 set is fatal, not just silent: the `! --match-set` RETURN
	# rule never installs, inverting gfwlist into proxy-everything.
	build_ipset_empty homeproxy_gfw4 inet hash:ip || {
		echo "homeproxy: FATAL: failed to create gfw ipset -- gfwlist cannot steer traffic. Aborting." >&2
		stop_fw; exit 1
	}
	if [ "$ipv6" = "1" ] && ! build_ipset_empty homeproxy_gfw6 inet6 hash:ip; then
		echo "homeproxy: WARNING: v6 gfw ipset missing -- v6 gfwlist rules will not be installed." >&2
	fi
	[ -s "$RES_DIR/gfw_list.txt" ] || \
		echo "homeproxy: WARNING: gfw_list.txt missing/empty -- gfwlist will proxy nothing (all direct)." >&2
fi

# wan_proxy / wan_direct: always created (even empty) so dnsmasq ipset= can
# populate wan_proxy dynamically from proxy_list.txt. A failed create leaves
# rules referencing the set uninstalled -- warn so the feature loss is visible.
load_list_ipset homeproxy_wan_proxy4 inet "$(wan_proxy_ipv4)" || \
	echo "homeproxy: WARNING: wan_proxy4 ipset missing -- always-proxy list rules disabled." >&2
if [ "$ipv6" = "1" ] && ! load_list_ipset homeproxy_wan_proxy6 inet6 "$(wan_proxy_ipv6)"; then
	echo "homeproxy: WARNING: wan_proxy6 ipset missing." >&2
fi
load_list_ipset homeproxy_wan_direct4 inet "$(wan_direct_ipv4)" || \
	echo "homeproxy: WARNING: wan_direct4 ipset missing -- always-direct list rules disabled." >&2
if [ "$ipv6" = "1" ] && ! load_list_ipset homeproxy_wan_direct6 inet6 "$(wan_direct_ipv6)"; then
	echo "homeproxy: WARNING: wan_direct6 ipset missing." >&2
fi

cnset4=homeproxy_cn4
cnset6=homeproxy_cn6
route_set4=""
route_set6=""
if [ "$routing_mode" = "bypass_mainland_china" ] || [ "$routing_mode" = "proxy_mainland_china" ]; then
	route_set4="$cnset4"; route_set6="$cnset6"
elif [ "$routing_mode" = "gfwlist" ]; then
	route_set4=homeproxy_gfw4; route_set6=homeproxy_gfw6
fi

# --- shared rule emitters -------------------------------------------------
# local/private destinations -> RETURN (mirrors upstream @homeproxy_local_addr).
# $1=ip $2=table $3=chain
emit_local() {
	local ip="$1" tbl="$2" ch="$3"
	$ip -t "$tbl" -A "$ch" -m conntrack --ctdir REPLY -j RETURN 2>/dev/null
	$ip -t "$tbl" -A "$ch" -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null
	if [ "$ip" = "$IP6" ]; then
		[ -n "$lan_net6" ] && $ip -t "$tbl" -A "$ch" -d "$lan_net6" -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d fc00::/7 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d fe80::/10 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d ::1/128 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d ff00::/8 -j RETURN 2>/dev/null
	else
		$ip -t "$tbl" -A "$ch" -d "$lan_net" -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 10.0.0.0/8 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 172.16.0.0/12 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 192.168.0.0/16 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 100.64.0.0/10 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 127.0.0.0/8 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 169.254.0.0/16 -j RETURN 2>/dev/null
		$ip -t "$tbl" -A "$ch" -d 224.0.0.0/3 -j RETURN 2>/dev/null
	fi
}

# routing-mode dst split: which destinations are direct (RETURN) before proxy.
# $1=ip $2=table $3=chain $4=rset (empty if none)
emit_routing() {
	local ip="$1" tbl="$2" ch="$3" rset="$4"
	case "$routing_mode" in
		bypass_mainland_china)
			[ -n "$rset" ] && $ip -t "$tbl" -A "$ch" -m set --match-set "$rset" dst -j RETURN 2>/dev/null ;;
		proxy_mainland_china)
			[ -n "$rset" ] && $ip -t "$tbl" -A "$ch" -m set ! --match-set "$rset" dst -j RETURN 2>/dev/null ;;
		gfwlist)
			[ -n "$rset" ] && $ip -t "$tbl" -A "$ch" -m set ! --match-set "$rset" dst -j RETURN 2>/dev/null ;;
	esac
}

# destination ipset match -> target. $1=ip $2=table $3=chain $4=kind(wan_proxy|wan_direct) $5=target
emit_dst_ipset() {
	local ip="$1" tbl="$2" ch="$3" kind="$4" tgt="$5" set4="" set6=""
	if [ "$kind" = "wan_proxy" ]; then set4=homeproxy_wan_proxy4; set6=homeproxy_wan_proxy6
	elif [ "$kind" = "wan_direct" ]; then set4=homeproxy_wan_direct4; set6=homeproxy_wan_direct6
	else return 0; fi
	# Family-correct: an inet6 set can never match under iptables (and vice
	# versa) -- emitting both leaves dead rules and spurious set references.
	if [ "$ip" = "$IP6" ]; then
		$ip -t "$tbl" -A "$ch" -m set --match-set "$set6" dst -j "$tgt" 2>/dev/null
	else
		$ip -t "$tbl" -A "$ch" -m set --match-set "$set4" dst -j "$tgt" 2>/dev/null
	fi
}

# source-list match (ipv4 list + ipv6 list + mac) -> target.
# $1=ip $2=table $3=chain $4=kind(lan_global|lan_gaming) $5=target
emit_src_list() {
	local ip="$1" tbl="$2" ch="$3" kind="$4" tgt="$5" v4 v6 mac
	if [ "$kind" = "lan_global" ]; then v4=$(lan_global_ipv4); v6=$(lan_global_ipv6); mac=$(lan_global_mac)
	else v4=$(lan_gaming_ipv4); v6=$(lan_gaming_ipv6); mac=$(lan_gaming_mac); fi
	if [ "$ip" = "$IP6" ]; then
		local d; for d in $v6; do $ip -t "$tbl" -A "$ch" -s "$d" -j "$tgt" 2>/dev/null; done
	else
		local d; for d in $v4; do $ip -t "$tbl" -A "$ch" -s "$d" -j "$tgt" 2>/dev/null; done
	fi
	local d; for d in $mac; do $ip -t "$tbl" -A "$ch" -m mac --mac-source "$d" -j "$tgt" 2>/dev/null; done
}

# Build the steering chain (homeproxy_redir / homeproxy_mangle). Jumped to
# only from the per-client PREROUTING gate (there is no OUTPUT steering).
# Order mirrors the historical layout:
#   self_mark -> wan_proxy -> local -> lan_global -> wan_direct -> routing
#   -> gaming -> catch-all(port-filtered)
# $1=ip $2=table $3=chain $4=rset $5=port_target $6=act_target
emit_steering() {
	local ip="$1" tbl="$2" ch="$3" rset="$4" port_tgt="$5" act_tgt="$6"
	$ip -t "$tbl" -N "$ch" 2>/dev/null || $ip -t "$tbl" -F "$ch"
	# mark exemption: never steer packets already stamped with self_mark.
	# meow's routing-mark tags only DIRECT outbound sockets (which never
	# reach PREROUTING anyway); the rule still protects forwarded traffic
	# whose fwmark was connmark-restored. Exact match -- a masked match
	# (100/100) also matches marks that merely have those bits set
	# (101, 102, QoS marks...), exempting real traffic.
	$ip -t "$tbl" -A "$ch" -m mark --mark "$self_mark" -j RETURN 2>/dev/null
	# "always proxy" destinations/clients go to the UNFILTERED target:
	# under routing_port=common the port-filtered target would only proxy
	# well-known ports, which is not what an explicit always-proxy list means.
	emit_dst_ipset "$ip" "$tbl" "$ch" wan_proxy "$act_tgt"
	emit_local "$ip" "$tbl" "$ch"
	if [ "$routing_mode" != "custom" ]; then
		emit_src_list "$ip" "$tbl" "$ch" lan_global "$act_tgt"
	fi
	emit_dst_ipset "$ip" "$tbl" "$ch" wan_direct RETURN
	emit_routing "$ip" "$tbl" "$ch" "$rset"
	# Block QUIC over UDP/80,443 so clients fall back to TCP (steered above).
	# mangle has no REJECT, so DROP. Only bypass/gfwlist; upstream lets QUIC
	# reach the proxy in proxy_mainland_china & custom. Only emitted while
	# the UDP arm exists (the mangle chain is built solely for UDP TPROXY)
	# and only under iptables -- v6 UDP is never steered.
	if [ "$tbl" = "mangle" ] && { [ "$routing_mode" = "bypass_mainland_china" ] || [ "$routing_mode" = "gfwlist" ]; }; then
		$ip -t "$tbl" -A "$ch" -p udp -m multiport --dports 80,443 -j DROP 2>/dev/null
	fi
	emit_src_list "$ip" "$tbl" "$ch" lan_gaming "$act_tgt"
	$ip -t "$tbl" -A "$ch" -j "$port_tgt"
}

# Build the per-client gate (lanac). PREROUTING jumps here.
# $1=ip $2=table $3=chain(gate) $4=steering_target
emit_gate() {
	local ip="$1" tbl="$2" ch="$3" tgt="$4"
	$ip -t "$tbl" -N "$ch" 2>/dev/null || $ip -t "$tbl" -F "$ch"
	# mark exemption (same self_mark reasoning as the steering chain).
	$ip -t "$tbl" -A "$ch" -m mark --mark "$self_mark" -j RETURN 2>/dev/null
	# do not steer DNS over UDP here -- the nat-table homeproxy_dns handles it.
	[ "$tbl" = "mangle" ] && $ip -t "$tbl" -A "$ch" -p udp --dport 53 -j RETURN 2>/dev/null
	if [ "$lan_proxy_mode" = "listed_only" ]; then
		local src_list d
		if [ "$ip" = "$IP6" ]; then src_list=$(list_ipv6); else src_list=$(list_ipv4); fi
		for d in $src_list; do $ip -t "$tbl" -A "$ch" -s "$d" -j "$tgt" 2>/dev/null; done
		for d in $(list_mac); do $ip -t "$tbl" -A "$ch" -m mac --mac-source "$d" -j "$tgt" 2>/dev/null; done
		# not listed -> direct (chain ends, implicit RETURN)
	elif [ "$lan_proxy_mode" = "except_listed" ]; then
		local dlist d
		if [ "$ip" = "$IP6" ]; then dlist=$(direct_ipv6); else dlist=$(direct_ipv4); fi
		for d in $dlist; do $ip -t "$tbl" -A "$ch" -s "$d" -j RETURN 2>/dev/null; done
		for d in $(direct_mac); do $ip -t "$tbl" -A "$ch" -m mac --mac-source "$d" -j RETURN 2>/dev/null; done
		$ip -t "$tbl" -A "$ch" -j "$tgt"            # proxy everyone else
	else   # global / only_proxy
		$ip -t "$tbl" -A "$ch" -j "$tgt"
	fi
}

# Hook a PREROUTING jump for every LAN interface. $1=ip $2=table $3=proto-args $4=chain
hook_prerouting() {
	local ip="$1" tbl="$2" proto="$3" ch="$4" li
	for li in $LAN_IFS; do
		$ip -t "$tbl" -D PREROUTING -i "$li" $proto -j "$ch" 2>/dev/null
		$ip -t "$tbl" -A PREROUTING -i "$li" $proto -j "$ch" 2>/dev/null
	done
}

# --- TCP redirect (nat) ----------------------------------------------------
# $3 = REDIRECT target port: redirect_port for IPv4, v6_port for IPv6 (each
# family is delivered to its own meow tproxy listener; chain names are shared
# because iptables/ip6tables have independent namespaces).
apply_tcp() {
	local ip="$1" rset="$2" rport="$3"
	# action (no port filter) -- used by gaming src rule
	$ip -t nat -N homeproxy_redir_act 2>/dev/null || $ip -t nat -F homeproxy_redir_act
	$ip -t nat -A homeproxy_redir_act -p tcp -j REDIRECT --to-ports "$rport"
	# port-filtered action -- used by catch-all / wan_proxy / lan_global
	$ip -t nat -N homeproxy_redir_port 2>/dev/null || $ip -t nat -F homeproxy_redir_port
	if [ "$routing_port" = "common" ]; then
		$ip -t nat -A homeproxy_redir_port -p tcp -m multiport --dports "$common_port" -j homeproxy_redir_act 2>/dev/null
	else
		$ip -t nat -A homeproxy_redir_port -p tcp -j homeproxy_redir_act
	fi
	# steering chain
	emit_steering "$ip" nat homeproxy_redir "$rset" homeproxy_redir_port homeproxy_redir_act
	# gate + PREROUTING hook
	emit_gate "$ip" nat homeproxy_redir_lanac homeproxy_redir
	hook_prerouting "$ip" nat "-p tcp" homeproxy_redir_lanac
}

# --- UDP tproxy (mangle, IPv4 only) ---------------------------------------
# UDP arm: TPROXY delivers to the SAME port TCP REDIRECT uses -- the single
# meow tproxy listener (redirect_port, udp:true). Requires the fwmark -> lo
# policy route (installed before this runs). --tproxy-mark uses a FULL mask:
# a partial mask preserves unrelated mark bits (e.g. MiWiFi QoS), producing a
# composite fwmark the exact-match `ip rule fwmark $tproxy_mark` then fails
# to route -> leaked/dropped traffic. IPv4 only: meow has no v6 UDP TPROXY,
# so ip6tables never gets a mangle rule (v6 UDP/QUIC stays direct).
apply_tproxy() {
	local ip="$1" rset="$2"
	$ip -t mangle -N homeproxy_mangle_act 2>/dev/null || $ip -t mangle -F homeproxy_mangle_act
	$ip -t mangle -A homeproxy_mangle_act -p udp -j TPROXY --on-ip 0.0.0.0 --on-port "$redirect_port" --tproxy-mark "$tproxy_mark/0xffffffff"
	$ip -t mangle -N homeproxy_mangle_port 2>/dev/null || $ip -t mangle -F homeproxy_mangle_port
	if [ "$routing_port" = "common" ]; then
		$ip -t mangle -A homeproxy_mangle_port -p udp -m multiport --dports "$common_port" -j homeproxy_mangle_act 2>/dev/null
	else
		$ip -t mangle -A homeproxy_mangle_port -p udp -j homeproxy_mangle_act
	fi
	emit_steering "$ip" mangle homeproxy_mangle "$rset" homeproxy_mangle_port homeproxy_mangle_act
	emit_gate "$ip" mangle homeproxy_mangle_lanac homeproxy_mangle
	hook_prerouting "$ip" mangle "-p udp" homeproxy_mangle_lanac
}

# --- DNS redirect (nat) ----------------------------------------------------
# Force clients using a custom DNS server back to local dnsmasq (port 53),
# which applies the per-routing_mode conf-dir rules written by init.d. We do
# NOT redirect straight to meow: dnsmasq owns the domain split + ipset
# population. Skipped when the user disables it or dnsmasq already hijacks.
apply_dns() {
	local ip="$1" target="$2"
	$ip -t nat -N homeproxy_dns 2>/dev/null || $ip -t nat -F homeproxy_dns
	emit_local "$ip" nat homeproxy_dns
	$ip -t nat -A homeproxy_dns -p udp --dport 53 -j REDIRECT --to-ports "$target"
	hook_prerouting "$ip" nat "-p udp --dport 53" homeproxy_dns
}

# --- apply per arm ----------------------------------------------------------
# UDP is only steered when the user wants UDP proxied (a dedicated UDP node
# or custom routing) -- the same condition that sets `udp:true` on the meow
# tproxy listener -- AND proxy_mode carries the tproxy arm. TCP never uses
# TPROXY (REDIRECT covers it), IPv6 UDP is never intercepted, and router-self
# traffic is never intercepted (no OUTPUT hooks exist).
main_udp_node=$(uci_get "config.main_udp_node"); main_udp_node=${main_udp_node:-nil}
udp_want=0
if [ "$main_udp_node" != "nil" ] || [ "$routing_mode" = "custom" ]; then
	udp_want=1
fi
udp_arm=0
case "$proxy_mode" in
	tproxy|redirect_tproxy) [ "$udp_want" = "1" ] && udp_arm=1 ;;
esac

# Takeover arms run only with a real outbound; server-only already warned.
if [ "$outbound_node" != "nil" ]; then
	case "$proxy_mode" in
		redirect|redirect_tproxy)
			apply_tcp "$IP4" "$route_set4" "$redirect_port"
			[ "$ipv6" = "1" ] && apply_tcp "$IP6" "$route_set6" "$v6_port"
			;;
		tproxy)
			[ "$udp_arm" = "1" ] || echo "homeproxy: WARNING: proxy_mode=tproxy but no UDP steering is configured (main_udp_node=nil, non-custom routing_mode) -- no traffic will be proxied." >&2
			;;
	esac
	if [ "$udp_arm" = "1" ]; then
		# fwmark -> lo local delivery for TPROXYed UDP (IPv4 only -- no v6 rule
		# or route is ever added). Install BEFORE the marking rules so freshly
		# marked packets always resolve to the listener.
		ip rule add fwmark "$tproxy_mark" table "$table_mark" pref 100 2>/dev/null
		ip route add local 0.0.0.0/0 dev lo table "$table_mark" 2>/dev/null
		apply_tproxy "$IP4" "$route_set4"
	fi
fi

# DNS redirect to dnsmasq (which steers via conf-dir). Skipped when the user
# disables it or dnsmasq already hijacks DNS, to avoid a double redirect.
dns_hijacked=0
[ "$(uci -q get dhcp.@dnsmasq[0].dns_redirect 2>/dev/null)" = "1" ] && dns_hijacked=1
if [ "$dns_redirect" = "1" ] && [ "$dns_hijacked" != "1" ]; then
	if [ -n "$dnsmasq_port" ]; then
		apply_dns "$IP4" "$dnsmasq_port"
		[ "$ipv6" = "1" ] && apply_dns "$IP6" "$dnsmasq_port"
	else
		echo "homeproxy: WARNING: dnsmasq port is unset/0/non-numeric -- DNS redirect arm skipped." >&2
	fi
else
	echo "homeproxy: DNS redirect skipped (dns_redirect=$dns_redirect dnsmasq_hijacked=$dns_hijacked)." >&2
fi

if [ -z "$LAN_IFS" ]; then
	echo "homeproxy: WARNING: no LAN interface found; no LAN traffic will be steered." >&2
fi

echo "homeproxy: firewall rules applied (mode=$proxy_mode routing=$routing_mode lan=$lan_proxy_mode ifaces=$LAN_IFS)." >&2
exit 0
