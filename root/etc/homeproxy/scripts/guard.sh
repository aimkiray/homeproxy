#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# HomeProxy fail-open guard: watches the sing-box client instance; once
# procd has permanently given up respawning it, tear down the DNS hijack
# and fw4 steering so the LAN degrades to plain direct access instead of
# staying black-holed.
#
# Deliberately a surgical teardown, NOT "init.d stop": stopping the
# service would unregister it and its service_triggers (interface.*.up ->
# reload self-healing). Keeping the service registered lets the next
# reload/restart re-arm the dataplane; the failopen.active marker records
# the degraded state for update_resources.sh's recovery-restart gate.

set -u

NAME="homeproxy"
HP_DIR="/etc/$NAME"
RUN_DIR="/var/run/$NAME"
LOG_PATH="$RUN_DIR/$NAME.log"
MARKER="$RUN_DIR/failopen.active"
INTERVAL=15
MISS_MAX=6

log() {
	echo -e "$(date "+%Y-%m-%d %H:%M:%S") [GUARD] $*" >> "$LOG_PATH"
}

mkdir -p "$RUN_DIR"

# No pgrep -> every probe reads "absent" -> false fail-open teardown of a
# healthy dataplane. Disable the guard outright instead of spinning on it.
command -v pgrep >/dev/null 2>&1 || {
	log "pgrep unavailable, guard disabled"
	exit 1
}

alive() {
	pgrep -f "run --config $RUN_DIR/sing-box-c.json" >/dev/null 2>&1
}

# Re-derive the dnsmasq conf-dir exactly like init.d does.
dnsmasq_confdir() {
	local cfg
	cfg="$(uci -q show "dhcp.@dnsmasq[0]" | awk 'NR==1 {split($0, conf, /[.=]/); print conf[2]}')"
	if [ -n "$cfg" ] && [ -f "/tmp/etc/dnsmasq.conf.$cfg" ]; then
		awk -F '=' '/^conf-dir=/ {print $2; exit}' "/tmp/etc/dnsmasq.conf.$cfg"
	else
		echo "/tmp/dnsmasq.d"
	fi
}

armed() {
	local ddir
	ddir="$(dnsmasq_confdir)"
	[ -f "$ddir/dnsmasq-homeproxy.conf" ] && return 0
	# Count a dataplane as armed only if some homeproxy_* chain still has a
	# NON-EMPTY body -- stop/teardown leaves bare "chain x { }" declarations
	# behind, which must not retrigger teardown.
	nft list table inet fw4 2>/dev/null | awk '
		/chain homeproxy_/ { inside=1; next }
		inside && /^[[:space:]]*\}/ { inside=0; next }
		inside && NF { found=1 }
		END { exit(found?0:1) }'
}

teardown() {
	local table_mark tproxy_mark tun_mark tun_name ddir
	table_mark="$(uci -q get $NAME.infra.table_mark)"; table_mark="${table_mark:-100}"
	tproxy_mark="$(uci -q get $NAME.infra.tproxy_mark)"; tproxy_mark="${tproxy_mark:-101}"
	tun_mark="$(uci -q get $NAME.infra.tun_mark)"; tun_mark="${tun_mark:-102}"
	tun_name="$(uci -q get $NAME.infra.tun_name)"; tun_name="${tun_name:-singtun0}"

	# DNS hijack: remove the conf-dir pointer file and the fragment dir.
	ddir="$(dnsmasq_confdir)"
	rm -rf "$ddir/dnsmasq-homeproxy.conf" "$ddir/dnsmasq-homeproxy.d"
	/etc/init.d/dnsmasq restart >/dev/null 2>&1

	# fw4 steering: empty the three uci includes so the next render has no
	# homeproxy_* objects, reload to drop the jump references from base
	# chains, then remove whatever is left. Dynamic enumeration covers
	# chains the static list in stop_service misses (e.g. mangle_lanac).
	: > "$RUN_DIR/fw4_forward.nft"
	: > "$RUN_DIR/fw4_input.nft"
	: > "$RUN_DIR/fw4_post.nft"
	fw4 reload >/dev/null 2>&1
	nft list table inet fw4 2>/dev/null | grep -oE '(chain|set|map) homeproxy_[A-Za-z0-9_]+' | \
	while read -r _type _name; do
		nft flush "$_type" inet fw4 "$_name" 2>/dev/null
		nft delete "$_type" inet fw4 "$_name" 2>/dev/null
	done

	# Policy routing (tproxy + tun marks), drained like stop_service does.
	while ip rule del fwmark "$tproxy_mark" table "$table_mark" 2>/dev/null; do :; done
	ip route del local 0.0.0.0/0 dev lo table "$table_mark" 2>/dev/null
	while ip -6 rule del fwmark "$tproxy_mark" table "$table_mark" 2>/dev/null; do :; done
	ip -6 route del local ::/0 dev lo table "$table_mark" 2>/dev/null
	while ip rule del fwmark "$tun_mark" lookup "$table_mark" 2>/dev/null; do :; done
	while ip -6 rule del fwmark "$tun_mark" lookup "$table_mark" 2>/dev/null; do :; done
	ip route del default dev "$tun_name" table "$table_mark" 2>/dev/null
	ip -6 route del default dev "$tun_name" table "$table_mark" 2>/dev/null
	ip link set "$tun_name" down 2>/dev/null
	ip tuntap del mode tun name "$tun_name" 2>/dev/null
}

miss=0
while true; do
	if alive; then
		miss=0
		if [ -f "$MARKER" ]; then
			rm -f "$MARKER"
			log "sing-box-c alive again while fail-open is active -- reloading service to re-arm DNS/steering."
			/etc/init.d/"$NAME" reload >/dev/null 2>&1 || true
			exit 0	# procd respawn replaces us
		fi
	else
		miss=$((miss + 1))
		if [ "$miss" -ge "$MISS_MAX" ] && { [ ! -f "$MARKER" ] || armed; }; then
			# Re-check once right before tearing down: shrinks the race
			# window against a concurrent (re)start that just spawned
			# sing-box.
			if alive; then
				miss=0
			else
				log "sing-box-c absent for ~$((miss * INTERVAL))s (procd gave up) -- failing open: removing DNS hijack + steering."
				teardown
				# Marker LAST: a guard killed mid-teardown leaves no
				# marker and re-does it.
				: > "$MARKER"
				log "fail-open applied (marker: $MARKER); any homeproxy (re)start re-arms."
				miss=0
			fi
		fi
	fi
	sleep "$INTERVAL"
done
