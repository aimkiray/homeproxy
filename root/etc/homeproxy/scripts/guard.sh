#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# HomeProxy fail-open guard (MiWiFi port): watches the sing-box client
# instance; once procd has permanently given up respawning it, tear down
# the DNS hijack + iptables steering so the LAN degrades to plain direct
# access instead of staying black-holed.
#
# Deliberately a surgical teardown, NOT "init.d stop": a full stop would
# unregister the service and its service_triggers (interface.*.up -> reload
# self-healing). Keeping the service registered lets the next reload or
# restart re-arm the dataplane; the failopen.active marker records the
# degraded state for the updater's recovery-restart gate.

set -u

NAME="homeproxy"
HP_DIR="/etc/$NAME"
RUN_DIR="/var/run/$NAME"
LOG_PATH="$RUN_DIR/$NAME.log"
MARKER="$RUN_DIR/failopen.active"
INTERVAL=15
MISS_MAX=6

[ -f /etc/homeproxy/env.sh ] && . /etc/homeproxy/env.sh || true
HP_LIB_DIR="${HP_LIB_DIR:-/usr/lib/homeproxy}"

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

miss=0
while true; do
    if pgrep -f "sing-box run --config $RUN_DIR/sing-box-c.json" >/dev/null 2>&1; then
        miss=0
        if [ -f "$MARKER" ]; then
            rm -f "$MARKER"
            log "sing-box-c alive again while fail-open is active -- reloading service to re-arm DNS/steering."
            /etc/init.d/"$NAME" reload >/dev/null 2>&1 || true
            exit 0    # procd respawn replaces us (or procd_kill already did)
        fi
    else
        miss=$((miss + 1))
        if [ "$miss" -ge "$MISS_MAX" ] && { [ ! -f "$MARKER" ] \
            || [ -f "$RUN_DIR/firewall.active" ] \
            || ls /tmp/dnsmasq.d/homeproxy_*.conf >/dev/null 2>&1; }; then
            # Re-check once right before tearing down: shrinks the race window
            # against a concurrent (re)start that just spawned sing-box.
            if pgrep -f "sing-box run --config $RUN_DIR/sing-box-c.json" >/dev/null 2>&1; then
                miss=0
            else
                log "sing-box-c absent for ~$((miss * INTERVAL))s (procd gave up) -- failing open: removing DNS hijack + steering rules."
                rm -f "$RUN_DIR/firewall.active"                      # stop the fw3 include re-arming on next firewall reload FIRST
                if ls /tmp/dnsmasq.d/homeproxy_*.conf >/dev/null 2>&1; then
                    rm -f /tmp/dnsmasq.d/homeproxy_*.conf
                    /etc/init.d/dnsmasq restart >/dev/null 2>&1
                fi
                sh "$HP_LIB_DIR/firewall.sh" stop >>"$LOG_PATH" 2>&1
                : > "$MARKER"                                         # marker LAST: a guard killed mid-teardown leaves no marker and re-does it
                log "fail-open applied (marker: $MARKER); any homeproxy (re)start re-arms."
            fi
        fi
    fi
    sleep "$INTERVAL"
done
