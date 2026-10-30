#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# HomeProxy cron job: refresh resource lists and subscriptions.

set -u

SCRIPTS_DIR="/etc/homeproxy/scripts"
[ -f /etc/homeproxy/env.sh ] && . /etc/homeproxy/env.sh || true
LUA_DIR="${HP_LIB_DIR:-/usr/lib/homeproxy}"
export HP_LUAPATH="$LUA_DIR"

for i in "china_ip4" "china_ip6" "gfw_list" "china_list"; do
    "$SCRIPTS_DIR"/update_resources.sh "$i"
done

# Node-name migration must run before the updater: after a package upgrade
# the UCI may still carry old-style section names which the updater would
# treat as foreign and rebuild (losing the selected main_node). migrate
# commits UCI, so it runs under the shared writer lock (same protocol as
# cgi-bin/api / init.d / the CLI): skip it when a live writer holds it --
# the updater below acquires the same lock itself.
RUN_DIR=/var/run/homeproxy
LK_DIR="$RUN_DIR/uci-write.lock.d"
mkdir -p "$RUN_DIR" 2>/dev/null
held=0; i=0
while [ "$i" -lt 15 ]; do
    if mkdir "$LK_DIR" 2>/dev/null; then
        echo $$ >"$LK_DIR/pid" 2>/dev/null
        held=1; break
    fi
    p=$(cat "$LK_DIR/pid" 2>/dev/null)
    case "$p" in ''|*[!0-9]*) p= ;; esac
    if [ -n "$p" ]; then
        kill -0 "$p" 2>/dev/null || { rm -f "$LK_DIR/pid"; rmdir "$LK_DIR" 2>/dev/null; }
    else
        mt=$(stat -c %Y "$LK_DIR" 2>/dev/null) || mt=0
        [ "${mt:-0}" -gt 0 ] && [ $(($(date +%s) - mt)) -gt 120 ] && rmdir "$LK_DIR" 2>/dev/null
    fi
    i=$((i + 1))
    sleep 1
done
if [ "$held" = 1 ]; then
    lua "$LUA_DIR/migrate_config.lua" 2>/dev/null
    rm -f "$LK_DIR/pid"; rmdir "$LK_DIR" 2>/dev/null
fi
lua "$LUA_DIR/update_subscriptions.lua"