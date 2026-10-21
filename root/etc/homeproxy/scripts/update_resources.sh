#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# HomeProxy resource list updater (MiWiFi port; uses lua+luci.json instead of
# jsonfilter which is unavailable on stock MiWiFi).

set -u

NAME="homeproxy"

# env.sh must be sourced BEFORE any mkdir: on MiWiFi the /etc/homeproxy
# symlink may not be restored yet when this runs (boot race), and mkdir-ing
# the standard paths first would create REAL ramfs dirs that then block the
# symlink forever (boot_restore.sh carries a merge branch just for that
# fallout). Dual-path fallback: after the symlinked location, try the
# script's own ../env.sh -- that reaches the persistent copy on
# /data/other_vol even while the symlink is still missing.
_self_dir=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd -P)
for _e in /etc/homeproxy/env.sh "$_self_dir/../env.sh"; do
    [ -f "$_e" ] && { . "$_e"; break; }
done
unset _e _self_dir

RESOURCES_DIR="${HP_RES_DIR:-/etc/$NAME/resources}"
RUN_DIR="/var/run/$NAME"
LOG_PATH="$RUN_DIR/$NAME.log"
mkdir -p "$RESOURCES_DIR" "$RUN_DIR"

log() {
    echo -e "$(date "+%Y-%m-%d %H:%M:%S") $*" >> "$LOG_PATH"
}

to_upper() { echo -e "$1" | tr "[a-z]" "[A-Z]"; }

# uci truth-table (same vocabulary as firewall.sh bool_on / init.d
# config_get_bool / install.sh): only {1,yes,on,true,enabled} are true;
# every other spelling -- including garbage values -- is false.
bool_on() {
    case "$1" in
        1|yes|on|true|enabled) return 0 ;;
        *) return 1 ;;
    esac
}

# Process probe: prefer pgrep -f; busybox builds may ship without it, so fall
# back to `ps w | grep` (bracket patterns keep grep from matching its own
# command line in the ps output). Same convention as install.sh/watchdog.sh.
proc_running() {
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -f "$1" >/dev/null 2>&1
    else
        ps w 2>/dev/null | grep -q "$1"
    fi
}

# update_via_proxy (homeproxy.subscription.update_via_proxy): fetch resource
# updates through the local meow mixed port, so routers whose upstreams are
# unreachable without the proxy (api.github.com / jsdelivr behind GFW) can
# still update. FAIL-CLOSED like update_subscriptions.lua's via_proxy path:
# a dead proxy never falls back to direct egress; failure logs carry
# $PROXY_NOTE so a dead mixed port is not misdiagnosed as an upstream fault.
PROXY=""
PROXY_NOTE=""
if bool_on "$(uci -q get "$NAME.subscription.update_via_proxy" 2>/dev/null)"; then
    mixed_port=$(uci -q get "$NAME.infra.mixed_port" 2>/dev/null); mixed_port=${mixed_port:-5330}
    # UCI may hold a dirty value (e.g. "abc", "53 30") -- fall back to default.
    case "$mixed_port" in ''|*[!0-9]*) mixed_port=5330 ;; esac
    PROXY="http://127.0.0.1:$mixed_port"
    PROXY_NOTE=" (via proxy 127.0.0.1:$mixed_port)"
fi

# HTTPS fetch. MiWiFi's busybox wget cannot do TLS (H8) -- prefer curl, which
# the installer pulls in; fall back to wget for standard OpenWrt builds.
fetch_url() {
    # $1=url [$2=extra header]
    # $PROXY set -> curl -x / wget proxy env; empty -> direct (unchanged).
    # ${PROXY:+-x "$PROXY"} field-splits into exactly two args ("-x" + URL);
    # safe because a 127.0.0.1:port URL never contains whitespace.
    if command -v curl >/dev/null 2>&1; then
        if [ -n "${2:-}" ]; then
            curl -fsSL --connect-timeout 10 --max-time 60 ${PROXY:+-x "$PROXY"} -H "$2" "$1" 2>/dev/null
        else
            curl -fsSL --connect-timeout 10 --max-time 60 ${PROXY:+-x "$PROXY"} "$1" 2>/dev/null
        fi
    elif [ -n "$PROXY" ]; then
        if [ -n "${2:-}" ]; then
            http_proxy="$PROXY" https_proxy="$PROXY" wget --timeout=30 -q --header="$2" -O- "$1" 2>/dev/null
        else
            http_proxy="$PROXY" https_proxy="$PROXY" wget --timeout=30 -q -O- "$1" 2>/dev/null
        fi
    elif [ -n "${2:-}" ]; then
        wget --timeout=30 -q --header="$2" -O- "$1" 2>/dev/null
    else
        wget --timeout=30 -q -O- "$1" 2>/dev/null
    fi
}

# parse GitHub commits API json with the on-device lua + luci.json
parse_verinfo() {
    lua -e '
-- luci.json (encode/decode) preferred; luci.jsonc (parse/stringify) fallback.
local ok, m = pcall(require, "luci.json")
if not ok then m = require("luci.jsonc") end
local decode = m.decode or function(s) return m.parse(s) end
local j = decode(io.read("*a"))
j = (j and j[1]) or {}
local msg = (j.commit and j.commit.message) or ""
local ver = (msg:match("[0-9%-]+") or ""):gsub("-", "")
io.write((j.sha or "") .. "\n" .. ver .. "\n")
'
}

check_list_update() {
    local listtype="$1"
    local listrepo="$2"
    local listref="$3"
    local listname="$4"
    local lock="$RUN_DIR/update_resources-$listtype.lock"
    local github_token auth_hdr
    github_token="$(uci -q get homeproxy.config.github_token)"
    # Quoting matters: the old code word-split an unquoted --header= arg, so
    # the token never actually reached GitHub. Pass the header as one arg.
    auth_hdr=""
    [ -z "$github_token" ] || auth_hdr="Authorization: Bearer $github_token"

    # Single-flight per list type. flock when available AND the lock file can
    # be opened; otherwise fall back to an atomic mkdir lock -- the same
    # pattern boot_restore.sh uses (U8-8). The `exec 200>` redirect would
    # abort the shell outright if RUN_DIR vanished mid-run, so re-create the
    # parent dir defensively before opening it.
    mkdir -p "$(dirname "$lock")" 2>/dev/null
    if command -v flock >/dev/null 2>&1 && exec 200>"$lock" 2>/dev/null; then
        if ! flock -n 200 2>/dev/null; then
            log "[$(to_upper "$listtype")] A task is already running."
            return 2
        fi
    elif ! mkdir "$lock.d" 2>/dev/null; then
        log "[$(to_upper "$listtype")] A task is already running."
        return 2
    else
        # Global (not local): the EXIT trap may fire after this function
        # returns, when the local `lock` is already out of scope.
        HP_RES_LOCKDIR="$lock.d"
        trap 'rm -rf "$HP_RES_LOCKDIR" 2>/dev/null' EXIT
    fi

    local list_info
    list_info="$(fetch_url "https://api.github.com/repos/$listrepo/commits?sha=$listref&path=$listname&per_page=1" "$auth_hdr")"
    [ -n "$list_info" ] || list_info="[]"
    printf '%s' "$list_info" | parse_verinfo > "$RUN_DIR/.verinfo_$listtype"
    local list_sha list_ver
    { read -r list_sha; read -r list_ver; } < "$RUN_DIR/.verinfo_$listtype"
    rm -f "$RUN_DIR/.verinfo_$listtype"

    if [ -z "$list_sha" ] || [ -z "$list_ver" ]; then
        log "[$(to_upper "$listtype")] Failed to get the latest version$PROXY_NOTE, please retry later."
        return 1
    fi

    local local_list_ver
    local_list_ver="$(cat "$RESOURCES_DIR/$listtype.ver" 2>/dev/null || echo NOT_FOUND)"
    if [ "$local_list_ver" = "$list_ver" ]; then
        log "[$(to_upper "$listtype")] Current version: $list_ver. Already up to date."
        return 3
    fi
    log "[$(to_upper "$listtype")] Local version: $local_list_ver, latest: $list_ver."

    if ! fetch_url "https://fastly.jsdelivr.net/gh/$listrepo@$list_sha/$listname" > "$RUN_DIR/$listname" || [ ! -s "$RUN_DIR/$listname" ]; then
        rm -f "$RUN_DIR/$listname"
        log "[$(to_upper "$listtype")] Update failed$PROXY_NOTE."
        return 1
    fi

    # china_list upstream ships "full:domain.tld" tags that the dnsmasq conf
    # generation would silently skip. Normalize BEFORE installing -- doing it
    # after the service restart below used to restart onto the unsanitized
    # file and left the cleanup one restart behind.
    if [ "$listtype" = "china_list" ]; then
        sed -i -e "s/full://g" -e "/:/d" "$RUN_DIR/$listname"
    fi
    if ! mv -f "$RUN_DIR/$listname" "$RESOURCES_DIR/$listtype.${listname##*.}"; then
        rm -f "$RUN_DIR/$listname"
        log "[$(to_upper "$listtype")] Update failed: could not install the list."
        return 1
    fi
    # Atomic .ver write (same-dir tmp + mv) so a crash never leaves a
    # half-written version file behind. Only write it after the data file
    # actually landed -- otherwise a failed install would look up-to-date.
    if ! { printf '%s\n' "$list_ver" > "$RESOURCES_DIR/.$listtype.ver.tmp" && \
        mv -f "$RESOURCES_DIR/.$listtype.ver.tmp" "$RESOURCES_DIR/$listtype.ver"; }; then
        log "[$(to_upper "$listtype")] WARNING: version file write failed; the update will be retried next run."
    fi
    log "[$(to_upper "$listtype")] Successfully updated."

    # The new list only takes effect after ipsets and the dnsmasq steering
    # confs are rebuilt; both happen inside a service restart. Only restart
    # when the proxy is actually running.
    if proc_running "[m]eow -f /var/run/homeproxy/meow-"; then
        /etc/init.d/"$NAME" restart >/dev/null 2>&1 && \
            log "[$(to_upper "$listtype")] Service restarted to apply new resources."
    fi
    return 0
}

case "${1:-}" in
"china_ip4")
    check_list_update "$1" "1715173329/IPCIDR-CHINA" "master" "ipv4.txt"
    ;;
"china_ip6")
    check_list_update "$1" "1715173329/IPCIDR-CHINA" "master" "ipv6.txt"
    ;;
"gfw_list")
    check_list_update "$1" "Loyalsoldier/v2ray-rules-dat" "release" "gfw.txt"
    ;;
"china_list")
    check_list_update "$1" "Loyalsoldier/v2ray-rules-dat" "release" "direct-list.txt"
    ;;
*)
    echo -e "Usage: $0 <china_ip4|china_ip6|gfw_list|china_list>"
    exit 1
    ;;
esac