#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# HomeProxy resource list updater (MiWiFi port; uses lua+luci.json instead of
# jsonfilter which is unavailable on stock MiWiFi).

NAME="homeproxy"

RESOURCES_DIR="/etc/$NAME/resources"
mkdir -p "$RESOURCES_DIR"

RULESET_DIR="/etc/$NAME/ruleset"
mkdir -p "$RULESET_DIR"

RUN_DIR="/var/run/$NAME"
LOG_PATH="$RUN_DIR/$NAME.log"
mkdir -p "$RUN_DIR"

[ -f /etc/homeproxy/env.sh ] && . /etc/homeproxy/env.sh
HP_LIB_DIR="${HP_LIB_DIR:-/usr/lib/homeproxy}"

log() {
    echo -e "$(date "+%Y-%m-%d %H:%M:%S") $*" >> "$LOG_PATH"
}

to_upper() { echo -e "$1" | tr "[a-z]" "[A-Z]"; }

# HTTPS fetch. MiWiFi's busybox wget cannot do TLS (H8) -- prefer curl, which
# the installer pulls in; fall back to wget for standard OpenWrt builds.
fetch_url() {
    # $1=url [$2=extra header]
    if command -v curl >/dev/null 2>&1; then
        if [ -n "${2:-}" ]; then
            curl -fsSL --connect-timeout 10 --max-time 60 -H "$2" "$1" 2>/dev/null
        else
            curl -fsSL --connect-timeout 10 --max-time 60 "$1" 2>/dev/null
        fi
    else
        if [ -n "${2:-}" ]; then
            wget --timeout=30 -q --header="$2" -O- "$1" 2>/dev/null
        else
            wget --timeout=30 -q -O- "$1" 2>/dev/null
        fi
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
    local destdir="${5:-$RESOURCES_DIR}"
    local destname="${6:-$listtype.${listname##*.}}"
    local lock="$RUN_DIR/update_resources-$listtype.lock"
    local github_token auth_hdr
    github_token="$(uci -q get homeproxy.config.github_token)"
    # Quoting matters: the old code word-split an unquoted --header= arg, so
    # the token never actually reached GitHub. Pass the header as one arg.
    auth_hdr=""
    [ -z "$github_token" ] || auth_hdr="Authorization: Bearer $github_token"

    if command -v flock >/dev/null 2>&1; then
        exec 200>"$lock"
        if ! flock -n 200 2>/dev/null; then
            log "[$(to_upper "$listtype")] A task is already running."
            return 2
        fi
    fi

    local list_info
    list_info="$(fetch_url "https://api.github.com/repos/$listrepo/commits?sha=$listref&path=$listname&per_page=1" "$auth_hdr")"
    [ -n "$list_info" ] || list_info="[]"
    printf '%s' "$list_info" | parse_verinfo > "$RUN_DIR/.verinfo_$listtype"
    local list_sha list_ver
    { read -r list_sha; read -r list_ver; } < "$RUN_DIR/.verinfo_$listtype"
    rm -f "$RUN_DIR/.verinfo_$listtype"

    if [ -z "$list_sha" ] || [ -z "$list_ver" ]; then
        log "[$(to_upper "$listtype")] Failed to get the latest version, please retry later."
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
        log "[$(to_upper "$listtype")] Update failed."
        return 1
    fi

    # .srs payloads must carry the SRS magic (0x53 0x52 0x53); a truncated
    # body or an HTML error page must never be installed as a ruleset.
    case "$destname" in
    *.srs)
        if [ "$(dd if="$RUN_DIR/$listname" bs=3 count=1 2>/dev/null)" != "SRS" ]; then
            rm -f "$RUN_DIR/$listname"
            log "[$(to_upper "$listtype")] Update failed: not an SRS binary."
            return 1
        fi
        ;;
    esac

    # china_list upstream ships "full:domain.tld" tags that the dnsmasq conf
    # generation would silently skip. Normalize BEFORE installing -- doing it
    # after the service restart below used to restart onto the unsanitized
    # file and left the cleanup one restart behind.
    if [ "$listtype" = "china_list" ]; then
        sed -i -e "s/full://g" -e "/:/d" "$RUN_DIR/$listname"
    fi
    if ! mv -f "$RUN_DIR/$listname" "$destdir/$destname"; then
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
    if pgrep -f "sing-box run --config" >/dev/null 2>&1 || [ -f "$RUN_DIR/failopen.active" ]; then
        /etc/init.d/"$NAME" restart >/dev/null 2>&1 && \
            log "[$(to_upper "$listtype")] Service restarted to apply new resources."
    fi
    return 0
}

case "$1" in
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
"geoip-cn")
    check_list_update "$1" "1715173329/IPCIDR-CHINA" "rule-set" "cn.srs" "$RULESET_DIR" "geoip-cn.srs"
    ;;
"geosite-cn")
    check_list_update "$1" "1715173329/sing-geosite" "rule-set-unstable" "geosite-geolocation-cn.srs" "$RULESET_DIR" "geosite-cn.srs"
    ;;
"geosite-noncn")
    check_list_update "$1" "1715173329/sing-geosite" "rule-set-unstable" "geosite-geolocation-!cn.srs" "$RULESET_DIR" "geosite-noncn.srs"
    ;;
*)
    echo -e "Usage: $0 <china_ip4|china_ip6|gfw_list|china_list|geoip-cn|geosite-cn|geosite-noncn>"
    exit 1
    ;;
esac