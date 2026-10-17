#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2025 ImmortalWrt.org

NAME="homeproxy"

RESOURCES_DIR="/etc/$NAME/resources"
mkdir -p "$RESOURCES_DIR"

RULESET_DIR="/etc/$NAME/ruleset"
mkdir -p "$RULESET_DIR"

RUN_DIR="/var/run/$NAME"
LOG_PATH="$RUN_DIR/$NAME.log"
mkdir -p "$RUN_DIR"

log() {
	echo -e "$(date "+%Y-%m-%d %H:%M:%S") $*" >> "$LOG_PATH"
}

to_upper() {
	echo -e "$1" | tr "[a-z]" "[A-Z]"
}

check_list_update() {
	local listtype="$1"
	local listrepo="$2"
	local listref="$3"
	local listname="$4"
	local destdir="${5:-$RESOURCES_DIR}"
	local destname="${6:-$listtype.${listname##*.}}"
	local lock="$RUN_DIR/update_resources-$listtype.lock"
	local github_token="$(uci -q get homeproxy.config.github_token)"
	local wget="wget --timeout=10 -q"

	exec 200>"$lock"
	if ! flock -n 200 &> "/dev/null"; then
		log "[$(to_upper "$listtype")] A task is already running."
		return 2
	fi

	[ -z "$github_token" ] || github_token="--header=Authorization: Bearer $github_token"
	local list_info="$($wget "${github_token:--q}" -O- "https://api.github.com/repos/$listrepo/commits?sha=$listref&path=$listname&per_page=1")"
	local list_sha="$(echo -e "$list_info" | jsonfilter -qe "@[0].sha")"
	local list_ver="$(echo -e "$list_info" | jsonfilter -qe "@[0].commit.message" | grep -Eo "[0-9-]+" | tr -d '-')"
	if [ -z "$list_sha" ] || [ -z "$list_ver" ]; then
		log "[$(to_upper "$listtype")] Failed to get the latest version, please retry later."
		return 1
	fi

	local local_list_ver="$(cat "$RESOURCES_DIR/$listtype.ver" 2>"/dev/null" || echo "NOT FOUND")"
	if [ "$local_list_ver" = "$list_ver" ]; then
		log "[$(to_upper "$listtype")] Current version: $list_ver."
		log "[$(to_upper "$listtype")] You're already at the latest version."
		return 3
	else
		log "[$(to_upper "$listtype")] Local version: $local_list_ver, latest version: $list_ver."
	fi

	if ! $wget "https://fastly.jsdelivr.net/gh/$listrepo@$list_sha/$listname" -O "$RUN_DIR/$listname" || [ ! -s "$RUN_DIR/$listname" ]; then
		rm -f "$RUN_DIR/$listname"
		log "[$(to_upper "$listtype")] Update failed."
		return 1
	fi

	# .srs payloads must carry the SRS magic; a truncated body or an HTML
	# error page must never be installed as a ruleset.
	case "$destname" in
	*.srs)
		if [ "$(dd if="$RUN_DIR/$listname" bs=3 count=1 2>/dev/null)" != "SRS" ]; then
			rm -f "$RUN_DIR/$listname"
			log "[$(to_upper "$listtype")] Update failed: not an SRS binary."
			return 1
		fi
		;;
	esac

	# china_list upstream ships "full:domain.tld" tags; normalize BEFORE
	# install so the restart below never lands on the unsanitized file.
	if [ "$listtype" = "china_list" ]; then
		sed -i -e "s/full://g" -e "/:/d" "$RUN_DIR/$listname"
	fi

	# Two-step install: cross-fs mv into a hidden temp name, then same-dir
	# rename -- the actually atomic step. An interrupted first mv leaves
	# only a ".*.tmp" stub that no reader matches.
	if ! { mv -f "$RUN_DIR/$listname" "$destdir/.$destname.tmp" && \
		mv -f "$destdir/.$destname.tmp" "$destdir/$destname"; }; then
		rm -f "$RUN_DIR/$listname" "$destdir/.$destname.tmp"
		log "[$(to_upper "$listtype")] Update failed: could not install the list."
		return 1
	fi
	# Atomic .ver write, after the data file actually landed.
	if ! { echo -e "$list_ver" > "$RESOURCES_DIR/.$listtype.ver.tmp" && \
		mv -f "$RESOURCES_DIR/.$listtype.ver.tmp" "$RESOURCES_DIR/$listtype.ver"; }; then
		log "[$(to_upper "$listtype")] WARNING: version file write failed; the update will be retried next run."
	fi
	log "[$(to_upper "$listtype")] Successfully updated."

	# New resources only take effect after a service restart. Only restart
	# when the proxy is actually running or the fail-open marker is set
	# (a restart also serves as the recovery re-arm path then).
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
	echo -e "Usage: $0 <china_ip4 / china_ip6 / gfw_list / china_list / geoip-cn / geosite-cn / geosite-noncn>"
	exit 1
	;;
esac
