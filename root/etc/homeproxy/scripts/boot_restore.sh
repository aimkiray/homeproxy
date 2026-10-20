#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Idempotent post-boot restorer for homeproxy on LuCI-less MiWiFi routers.
#
# Why this exists: '/' is squashfs (ro) and '/etc' is ramfs (volatile) -- every
# reboot wipes /etc/init.d/*, the /etc/homeproxy symlink, and /etc/profile.d.
# The backend (lib/scripts/web/resources), meow, and the patched init
# scripts all live on persistent /data/other_vol; and MiWiFi mirrors
# /etc/config + /etc/crontabs to /data/etc/ and restores them on boot, so the
# UCI config (lan_proxy_mode, subscription, main_node, firewall include) and
# the crontab already survive a reboot. The ONLY thing missing for auto-start
# is recreating the volatile /etc bits and starting the services -- which is
# exactly what this script does.
#
# Triggered from /data/auto_start.sh (MiWiFi's boot hook) and a low-frequency
# cron watchdog (defense-in-depth). Safe to run repeatedly: it only (re)starts
# the services in the same invocation that recreated the init scripts, so an
# intentional user stop (init scripts still present) is never overridden.

set -u
# Ensure cron/auto_start (minimal env) can find core utils + flock.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
HP=/data/other_vol/homeproxy
INITD=/etc/init.d
RUN=/var/run/homeproxy
LOG=$RUN/homeproxy.log
mkdir -p "$RUN" 2>/dev/null
log() { echo "$(date '+%H:%M:%S') [hp-restore] $*" >>"$LOG" 2>/dev/null; }

# Concurrency guard: auto_start + the cron tick can race on the same boot.
# BusyBox builds without the flock applet must not silently disable boot
# restore -- fall back to an atomic mkdir lock (H7).
if command -v flock >/dev/null 2>&1 && exec 9>/var/run/hp_restore.lock 2>/dev/null; then
	flock -n 9 2>/dev/null || { log "another restore in progress, exiting."; exit 0; }
elif ! mkdir /var/run/hp_restore.lock.d 2>/dev/null; then
	log "another restore in progress, exiting."; exit 0
else
	trap 'rmdir /var/run/hp_restore.lock.d 2>/dev/null' EXIT
fi

# 1. /etc/homeproxy symlink (resources + scripts resolve through it)
if [ -L /etc/homeproxy ]; then
	# Re-assert the link: it may exist but point at a wrong/stale target.
	ln -sfn "$HP" /etc/homeproxy 2>/dev/null
elif [ -d /etc/homeproxy ] && [ -d "$HP" ]; then
	# A REAL directory blocks the symlink: something like a premature
	# `mkdir -p /etc/homeproxy/resources` (update_resources.sh runs before
	# the restore on a boot race) created it, and the old `-e` check then
	# skipped the link forever. Merge contents in WITHOUT clobbering files
	# already on persistent storage -- `cp -a` would overwrite the
	# authoritative copies with stale ramfs ones.
	if (cd /etc/homeproxy && tar -cf - . 2>/dev/null) | (cd "$HP" && tar -xkf - 2>/dev/null); then
		log "merged stale /etc/homeproxy into $HP (existing files kept)"
	else
		log "WARN: could not merge stale /etc/homeproxy contents."
	fi
	rm -rf /etc/homeproxy
	ln -sfn "$HP" /etc/homeproxy 2>/dev/null
	log "replaced real /etc/homeproxy dir with symlink -> $HP"
elif [ ! -e /etc/homeproxy ]; then
	ln -sfn "$HP" /etc/homeproxy 2>/dev/null
	log "created /etc/homeproxy -> $HP"
fi

# 2. init.d scripts -> persistent patched copies on /data/other_vol
need_start=0
for s in homeproxy homeproxy-web; do
	if [ ! -e "$INITD/$s" ]; then
		[ -f "$HP/init.d/$s" ] || { log "missing $HP/init.d/$s -- skip."; continue; }
		ln -sfn "$HP/init.d/$s" "$INITD/$s" 2>/dev/null
		[ -x "$HP/init.d/$s" ] || chmod +x "$HP/init.d/$s" 2>/dev/null
		need_start=1
		log "recreated $INITD/$s"
	fi
done

# 3. PATH helper for interactive shells
if [ ! -e /etc/profile.d/homeproxy.sh ]; then
	mkdir -p /etc/profile.d 2>/dev/null
	printf 'export PATH="$PATH:/data/other_vol/bin:/data/other_vol/homeproxy/bin"\n' \
		> /etc/profile.d/homeproxy.sh 2>/dev/null
	log "created /etc/profile.d/homeproxy.sh"
fi

# 4. Start services ONLY when we just recreated the init scripts (post-reboot).
#    If the scripts already existed (normal runtime), do nothing -- respecting
#    any intentional stop the user made via the web UI / CLI.
if [ "$need_start" = 1 ]; then
	# Honor the same falsy vocabulary as config_get_bool (0|off|false|no|
	# disabled): a bare '= 0' test would restart the service even when the
	# user wrote 'off' (W3-1b).
	case "$(uci -q get homeproxy.config.enabled 2>/dev/null)" in
		0|false|no|off|disabled)
		# G5: master switch off -- restore the init scripts but leave the
		# service down. 'homeproxy enable' + 'homeproxy start' brings it back.
		log "homeproxy disabled (config.enabled falsy) -- init scripts restored, service NOT started."
		;;
		*)
		log "starting homeproxy + homeproxy-web."
		"$INITD/homeproxy" start >/dev/null 2>&1 || {
			rc=$?
			# rc=2 = "nothing to run" (nil outbound / enabled=0): a defined
			# no-op per G9, not a failure worth logging. rc=1 IS a real
			# failure -- only rc=2 stays silent (W3-1).
			[ "$rc" != "0" ] && [ "$rc" != "2" ] && log "homeproxy start returned $rc"
		}
		;;
	esac
	# homeproxy-web is NOT gated on config.enabled: it is the recovery channel.
	"$INITD/homeproxy-web" start >/dev/null 2>&1 || log "homeproxy-web start returned $?"
fi
