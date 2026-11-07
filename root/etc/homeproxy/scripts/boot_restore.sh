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
else
	# flock-less fallback: atomic mkdir + pid/mtime stale-reclaim (a killed
	# restore cannot auto-release a dir lock -- same protocol as init.d's
	# uci-write.lock.d: a live holder pid wins, a dead pid reclaims at once,
	# a pid-less lock falls back to a 120s mtime).
	_lkd=/var/run/hp_restore.lock.d
	_try=0
	while [ "$_try" -lt 2 ]; do
		mkdir "$_lkd" 2>/dev/null && break
		# '0' is dirty: kill -0 0 probes our own process group and always
		# succeeds -> a 0-pid lock would read as held forever.
		_p=$(cat "$_lkd/pid" 2>/dev/null); case "$_p" in ''|0|*[!0-9]*) _p= ;; esac
		_ino=$(stat -c %i "$_lkd" 2>/dev/null)
		_mt=$(stat -c %Y "$_lkd" 2>/dev/null) || _mt=0
		_stale=0
		if [ -n "$_p" ]; then
			kill -0 "$_p" 2>/dev/null && { log "another restore in progress, exiting."; exit 0; }
			_stale=1
		elif [ -z "$_ino" ] || [ "${_mt:-0}" -eq 0 ]; then
			_stale=0   # stat inconclusive -> retry, do NOT reclaim (fail-closed)
		elif [ $(($(date +%s) - _mt)) -le 120 ]; then
			log "another restore in progress, exiting."; exit 0
		else
			_stale=1
		fi
		# Reclaim only the exact dir judged stale: a lockdir recreated by a
		# racing holder carries a different inode.
		[ "$_stale" = "1" ] && [ "$(stat -c %i "$_lkd" 2>/dev/null)" = "$_ino" ] \
			&& { rm -f "$_lkd/pid" 2>/dev/null; rmdir "$_lkd" 2>/dev/null; }
		_try=$((_try + 1))
	done
	[ "$_try" -ge 2 ] && { log "another restore in progress, exiting."; exit 0; }
	echo $$ >"$_lkd/pid" 2>/dev/null
	trap 'rm -f "$_lkd/pid" 2>/dev/null; rmdir "$_lkd" 2>/dev/null' EXIT
	# An untrapped SIGTERM/SIGINT skips the EXIT trap in ash -- re-raise as
	# exit so the lockdir is released. SIGKILL still stale-locks: covered by
	# the dead-pid reclaim above.
	trap 'exit 143' TERM; trap 'exit 130' INT
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

# 1b. Re-assert exec bits on every tick: a deploy via `cat >/tmp + mv`
#     silently strips +x (umask 0644), and the watchdog cron's `[ -x ]`
#     gate then no-ops with zero symptoms -- watchdog was dead 49h before
#     anyone noticed (2026-11). Cheap self-heal; harmless if already 755.
chmod +x "$HP"/scripts/*.sh "$HP"/lib/firewall.sh "$HP"/init.d/* 2>/dev/null

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
		# 9>&-: never leak the restore-lock fd into service children -- a
		# lingering descendant would hold the flock forever (2026-11 wedge).
		"$INITD/homeproxy" start >/dev/null 2>&1 9>&- || {
			rc=$?
			# rc=2 = "nothing to run" (nil outbound / enabled=0): a defined
			# no-op per G9, not a failure worth logging. rc=1 IS a real
			# failure -- only rc=2 stays silent (W3-1).
			[ "$rc" != "0" ] && [ "$rc" != "2" ] && log "homeproxy start returned $rc"
		}
		;;
	esac
	# homeproxy-web is NOT gated on config.enabled: it is the recovery channel.
	# 9>&-: same restore-lock fd guard as the homeproxy call above.
	"$INITD/homeproxy-web" start >/dev/null 2>&1 9>&- || log "homeproxy-web start returned $?"
fi

# 5. meow-los chained relay: its only restorer is a */5 cron running
#    /data/other_vol/meow-los/check.sh, leaving up to 5min of dead upstream
#    chain after a reboot -- exactly while homeproxy above is already
#    steering LAN traffic at it. check.sh is self-contained and idempotent
#    (it re-pins the /etc/init.d + rc.d links and the dropbear host key
#    unconditionally, exits early when the process is alive, and fail-
#    counters start attempts), so it is safe to run when needed.
#    Missing LOS tree -> silent skip; a failing check only gets logged --
#    the relay must never block or fail the homeproxy restore above.
#    9>&- keeps the restore-lock fd out of the service chain it may spawn.
#    Gate on "something actually missing": this script runs on the same
#    */5 cron minute as check.sh's own cron, and check.sh takes no lock --
#    in the dead case both would run `init.d start` and the FAIL counter
#    loses an update (benign direction but avoidable). Link present AND
#    process alive means nothing to restore: leave that pass to the cron.
_los_call=0
if [ -d /data/other_vol/meow-los ] && [ -f /data/other_vol/meow-los/check.sh ]; then
	[ -e /etc/init.d/meow-los ] || _los_call=1
	if [ "$_los_call" = 0 ]; then
		# same /proc-cmdline liveness shape as check.sh (case pattern so our
		# own argv never matches)
		_los_call=1
		for _f in /proc/[0-9]*/cmdline; do
			case "$(tr '\000' ' ' <"$_f" 2>/dev/null)" in
				*meow-los.yaml*) _los_call=0; break ;;
			esac
		done
	fi
	if [ "$_los_call" = 1 ]; then
		los_out=$(sh /data/other_vol/meow-los/check.sh 2>&1 9>&-); los_rc=$?
		[ -n "$los_out" ] && log "meow-los check: $los_out"
		[ "$los_rc" != "0" ] && log "WARN: meow-los check.sh returned $los_rc"
	fi
fi
exit 0
