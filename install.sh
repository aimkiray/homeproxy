#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# homeproxy MiWiFi port -- one-click installer / upgrader (runs ON the router).
#
#   curl -fsSL <URL>/install.sh | sh
#   sh install.sh [SRC] [--force] [--rollback]
#       SRC   local path/dir or URL of a tarball holding the repo root/ tree.
#             Overrides HP_SRC_URL. Required if no HP_SRC_URL env.
#   env: HP_SRC_URL          tarball URL (github release / own host)
#        HP_DOWNLOAD_SHA256  sha256 of the source tarball (verified if set)
#        HP_SINGBOX_URL      sing-box tar URL (default: 1.13.15 linux arm64)
#        HP_SINGBOX_SHA256   sha256 of the sing-box tarball (verified if set)
#        HP_CONFIRM_TIMEOUT  verify window before auto-rollback (default 30)
#        HP_FORCE_CONFIG     non-empty -> overwrite existing UCI config too
#
# Fresh install and in-place upgrade are both supported. Persistent files live
# on /data/other_vol (ubifs); volatile /etc bits are recreated every boot by
# boot_restore.sh. A failed UPGRADE is auto-rolled back (30s verify window); a
# failed FRESH install is cleaned up to a safe no-proxy state.

set -u

# -- layout ------------------------------------------------------------------
HP_BASE=/data/other_vol/homeproxy
LIB=$HP_BASE/lib
RES=$HP_BASE/resources
SCR=$HP_BASE/scripts
BIN=$HP_BASE/bin
WEB=$HP_BASE/web
INITD_PERSIST=$HP_BASE/init.d
SINGBOX_DIR=/data/other_vol/bin
SINGBOX=$SINGBOX_DIR/sing-box
BACKUP_TAR=/data/other_vol/.hp_install_backup.tar.gz
BACKUP_META=/data/other_vol/.hp_install_meta.sh
# The sing-box binary is NOT in BACKUP_TAR (too large for ubifs); keep its
# previous copy on tmpfs for the duration of the install so a failed swap
# can be undone.
SB_BACKUP=/tmp/.hp_singbox_prev
CONFIRM_FILE=/tmp/hp_install_confirmed
LOG=/var/run/homeproxy/homeproxy.log

SINGBOX_VER=1.13.15
SINGBOX_SHA256=""  # If set, sing-box download is verified against this hash.
SINGBOX_URL_DEFAULT="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/sing-box-${SINGBOX_VER}-linux-arm64.tar.gz"
TIMEOUT=${HP_CONFIRM_TIMEOUT:-30}

export PATH=/usr/bin:/bin:/usr/sbin:/sbin:$PATH
mkdir -p /var/run/homeproxy 2>/dev/null

log() { echo "[hp-install] $*"; }
die() { echo "[hp-install] ERROR: $*" >&2; exit 1; }

# Single-flight: a second concurrent install would race on $WORK/$BACKUP_TAR
# and the in-place file swaps. mkdir is atomic on busybox.
LOCK=/tmp/homeproxy-install.lock
mkdir "$LOCK" 2>/dev/null || die "another install is already running (lock: $LOCK)"
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

# fetch <url> <out_file>  (curl preferred, wget fallback)
# Enforces HTTPS-only (C5). Callers verify integrity via verify_checksum (C2).
fetch() {
    url=$1; out=$2
    # Reject non-HTTPS URLs to prevent MITM on cleartext downloads (C5).
    case "$url" in
        https://*) ;;
        *) die "refusing non-HTTPS URL (security policy): $url" ;;
    esac
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$out" || die "download failed: $url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$out" "$url" || die "download failed: $url"
    else
        die "neither curl nor wget available"
    fi
}

# Verify a file's SHA256 checksum if HP_DOWNLOAD_SHA256 is set (C2).
# Usage: verify_checksum <file> <expected_sha256_or_empty>
verify_checksum() {
    _file=$1; _expected=$2
    [ -n "$_expected" ] || return 0  # no hash specified — skip
    if ! command -v sha256sum >/dev/null 2>&1; then
        log "WARN: sha256sum not available — skipping checksum verification."
        return 0
    fi
    local actual
    actual=$(sha256sum "$_file" 2>/dev/null | awk '{print $1}')
    [ "$actual" = "$_expected" ] || die "checksum mismatch: expected $_expected, got ${actual:-<empty>}"
}

# List members of a (possibly gzipped) tar archive, one per line.
tar_members() {
    tar -tzf "$1" 2>/dev/null || tar -tf "$1" 2>/dev/null
}

# Safe tar extraction: validates the member LIST before touching the fs (C6).
# The old post-extraction `find "$_dest"` could only ever see paths already
# inside $_dest, so escapes were undetectable -- and symlinks were skipped
# entirely. Here we reject: absolute names, '..' path components, and every
# member that is not a regular file or directory (symlink/hardlink/device/
# fifo), so no entry can point outside $_dest by construction.
# Usage: safe_extract <tarball> <dest_dir>
safe_extract() {
    _tar=$1; _dest=$2
    _names=$(tar_members "$_tar")
    [ -n "$_names" ] || die "cannot list archive (not a tar?): $_tar"
    _bad=$(printf '%s\n' "$_names" | while IFS= read -r _m; do
        case "$_m" in
            /*|../*|*/../*|*/..|..) printf '%s\n' "$_m" ;;
        esac
    done | head -n 3)
    [ -z "$_bad" ] || die "unsafe path in archive: $_bad"
    _links=$(tar -tvzf "$_tar" 2>/dev/null || tar -tvf "$_tar" 2>/dev/null)
    # awk field 1 is the mode string: '-' regular file, 'd' dir are the only
    # member types this installer ships or accepts.
    _bad=$(printf '%s\n' "$_links" | awk '{c=substr($1,1,1)} c!="-" && c!="d" {print; n++} n>=3{exit}')
    [ -z "$_bad" ] || die "unsupported member type in archive (links/devices not allowed): $_bad"
    tar -C "$_dest" -xzf "$_tar" 2>/dev/null || tar -C "$_dest" -xf "$_tar" 2>/dev/null || die "extract failed: $_tar"
}

# -- args --------------------------------------------------------------------
SRC=""
FORCE_CONFIG=""
ROLLBACK=0
for a in "$@"; do
    case "$a" in
        --force) FORCE_CONFIG=1 ;;
        --rollback) ROLLBACK=1 ;;
        --*) die "unknown option: $a" ;;
        *) [ -z "$SRC" ] || die "multiple SRC args"; SRC="$a" ;;
    esac
done
[ -n "$SRC" ] || SRC=${HP_SRC_URL:-}
[ -n "$FORCE_CONFIG" ] || FORCE_CONFIG=${HP_FORCE_CONFIG:-}

# -- prechecks ---------------------------------------------------------------
command -v lua >/dev/null 2>&1 || die "lua not found (homeproxy needs lua 5.1)"
command -v iptables >/dev/null 2>&1 || log "WARN: iptables missing -- tproxy steering will fail"
command -v ipset >/dev/null 2>&1    || log "WARN: ipset missing -- CN bypass will fail"

# Error-aware EXIT trap: if the script dies after backup but before successful
# completion, trigger auto-rollback for upgrades (C4).  DONE=1 is set only at
# the final successful exit.
DONE=0

# -- rollback (restore last backup) -----------------------------------------
do_rollback() {
    log "rolling back to previous install..."
    /etc/init.d/homeproxy stop 2>/dev/null
    /etc/init.d/homeproxy-web stop 2>/dev/null
    sleep 1
    # Selectively remove code/config/symlinks but PRESERVE resources/ (C3):
    # the backup tarball never captured the bulky geodata, so a full rm -rf
    # would leave the router without china_ip4.txt etc. after rollback.
    rm -rf "$LIB" "$SCR" "$WEB" "$INITD_PERSIST" "$BIN"
    rm -f "$HP_BASE/boot_restore.sh" "$HP_BASE/env.sh"
    rm -rf /etc/homeproxy
    rm -f /etc/init.d/homeproxy /etc/init.d/homeproxy-web /etc/profile.d/homeproxy.sh
    if [ -f "$BACKUP_TAR" ] && [ -s "$BACKUP_TAR" ]; then
        tar -C / -xzf "$BACKUP_TAR" 2>/dev/null || log "WARN: backup extraction may have failed."
        log "backup restored from $BACKUP_TAR"
    else
        log "no backup -- clean removal done (fresh install)"
    fi
    # Restore the previous sing-box binary if this install replaced it.
    restore_singbox
    # Pre-initialize vars to avoid set -u abort on partial BACKUP_META (M from review).
    HP_FW_INC=""; HP_FW_PATH=""; HP_WAS_RUNNING="no"
    if [ -f "$BACKUP_META" ]; then
        . "$BACKUP_META" 2>/dev/null || true
        if [ "$HP_FW_INC" = "include" ]; then
            uci -q set firewall.homeproxy=include
            uci -q set firewall.homeproxy.type=script
            uci -q set firewall.homeproxy.path="$HP_FW_PATH"
            uci -q set firewall.homeproxy.reload=1
            uci -q set firewall.homeproxy.enabled=1
        else
            uci -q delete firewall.homeproxy 2>/dev/null
        fi
        uci -q commit firewall 2>/dev/null || log "WARN: uci commit firewall failed."
    else
        uci -q delete firewall.homeproxy 2>/dev/null
        uci -q commit firewall 2>/dev/null
    fi
    /etc/init.d/dnsmasq restart 2>/dev/null
    /etc/init.d/firewall reload 2>/dev/null
    if [ "$HP_WAS_RUNNING" = "yes" ]; then
        /etc/init.d/homeproxy start 2>/dev/null
        /etc/init.d/homeproxy-web start 2>/dev/null
        log "rollback complete, services restarted."
    else
        log "rollback complete (service was not running before)."
    fi
    rm -f "$CONFIRM_FILE" "$BACKUP_META" "$BACKUP_TAR"
}

# Restore the pre-install sing-box binary if we stashed one.
restore_singbox() {
    if [ -f "$SB_BACKUP" ]; then
        cp -f "$SB_BACKUP" "$SINGBOX" 2>/dev/null && chmod 755 "$SINGBOX" \
            && log "sing-box binary restored." \
            || log "WARN: could not restore sing-box binary."
        rm -f "$SB_BACKUP"
    fi
}

# remove volatile /etc bits only (keep persistent tree for inspection)
cleanup_volatile() {
    /etc/init.d/homeproxy stop 2>/dev/null
    /etc/init.d/homeproxy-web stop 2>/dev/null
    restore_singbox
    rm -f /etc/init.d/homeproxy /etc/init.d/homeproxy-web /etc/profile.d/homeproxy.sh
    rm -rf /etc/homeproxy
    uci -q delete firewall.homeproxy 2>/dev/null; uci -q commit firewall
    sed -i '/homeproxy\/boot_restore.sh/d' /data/auto_start.sh 2>/dev/null
    crontab -l 2>/dev/null | grep -v 'homeproxy/boot_restore.sh' | crontab - 2>/dev/null
    /etc/init.d/dnsmasq restart 2>/dev/null
    /etc/init.d/firewall reload 2>/dev/null
}

if [ "$ROLLBACK" = 1 ]; then
    do_rollback
    DONE=1  # Prevent EXIT trap from triggering a second rollback (F2).
    exit 0
fi

# -- upgrade detection + backup ---------------------------------------------
UPGRADE=0
[ -f "$LIB/generate_client.lua" ] && UPGRADE=1
log "mode: $([ "$UPGRADE" = 1 ] && echo upgrade || echo fresh-install)"

HP_FW_INC=$(uci -q get firewall.homeproxy 2>/dev/null || echo "")
HP_FW_PATH=$(uci -q get firewall.homeproxy.path 2>/dev/null || echo "")
ps w 2>/dev/null | grep -q '[s]ing-box run --config' && HP_WAS_RUNNING=yes || HP_WAS_RUNNING=no

# backup code+config+symlinks only. We list the code subdirs explicitly so
# the bulky resources/ (geodata) is NEVER captured -- avoids doubling ubifs use
# and does not depend on busybox --exclude matching member names.
paths=""
for p in /etc/init.d/homeproxy /etc/init.d/homeproxy-web /etc/config/homeproxy \
         /etc/homeproxy \
         "$HP_BASE/lib" "$HP_BASE/scripts" "$HP_BASE/web" "$HP_BASE/init.d" \
         "$HP_BASE/bin" "$HP_BASE/boot_restore.sh" "$HP_BASE/env.sh" \
         /etc/profile.d/homeproxy.sh; do
    [ -e "$p" ] && paths="$paths $p"
done
# For upgrades: a failed backup must abort (H13). For fresh installs, an empty
# backup is acceptable (nothing to restore).
if [ "$UPGRADE" = 1 ] && [ -n "$paths" ]; then
    tar -C / -czf "$BACKUP_TAR" $paths 2>/dev/null
    if [ $? -ne 0 ] || [ ! -s "$BACKUP_TAR" ]; then
        die "backup failed -- aborting upgrade (disk full?)"
    fi
elif [ -n "$paths" ]; then
    tar -C / -czf "$BACKUP_TAR" $paths 2>/dev/null || tar -C / -czf "$BACKUP_TAR" --no-recursion /dev/null 2>/dev/null || true
else
    tar -C / -czf "$BACKUP_TAR" --no-recursion /dev/null 2>/dev/null || true
fi
cat > "$BACKUP_META.tmp" <<EOF
HP_FW_INC="$HP_FW_INC"
HP_FW_PATH="$HP_FW_PATH"
HP_WAS_RUNNING="$HP_WAS_RUNNING"
EOF
mv "$BACKUP_META.tmp" "$BACKUP_META"
log "backup saved: $BACKUP_TAR"

# -- sing-box (install missing / upgrade to the pinned version) --------------
sb_want=0
sb_cur=""
if [ ! -x "$SINGBOX" ]; then
    sb_want=1
elif [ -n "${HP_SINGBOX_URL:-}" ]; then
    sb_want=1   # explicit URL -> always (re)install
else
    # "sing-box version" first line: "sing-box version 1.13.15"
    sb_cur=$("$SINGBOX" version 2>/dev/null | sed -n 's/^sing-box version //p' | head -n1)
    [ -n "$sb_cur" ] && [ "$sb_cur" != "$SINGBOX_VER" ] && sb_want=1
fi
if [ "$sb_want" = 1 ]; then
    log "installing sing-box v${SINGBOX_VER} (current: ${sb_cur:-none})..."
    mkdir -p "$SINGBOX_DIR" /tmp/hp_sb
    url=${HP_SINGBOX_URL:-$SINGBOX_URL_DEFAULT}
    fetch "$url" /tmp/hp_sb/sb.tar.gz
    verify_checksum /tmp/hp_sb/sb.tar.gz "${HP_SINGBOX_SHA256:-$SINGBOX_SHA256}"
    safe_extract /tmp/hp_sb/sb.tar.gz /tmp/hp_sb
    sb=$(find /tmp/hp_sb -type f -name sing-box | head -n1)
    [ -n "$sb" ] || die "sing-box binary not found in archive"
    chmod 755 "$sb"
    # Sanity-run before swapping: a truncated/corrupt download must never
    # replace a working binary (mv below is a cross-device copy, not atomic).
    "$sb" version >/dev/null 2>&1 || die "downloaded sing-box fails to execute -- keeping existing binary"
    # Keep the working binary on tmpfs so rollback can restore it -- the
    # backup tarball deliberately excludes it (too large for ubifs).
    [ -x "$SINGBOX" ] && cp -f "$SINGBOX" "$SB_BACKUP" 2>/dev/null
    mv -f "$sb" "$SINGBOX" || die "failed to install sing-box binary"
    chmod 755 "$SINGBOX"
    "$SINGBOX" version >/dev/null 2>&1 || {
        restore_singbox
        die "installed sing-box fails to execute -- restored previous binary"
    }
    rm -rf /tmp/hp_sb
    log "sing-box installed: $SINGBOX"
fi

# -- fetch + extract homeproxy source ---------------------------------------
[ -n "$SRC" ] || die "no source: pass a URL/path arg or set HP_SRC_URL"
WORK=/tmp/hp_install_src
rm -rf "$WORK" /tmp/hp_sb; mkdir -p "$WORK"
# EXIT trap: clean temp dirs always; trigger rollback if upgrade failed mid-way (C4).
trap 'rm -rf "$WORK" /tmp/hp_sb 2>/dev/null; [ "$DONE" = 0 ] && [ "${UPGRADE:-0}" = 1 ] && do_rollback; rmdir "$LOCK" 2>/dev/null' EXIT
case "$SRC" in
    https://*)
        log "downloading source: $SRC"
        fetch "$SRC" "$WORK/src.tar.gz"
        verify_checksum "$WORK/src.tar.gz" "${HP_DOWNLOAD_SHA256:-}"
        safe_extract "$WORK/src.tar.gz" "$WORK"
        ;;
    *)
        if [ -d "$SRC" ]; then
            cp -a "$SRC"/. "$WORK"/
            # A local directory can still contain links pointing outside the
            # tree -- reject them rather than trusting the path.
            _l=$(find "$WORK" -type l 2>/dev/null | head -n 1)
            [ -z "$_l" ] || die "source dir contains a symlink, refusing: $_l"
        elif [ -f "$SRC" ]; then
            safe_extract "$SRC" "$WORK"
        else
            die "source not found: $SRC"
        fi
        ;;
esac

# locate repo root/ tree (top-level or nested one/two levels deep)
ROOT=""
for d in "$WORK" "$WORK"/* "$WORK"/*/*; do
    [ -f "$d/root/usr/lib/homeproxy/homeproxy.lua" ] && { ROOT="$d/root"; break; }
done
[ -n "$ROOT" ] || { [ -f "$WORK/usr/lib/homeproxy/homeproxy.lua" ] && ROOT="$WORK"; }
[ -n "$ROOT" ] || die "could not locate repo root/ tree in archive"
log "source root: $ROOT"

# -- generate runtime path overrides (env.sh) -------------------------------
# No deploy-time patching: scripts source /etc/homeproxy/env.sh (-> $HP_BASE
# via the symlink) and fall back to /usr/lib/homeproxy on a standard build.
mkdir -p "$HP_BASE"
log "writing env.sh (persistent path overrides)..."
cat > "$HP_BASE/env.sh.tmp" <<EOF
# generated by install.sh -- MiWiFi persistent layout overrides
HP_LIB_DIR=$LIB
HP_RES_DIR=$RES
HP_BIN_DIR=$BIN
HP_SINGBOX=$SINGBOX
HP_WEBUI_PORT=${HP_WEBUI_PORT:-8910}
EOF
mv "$HP_BASE/env.sh.tmp" "$HP_BASE/env.sh"
chmod 644 "$HP_BASE/env.sh"

# -- lay down files ----------------------------------------------------------
install_file() {  # <src> <dst> <mode> <policy: always|if_missing>
    s=$1; d=$2; m=$3; pol=$4
    if [ "$pol" = "if_missing" ] && [ -e "$d" ] && [ -z "$FORCE_CONFIG" ]; then
        log "  skip $d (exists)"; return 0
    fi
    # Never install a symlink as-is: cp -a would copy the link and the
    # following chmod would then apply to the link TARGET.
    [ ! -L "$s" ] || die "refusing symlink source: $s"
    mkdir -p "$(dirname "$d")"
    # Atomic write: copy to temp then rename (H15) — prevents partial files
    # if interrupted (e.g. SIGPIPE from curl|sh mid-copy).
    cp -a "$s" "$d.tmp" 2>/dev/null || cp "$s" "$d.tmp" || die "copy failed: $s -> $d"
    mv "$d.tmp" "$d" || die "rename failed: $d.tmp -> $d"
    chmod "$m" "$d"
}

log "laying down files..."
# Glob all .lua modules (matches Makefile's *.lua install); any new module
# is auto-deployed without updating a hardcoded list.
for f in "$ROOT"/usr/lib/homeproxy/*.lua; do
    [ -f "$f" ] || continue
    install_file "$f" "$LIB/$(basename "$f")" 644 always
done
# Shell scripts get 755 directly.
for f in firewall.sh firewall_include.sh; do
    install_file "$ROOT/usr/lib/homeproxy/$f" "$LIB/$f" 755 always
done
install_file "$ROOT/usr/bin/homeproxy" "$BIN/homeproxy" 755 always
for f in clean_log.sh update_crond.sh update_resources.sh guard.sh; do
    install_file "$ROOT/etc/homeproxy/scripts/$f" "$SCR/$f" 755 always
done
install_file "$ROOT/etc/homeproxy/web/index.html" "$WEB/index.html" 644 always
install_file "$ROOT/etc/homeproxy/web/cgi-bin/api" "$WEB/cgi-bin/api" 755 always
install_file "$ROOT/etc/init.d/homeproxy" "$INITD_PERSIST/homeproxy" 755 always
install_file "$ROOT/etc/init.d/homeproxy-web" "$INITD_PERSIST/homeproxy-web" 755 always
install_file "$ROOT/etc/homeproxy/scripts/boot_restore.sh" "$HP_BASE/boot_restore.sh" 755 always
install_file "$ROOT/etc/config/homeproxy" /etc/config/homeproxy 644 if_missing
if [ -d "$ROOT/etc/homeproxy/resources" ]; then
    mkdir -p "$RES"
    for f in "$ROOT"/etc/homeproxy/resources/*; do
        [ -f "$f" ] || continue
        install_file "$f" "$RES/$(basename "$f")" 644 if_missing
    done
fi

# -- volatile /etc bits + boot hooks ----------------------------------------
log "linking volatile /etc bits..."
rm -rf /etc/homeproxy 2>/dev/null
ln -sfn "$HP_BASE" /etc/homeproxy
mkdir -p /etc/init.d /etc/profile.d
ln -sfn "$INITD_PERSIST/homeproxy" /etc/init.d/homeproxy
ln -sfn "$INITD_PERSIST/homeproxy-web" /etc/init.d/homeproxy-web
printf 'export PATH="$PATH:/data/other_vol/bin:/data/other_vol/homeproxy/bin"\n' > /etc/profile.d/homeproxy.sh
if ! grep -q 'homeproxy/boot_restore.sh' /data/auto_start.sh 2>/dev/null; then
    printf '\n# homeproxy auto-restore (LuCI-less MiWiFi port)\n[ -x /data/other_vol/homeproxy/boot_restore.sh ] && /data/other_vol/homeproxy/boot_restore.sh\n' >> /data/auto_start.sh
fi
crontab -l 2>/dev/null | grep -v 'homeproxy/boot_restore.sh' | { cat; echo '*/5 * * * * /data/other_vol/homeproxy/boot_restore.sh'; } | crontab -
# fw3 include (idempotent)
uci -q set firewall.homeproxy=include
uci -q set firewall.homeproxy.type=script
uci -q set firewall.homeproxy.path="$LIB/firewall_include.sh"
uci -q set firewall.homeproxy.reload=1
uci -q set firewall.homeproxy.enabled=1
uci -q commit firewall

# -- migrate + start ---------------------------------------------------------
log "running config migration..."
HP_LUAPATH="$LIB" lua "$LIB/migrate_config.lua" >>"$LOG" 2>&1 || log "WARN: migration rc=$?"

log "starting services..."
/etc/init.d/homeproxy stop 2>/dev/null
/etc/init.d/homeproxy-web stop 2>/dev/null
/etc/init.d/homeproxy start >>"$LOG" 2>&1
/etc/init.d/homeproxy-web start >>"$LOG" 2>&1

# -- verify within TIMEOUT seconds -----------------------------------------
# A stock-config install legitimately runs no sing-box instance (no node
# configured, server disabled) -- "installed, awaiting configuration" is a
# success state, so verify the web UI instead of a process that will never
# exist. Mirrors the start conditions in init.d/homeproxy.
need_singbox=0
if [ "$(uci -q get homeproxy.server.enabled 2>/dev/null)" = "1" ]; then
    need_singbox=1
elif [ "$(uci -q get homeproxy.config.routing_mode 2>/dev/null)" = "custom" ]; then
    _o=$(uci -q get homeproxy.routing.default_outbound 2>/dev/null)
    [ -n "$_o" ] && [ "$_o" != "nil" ] && need_singbox=1
else
    _o=$(uci -q get homeproxy.config.main_node 2>/dev/null)
    [ -n "$_o" ] && [ "$_o" != "nil" ] && need_singbox=1
fi
# Upgrades: a previously running sing-box must come back regardless.
[ "$HP_WAS_RUNNING" = "yes" ] && need_singbox=1

ok=0; i=0
if [ "$need_singbox" = 0 ]; then
    log "no node/server configured -- verifying web UI instead of sing-box..."
    while [ "$i" -lt "$TIMEOUT" ]; do
        if pgrep -f 'uhttpd.*homeproxy' >/dev/null 2>&1; then ok=1; break; fi
        sleep 1; i=$((i+1))
    done
    [ "$ok" = 1 ] && log "installed (unconfigured): web UI up, add a node to start proxying."
else
    log "verifying sing-box start (${TIMEOUT}s)..."
    while [ "$i" -lt "$TIMEOUT" ]; do
        if pgrep -f 'sing-box run --config' >/dev/null 2>&1; then ok=1; break; fi
        sleep 1; i=$((i+1))
    done
fi

if [ "$ok" = 1 ]; then
    touch "$CONFIRM_FILE"
    rm -f "$BACKUP_TAR" "$BACKUP_META" "$SB_BACKUP"
    lip=$(uci -q get network.lan.ipaddr 2>/dev/null || echo 192.168.31.1)
    if [ "$need_singbox" = 1 ]; then
        log "OK sing-box running. install/upgrade complete."
    else
        log "OK install complete (proxy starts once a node is configured)."
    fi
    log "  CLI: $BIN/homeproxy"
    log "  Web: http://${lip}:8910/"
    log "  Log: $LOG (tail -f)"
    DONE=1
    exit 0
fi

if [ "$need_singbox" = 1 ]; then
    log "FAILED: sing-box did not start within ${TIMEOUT}s."
else
    log "FAILED: web UI did not come up within ${TIMEOUT}s."
fi
if [ "$UPGRADE" = 1 ]; then
    log "upgrade failed -- auto-rolling back..."
    do_rollback
else
    log "fresh install failed -- cleaning volatile bits (safe no-proxy state)."
    cleanup_volatile
fi
log "see log: $LOG"
DONE=1
exit 1