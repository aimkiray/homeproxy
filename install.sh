#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# homeproxy MiWiFi port -- one-click installer / upgrader (runs ON the router).
#
#   curl -fsSL <URL>/install.sh | sh
#   sh install.sh [SRC] [--force] [--rollback]
#       SRC        local path/dir or URL of a tarball holding the repo root/ tree.
#                  Overrides HP_SRC_URL. Required if no HP_SRC_URL env.
#       --rollback restore the previous install from backup. ONLY for
#                  recovering an interrupted/failed install -- NOT a general
#                  downgrade mechanism (the backup only captures the install
#                  immediately before this one).
#   env: HP_SRC_URL          tarball URL (github release / own host)
#        HP_DOWNLOAD_SHA256  sha256 of the source tarball (verified if set)
#        HP_MEOW_URL         meow tar URL (default: v0.24.0 aarch64 musl;
#                            file:///abs/path also accepted for local push)
#        HP_MEOW_SHA256      sha256 of the meow tarball (verified if set)
#        HP_CONFIRM_TIMEOUT  seconds per verify window before auto-rollback
#                            (default 30). When meow is expected there are TWO
#                            windows: process start, then proxied connectivity
#                            -- worst-case verify time is TIMEOUT x2.
#        HP_INSTALL_SKIP_CONN  1 -> skip the through-proxy connectivity probe
#                              (restores the old process-only verification)
#        HP_PROBE_URL        connectivity probe URL fetched via the mixed port
#                            (default http://www.gstatic.com/generate_204)
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
MEOW_DIR=/data/other_vol/bin
MEOW_BIN=$MEOW_DIR/meow
BACKUP_TAR=/data/other_vol/.hp_install_backup.tar.gz
BACKUP_META=/data/other_vol/.hp_install_meta.sh
# The meow binary is NOT in BACKUP_TAR (too large for ubifs); keep its
# previous copy on tmpfs for the duration of the install so a failed swap
# can be undone.
MEOW_BACKUP=/tmp/.hp_meow_prev
CONFIRM_FILE=/tmp/hp_install_confirmed
LOG=/var/run/homeproxy/homeproxy.log

MEOW_VER=0.24.0
MEOW_SHA256=""  # If set, meow download is verified against this hash.
# NOTE: the upstream release binary at this URL does NOT include the
# `listener-shadowsocks` feature, so a Shadowsocks SERVER listener will not
# work with it (client side is unaffected). Server(SS) deployments must point
# HP_MEOW_URL at a contract-built artifact (full + listener-shadowsocks) --
# e.g. push a locally built binary/tarball and use file:///abs/path.
MEOW_URL_DEFAULT="https://github.com/meow-rs/meow-rs/releases/download/v${MEOW_VER}/meow-v${MEOW_VER}-aarch64-unknown-linux-musl.tar.gz"
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
    # file:// is the local-push path (e.g. a scp'd meow tarball).
    case "$url" in
        https://*) ;;
        file://*)
            _src=${url#file://}
            [ -f "$_src" ] || die "local file not found: $_src"
            cp -f "$_src" "$out" || die "copy failed: $_src -> $out"
            return 0
            ;;
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
        # Fail closed: a caller that supplied a checksum expects the download
        # to be verified -- silently skipping would defeat the MITM check (C2).
        die "sha256sum not available but a checksum was provided -- refusing to install unverified $_file"
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
    # Restore the previous meow binary if this install replaced it.
    restore_meow
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

# Restore the pre-install meow binary if we stashed one.
restore_meow() {
    if [ -f "$MEOW_BACKUP" ]; then
        cp -f "$MEOW_BACKUP" "$MEOW_BIN" 2>/dev/null && chmod 755 "$MEOW_BIN" \
            && log "meow binary restored." \
            || log "WARN: could not restore meow binary."
        rm -f "$MEOW_BACKUP"
    fi
}

# remove volatile /etc bits only (keep persistent tree for inspection)
cleanup_volatile() {
    /etc/init.d/homeproxy stop 2>/dev/null
    /etc/init.d/homeproxy-web stop 2>/dev/null
    restore_meow
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
# Probe for a running proxy BEFORE the swap: meow (current) OR a legacy
# sing-box left over from a pre-meow install (U8-1) -- otherwise an upgrade
# that later rolls back would not restart the still-running old service.
if ps w 2>/dev/null | grep -q '[m]eow -f /var/run/homeproxy/meow-' \
    || ps w 2>/dev/null | grep -q '[s]ing-box run'; then
    HP_WAS_RUNNING=yes
else
    HP_WAS_RUNNING=no
fi

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

# -- meow (install missing / upgrade to the pinned version) ------------------
# Install when: HP_MEOW_URL explicitly requests it, no meow binary resolves
# (neither $MEOW_BIN nor `command -v meow`), or the resolved binary is not the
# pinned 0.24 series. Sets meow_cur for the caller's log line.
need_meow() {
    meow_cur=""
    # Always probe the installed version FIRST so the caller's log line can
    # report it ("current: X") even on a forced HP_MEOW_URL reinstall (U8-12).
    if [ -x "$MEOW_BIN" ]; then
        # "meow --version" first line looks like "meow 0.24.0" (clap).
        meow_cur=$("$MEOW_BIN" --version 2>/dev/null | sed -n 's/^meow //p' | head -n1)
    elif command -v meow >/dev/null 2>&1; then
        meow_cur=$(meow --version 2>/dev/null | sed -n 's/^meow //p' | head -n1)
    else
        return 0   # `command -v meow` finds nothing -> install
    fi
    [ -n "${HP_MEOW_URL:-}" ] && return 0   # explicit URL -> always (re)install
    case "$meow_cur" in
        0.24*) return 1 ;;   # pinned series already present -> skip
    esac
    return 0
}
if need_meow; then
    log "installing meow v${MEOW_VER} (current: ${meow_cur:-none})..."
    mkdir -p "$MEOW_DIR" /tmp/hp_meow
    url=${HP_MEOW_URL:-$MEOW_URL_DEFAULT}
    # Fetch under a neutral name: the payload may be a tarball OR a bare
    # executable (file:// push of a locally built meow binary, U8-4).
    fetch "$url" /tmp/hp_meow/meow.dl
    verify_checksum /tmp/hp_meow/meow.dl "${HP_MEOW_SHA256:-$MEOW_SHA256}"
    if tar_members /tmp/hp_meow/meow.dl >/dev/null 2>&1; then
        safe_extract /tmp/hp_meow/meow.dl /tmp/hp_meow
        m=$(find /tmp/hp_meow -type f -name meow | head -n1)
        [ -n "$m" ] || die "meow binary not found in archive"
    else
        # Non-tar input -> the downloaded file IS the meow binary; it still
        # goes through the same --version smoke test before the swap below.
        m=/tmp/hp_meow/meow.dl
    fi
    chmod 755 "$m"
    # Sanity-run before swapping: a truncated/corrupt download must never
    # replace a working binary (mv below is a cross-device copy, not atomic).
    "$m" --version >/dev/null 2>&1 || die "downloaded meow fails to execute -- keeping existing binary"
    # Keep the working binary on tmpfs so rollback can restore it -- the
    # backup tarball deliberately excludes it (too large for ubifs).
    [ -x "$MEOW_BIN" ] && cp -f "$MEOW_BIN" "$MEOW_BACKUP" 2>/dev/null
    # mv is a cross-device copy (/tmp tmpfs -> /data ubifs), NOT atomic: a
    # partial copy would leave a truncated binary in place, so on failure
    # restore the stashed previous binary immediately (U8-3).
    mv -f "$m" "$MEOW_BIN" || { restore_meow; die "failed to install meow binary"; }
    chmod 755 "$MEOW_BIN"
    "$MEOW_BIN" --version >/dev/null 2>&1 || {
        restore_meow
        die "installed meow fails to execute -- restored previous binary"
    }
    rm -rf /tmp/hp_meow
    log "meow installed: $MEOW_BIN"
fi

# -- fetch + extract homeproxy source ---------------------------------------
[ -n "$SRC" ] || die "no source: pass a URL/path arg or set HP_SRC_URL"
WORK=/tmp/hp_install_src
rm -rf "$WORK" /tmp/hp_meow; mkdir -p "$WORK"
# EXIT trap: clean temp dirs always; trigger rollback if upgrade failed mid-way (C4).
trap 'rm -rf "$WORK" /tmp/hp_meow 2>/dev/null; [ "$DONE" = 0 ] && [ "${UPGRADE:-0}" = 1 ] && do_rollback; rmdir "$LOCK" 2>/dev/null' EXIT
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
# HP_MEOW_BIN records the ACTUAL binary path: the persistent copy this
# installer manages, or a PATH-resolved one (standard-package /usr/bin/meow).
if [ -x "$MEOW_BIN" ]; then
    meow_bin=$MEOW_BIN
else
    meow_bin=$(command -v meow 2>/dev/null || echo "$MEOW_BIN")
fi
log "writing env.sh (persistent path overrides)..."
# Every var is EXPORTED: sourcing shells must pass them to lua children --
# os.getenv("HP_MEOW_BIN") etc. only see exported env, not shell-locals (U8-10).
cat > "$HP_BASE/env.sh.tmp" <<EOF
# generated by install.sh -- MiWiFi persistent layout overrides
export HP_LIB_DIR=$LIB
export HP_RES_DIR=$RES
export HP_BIN_DIR=$BIN
export HP_MEOW_BIN=$meow_bin
export HP_WEBUI_PORT=${HP_WEBUI_PORT:-8910}
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
for f in clean_log.sh update_crond.sh update_resources.sh watchdog.sh; do
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
# Stop first so init.d can't race the migration, then run it under the same
# shared UCI writer lock the cgi/updater/CLI/cron use -- a cron-triggered
# subscription run can still be holding a staged delta right now.
log "stopping services for migration..."
/etc/init.d/homeproxy stop 2>/dev/null
/etc/init.d/homeproxy-web stop 2>/dev/null

log "running config migration..."
_RUN_DIR=/var/run/homeproxy
_LK_DIR="$_RUN_DIR/uci-write.lock.d"
mkdir -p "$_RUN_DIR" 2>/dev/null
_held=0; _i=0
while [ "$_i" -lt 15 ]; do
    if mkdir "$_LK_DIR" 2>/dev/null; then
        echo $$ >"$_LK_DIR/pid" 2>/dev/null
        _held=1; break
    fi
    _p=$(cat "$_LK_DIR/pid" 2>/dev/null)
    case "$_p" in ''|*[!0-9]*) _p= ;; esac
    if [ -n "$_p" ]; then
        kill -0 "$_p" 2>/dev/null || { rm -f "$_LK_DIR/pid"; rmdir "$_LK_DIR" 2>/dev/null; }
    else
        _mt=$(stat -c %Y "$_LK_DIR" 2>/dev/null) || _mt=0
        [ "${_mt:-0}" -gt 0 ] && [ $(($(date +%s) - _mt)) -gt 120 ] && rmdir "$_LK_DIR" 2>/dev/null
    fi
    _i=$((_i + 1))
    sleep 1
done
if [ "$_held" = 1 ]; then
    HP_LUAPATH="$LIB" lua "$LIB/migrate_config.lua" >>"$LOG" 2>&1 || log "WARN: migration rc=$?"
    rm -f "$_LK_DIR/pid"; rmdir "$_LK_DIR" 2>/dev/null
else
    log "WARN: uci lock busy -- skipped migration (init.d retries on start)"
fi

log "starting services..."
/etc/init.d/homeproxy start >>"$LOG" 2>&1
/etc/init.d/homeproxy-web start >>"$LOG" 2>&1

# -- verify within TIMEOUT seconds -----------------------------------------
# A stock-config install legitimately runs no meow instance (no node
# configured, server disabled) -- "installed, awaiting configuration" is a
# success state, so verify the web UI instead of a process that will never
# exist. Mirrors the start conditions in init.d/homeproxy.
#
# uci truth-table helper (same vocabulary as config_get_bool): only
# {1,yes,on,true,enabled} are true; every other spelling -- including
# garbage values -- is false. The absent/empty default is each caller's
# choice (config.enabled defaults on, the server switches default off).
bool_on() {
    case "$1" in
        1|yes|on|true|enabled) return 0 ;;
        *) return 1 ;;
    esac
}

# Master switch first (spec 7.2): config.enabled absent/empty = enabled;
# any other value disables the whole service. An explicit disabled must
# NOT be overturned by the HP_WAS_RUNNING upgrade override below.
hp_disabled=0
_en=$(uci -q get homeproxy.config.enabled 2>/dev/null)
if [ -n "$_en" ] && ! bool_on "$_en"; then hp_disabled=1; fi

# Expectations per instance so the stage-1 probe can look for exactly the
# yamls this install should run: expect_c -> meow-c.yaml (an outbound is
# configured), expect_s -> meow-s.yaml (C3 server formula).
expect_c=0; expect_s=0
if [ "$hp_disabled" = 0 ]; then
    # C3: the named `homeproxy.server.enabled` master switch is uci-true
    # OR any `config server` listener section's enabled is uci-true (same
    # sed pipeline as the CLI srv_en probe / firewall.sh apply_fw_pre).
    if bool_on "$(uci -q get homeproxy.server.enabled 2>/dev/null)"; then
        expect_s=1
    else
        for _s in $(uci -q show homeproxy 2>/dev/null | sed -n "s/^homeproxy\.\([^.]*\)=server/\1/p"); do
            bool_on "$(uci -q get "homeproxy.$_s.enabled" 2>/dev/null)" && expect_s=1
        done
    fi
    if [ "$(uci -q get homeproxy.config.routing_mode 2>/dev/null)" = "custom" ]; then
        _o=$(uci -q get homeproxy.routing.default_outbound 2>/dev/null)
    else
        _o=$(uci -q get homeproxy.config.main_node 2>/dev/null)
    fi
    [ -n "$_o" ] && [ "$_o" != "nil" ] && expect_c=1
fi
meow_expected=0
{ [ "$expect_c" = 1 ] || [ "$expect_s" = 1 ]; } && meow_expected=1
# Upgrades: a previously running meow must come back regardless -- unless
# the master switch was explicitly turned off.
[ "$hp_disabled" = 0 ] && [ "$HP_WAS_RUNNING" = "yes" ] && meow_expected=1

# yaml set the stage-1 probe should look for. Empty means "meow was
# running before but nothing is expected now" -> any meow- instance.
exp_yamls=""
[ "$expect_c" = 1 ] && exp_yamls="$exp_yamls meow-c.yaml"
[ "$expect_s" = 1 ] && exp_yamls="$exp_yamls meow-s.yaml"

# Process probe: prefer pgrep -f; busybox builds may ship without it, so fall
# back to `ps w | grep` (the bracket patterns below keep grep from matching
# its own command line in the ps output). (U8-5)
proc_running() {
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -f "$1" >/dev/null 2>&1
    else
        ps w 2>/dev/null | grep -q "$1"
    fi
}

# Stage-2 probe (meow_expected=1 only): an end-to-end fetch through the mixed
# port proves "meow + node + upstream" all work -- a process that starts but
# whose outbound is black must still trigger rollback/cleanup (G10). The URL
# is overridable via HP_PROBE_URL (https:// works too: CONNECT via mixed).
PROBE_URL=${HP_PROBE_URL:-http://www.gstatic.com/generate_204}
mixed_port=$(uci -q get homeproxy.infra.mixed_port 2>/dev/null); mixed_port=${mixed_port:-5330}
# UCI may hold a dirty value (e.g. "abc", "53 30") -- fall back to default.
case "$mixed_port" in ''|*[!0-9]*) mixed_port=5330 ;; esac
conn_probe() {
    command -v curl >/dev/null 2>&1 || return 1
    code=$(curl -s -o /dev/null --max-time 8 -x "http://127.0.0.1:$mixed_port" \
        -w '%{http_code}' "$PROBE_URL" 2>/dev/null) || return 1
    case "$code" in 2[0-9][0-9]|3[0-9][0-9]) return 0 ;; *) return 1 ;; esac
}

ok=0; i=0; fail_reason=""
if [ "$meow_expected" = 0 ]; then
    log "no node/server configured -- verifying web UI instead of meow..."
    while [ "$i" -lt "$TIMEOUT" ]; do
        if proc_running '[u]httpd.*homeproxy'; then ok=1; break; fi
        sleep 1; i=$((i+1))
    done
    [ "$ok" = 1 ] && log "installed (unconfigured): web UI up, add a node to start proxying."
else
    # Stage 1: wait for a meow process from the EXPECTED yaml set -- any
    # one expected instance up counts, an orphan outside the set does not.
    # With no yaml expectation (HP_WAS_RUNNING alone) fall back to the
    # legacy meow- prefix probe.
    log "verifying meow start (${TIMEOUT}s)..."
    while [ "$i" -lt "$TIMEOUT" ]; do
        if [ -n "$exp_yamls" ]; then
            for _y in $exp_yamls; do
                if proc_running "[m]eow -f /var/run/homeproxy/$_y"; then ok=1; break; fi
            done
        elif proc_running '[m]eow -f /var/run/homeproxy/meow-'; then
            ok=1
        fi
        [ "$ok" = 1 ] && break
        sleep 1; i=$((i+1))
    done
    if [ "$ok" != 1 ]; then
        fail_reason="process never appeared"
    elif [ "$expect_c" != 1 ]; then
        # Pure-server expectation (or a was-running upgrade with no yaml
        # set): meow-s has no mixed port, so process presence is the pass.
        log "meow process up; no client instance expected -- skipping connectivity probe."
    elif [ "${HP_INSTALL_SKIP_CONN:-}" = "1" ]; then
        log "meow process up; HP_INSTALL_SKIP_CONN=1 -- skipping connectivity probe."
    elif ! command -v curl >/dev/null 2>&1; then
        # +curl is in DEPENDS so this should never happen; fail closed
        # rather than silently trusting an unverified outbound.
        log "WARN: curl not found -- connectivity probe impossible."
        ok=0; fail_reason="up but no proxied connectivity (${PROBE_URL})"
    else
        # Stage 2: fresh TIMEOUT window, probe through the mixed port every
        # 2s. A mid-window process death does NOT fail early -- procd may
        # respawn it and the probe can still pass before the window ends.
        # The window is wall-clock (date +%s deadline), NOT iteration-counted:
        # a single conn_probe may take up to --max-time 8s, which must count
        # against the window so worst-case verify stays within TIMEOUT (W5-1).
        log "meow process up -- probing proxied connectivity via 127.0.0.1:$mixed_port (${TIMEOUT}s)..."
        ok=0; end=$(( $(date +%s) + TIMEOUT ))
        while [ "$(date +%s)" -lt "$end" ]; do
            if conn_probe; then ok=1; break; fi
            sleep 2
        done
        [ "$ok" = 1 ] || fail_reason="up but no proxied connectivity (${PROBE_URL})"
    fi
fi

if [ "$ok" = 1 ]; then
    touch "$CONFIRM_FILE"
    rm -f "$BACKUP_TAR" "$BACKUP_META" "$MEOW_BACKUP"
    lip=$(uci -q get network.lan.ipaddr 2>/dev/null || echo 192.168.31.1)
    if [ "$meow_expected" = 1 ]; then
        log "OK meow running. install/upgrade complete."
    else
        log "OK install complete (proxy starts once a node is configured)."
    fi
    log "  CLI: $BIN/homeproxy"
    log "  Web: http://${lip}:8910/"
    log "  Log: $LOG (tail -f)"
    DONE=1
    exit 0
fi

if [ "$meow_expected" = 1 ]; then
    log "FAILED: meow ${fail_reason:-did not start within ${TIMEOUT}s}."
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