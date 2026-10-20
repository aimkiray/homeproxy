# HomeProxy — Complete Engineering Code Review

> **历史存档**：本评审针对 sing-box 时代的代码基线（分支 `xiaomi`）。当前 `meow-kernel` 分支已完成 meow-rs v0.24.0 迁移与独立评审/修复，见 `docs/spec-meow-migration-A.md` §13 勘误。

**Scope**: 7 core files (~3500 lines)  
**Target**: Xiaomi/MiWiFi router, OpenWrt 18.06, Lua 5.1, iptables+ipset, sing-box 1.11+  
**Method**: 7 parallel subagent deep reviews + manual cross-file analysis

---

## Executive Summary

The codebase demonstrates **solid engineering fundamentals** for embedded OpenWrt development: modular design, consistent `shellQuote`, pcall wrappers, fail-closed defaults, idempotent iptables. However, **6 CRITICAL issues** (data loss + security) and **16 HIGH issues** (correctness + state management) must be fixed before production deployment.

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 6 |
| 🟠 HIGH | 16 |
| 🟡 MEDIUM | 34 |
| 🟢 LOW | 28+ |

**Grade**: B → B+ after immediate fixes

---

## 🔴 CRITICAL (Must Fix Before Release)

### C1. Cross-Subscription Label Collision → Silent Data Loss
**File**: `update_subscriptions.lua:313-316`

UCI sections named `md5(node.label)` — no subscription disambiguation. Two subs with "🇭🇰 HK 01" → second overwrites first → **oscillation every run**, one server permanently missing.

**Fix**: `local nameHash = hp.md5(groupHash .. "\x00" .. node.label)`

---

### C2. Install: No Download Integrity Verification
**File**: `install.sh:48-57, 179, 196`

Zero checksum/signature on sing-box binary + source tarball. MITM → root code execution on traffic-intercepting router.

**Fix**: `echo "$EXPECTED_SHA256  $out" | sha256sum -c || die "checksum failed"`

---

### C3. Install: Rollback Destroys resources/ Not In Backup
**File**: `install.sh:154-158, 85`

Backup excludes `resources/` (ubifs cost). Rollback does `rm -rf "$HP_BASE"` → geodata gone → routing modes broken. User told "rollback complete."

**Fix**: Include resources in backup, or selective rm during rollback.

---

### C4. Install: die() After Backup Doesn't Trigger Rollback
**File**: `install.sh:192, 240, 197`

EXIT trap only removes temp, never calls `do_rollback`. Network drop during `curl | sh` → half-applied upgrade, no auto-recovery.

**Fix**: Error-aware EXIT trap with `DONE=0` flag.

---

### C5. Install: HTTP/FTP URLs Accepted
**File**: `install.sh:194`

Non-HTTPS URLs → cleartext download, trivial MITM.

**Fix**: `case "$url" in https://*) ;; *) die "refusing non-HTTPS" ;; esac`

---

### C6. Install: Tarball Path-Traversal Attack
**File**: `install.sh:180, 197, 203`

No member validation. Malicious tarball with `../../etc/rc.local` → arbitrary overwrite as root.

**Fix**: Validate extracted paths stay within `$WORK`.

---

## 🟠 HIGH (Fix Before Next Release)

### H1. Node Update Logic Incomplete
**File**: `update_subscriptions.lua:295-304`

Update loop iterates only OLD fields. New fields from provider (e.g. `tls_alpn`) never applied to existing nodes.

**Fix**: Iterate new node fields first, then delete absent old fields.

### H2. Silent Data Loss on Write Failure
**File**: `homeproxy.lua:23-37`

`f:write()`/`f:close()` returns unchecked. Full filesystem → truncated config → sing-box loads corrupt JSON.

**Fix**: Check returns + atomic write (temp→rename).

### H3. Predictable Temp Files
**File**: `homeproxy.lua:333-335`

`math.randomseed()` never called → same "random" temp names every run → symlink attack + collision.

**Fix**: Seed random or use `os.tmpname()`.

### H4. Non-Atomic UCI Updates
**File**: `update_subscriptions.lua:323, 378-388`

Multiple commits mid-flow. Failure after node update → broken config → FATAL handler restarts on broken state, no rollback.

**Fix**: Single commit at end + backup/rollback in FATAL.

### H5. UCI Commit Return Never Checked
**File**: `update_subscriptions.lua:170, 323, etc.`

Read-only FS → silent commit failure → service restarts with old config, logs "success."

**Fix**: `if not uci:commit(CFG) then error(...) end`

### H6. Port Override on URIs with Path
**File**: `subscription_parser.lua:36-37`

`authority` regex stops at `?`/`#`, not `/`. `vless://...@host:8443/path?query` → port detection fails → default port used → wrong server.

**Fix**: `rest:match("^([^?#/]*)")` — add `/` to exclusion.

### H7. Firewall: No Rollback on Partial Application
**File**: `firewall.sh:518-519`

All iptables best-effort, always `exit 0`. Critical rule failure → half-applied rules, traffic leaks.

**Fix**: Error flag + `stop_fw` + `exit 1` on failure.

### H8. Firewall: Wrong Warning for proxy_mainland_china + Empty CN
**File**: `firewall.sh:184-188`

Empty CN set + `proxy_mainland_china` → `! --match-set cn` always matches → RETURN all → **proxies NOTHING** (silent kill-switch). Warning says "proxy all."

**Fix**: Fatal error for this combination.

### H9. Init: Start Failure Leaves Broken State
**File**: `init.d/homeproxy:48-166`

Config check fails at line 57/67, but routing rules (93-94), tun (105-107), cron (78) already applied. No rollback.

**Fix**: Reorder — validate all configs before mutating state.

### H10. Init: reload_service Leaks Tun Device
**File**: `init.d/homeproxy:261-265`

`stop_service` doesn't call `service_stopped` → `singtun0` never deleted on reload.

**Fix**: Call `service_stopped` from `stop_service`.

### H11. Init: Firewall Failure Ignored, firewall.active Still Written
**File**: `init.d/homeproxy:165-166`

Exit code unchecked. `lan_proxy_mode=disabled` → no rules but flag set. Status readers get false positive.

**Fix**: Check exit code, gate flag on success + mode.

### H12. Init: Command Injection via auto_update_time
**File**: `init.d/homeproxy:78`

UCI value written to crontab unvalidated. `auto_update_time='2 ; rm -rf / #'` → executed by cron.

**Fix**: Validate integer 0-23 before writing.

### H13. Install: Backup Failure Silently Swallowed
**File**: `install.sh:162-166`

`|| tar ... /dev/null || true` → empty backup on disk full → rollback restores nothing.

**Fix**: Check backup success, `die` on failure.

### H14. Install: Rollback Extraction Errors Suppressed
**File**: `install.sh:88`

`2>/dev/null` hides corrupt tarball → partial restore, logs "complete."

**Fix**: Check tar exit, verify key files exist.

### H15. Install: Non-Atomic File Writes
**File**: `install.sh:240, 224-230`

Direct `cp`/`cat >` to destination. SIGPIPE from `curl | sh` → partial `.lua` → syntax error.

**Fix**: Write temp, then rename.

### H16. Generate: urltest with Empty Node List → Invalid Config
**File**: `generate_client.lua:537-547`

Empty `main_urltest_nodes` → `outbounds = {}` → `clean` drops it → sing-box rejects ("outbounds required"). Init.d retry doesn't recover (main outbound, not probe).

**Fix**: Guard — if empty, fall back to direct/block outbound.

---

## 🟡 MEDIUM (Top 20 of 34)

### Config Generation

| ID | File | Issue |
|----|------|-------|
| M1 | generate_client:492 | Custom mode `dns.final` → dangling `cfg-local-dns-dns` (no section exists) |
| M2 | generate_client:121 | `dns_strategy` vs `default_strategy` name mismatch → strategy silently ignored |
| M3 | generate_client:397 | DNS `detour` nil in tproxy/tun-only mode → direct DNS routed via proxy |
| M4 | generate_client:648 | `domain_keyword` (substring) for direct/proxy lists — overly broad, inconsistent with dnsmasq suffix matching |
| M5 | generate_client:656 | Hardcoded jsdelivr `@rule-set-unstable` URLs, no fallback |
| M6 | generate_client:344 | `get_outbound("any-out")` returns `"any"` — tag never created |

### Subscription Parser

| ID | File | Issue |
|----|------|-------|
| M7 | subscription_parser:132 | vmess base64 not stripped of `#fragment` → corrupted JSON |
| M8 | subscription_parser:154,187,204,217 | TLS boolean variants inconsistent (`"1"` vs `"true"` vs `true`) |
| M9 | subscription_parser:262 | `filter_check` crashes on `nil` keywords (`#keywords` on nil) |
| M10 | subscription_parser:52 | No per-type required-field validation (password, uuid, etc.) |

### homeproxy.lua

| ID | File | Issue |
|----|------|-------|
| M11 | homeproxy:127 | `is_hostname` accepts invalid labels (`a-.b`, `a..b`) |
| M12 | homeproxy:287 | `clean()` isarray drops non-sequential numeric keys |
| M13 | homeproxy:349 | curl missing `-L` → redirect HTML returned as subscription content |
| M14 | homeproxy:162 | Base64 invalid chars silently skipped, not rejected |
| M15 | homeproxy:76 | `strToTime` double-suffix: `"30m"` → `"30ms"` (30ms not 30min) |

### Update/Firewall/Init

| ID | File | Issue |
|----|------|-------|
| M16 | update_subscriptions | No concurrency lock → cron + manual update clobber each other |
| M17 | firewall:8 | `set -u` aborts on missing `$1` |
| M18 | firewall:179 | Invalid `routing_mode` silently proxies all |
| M19 | firewall:389 | Gaming mode port filter not bypassed in TUN (contradicts comment) |
| M20 | init.d:295 | Migration failure non-fatal → inconsistent UCI, service starts anyway |

*(14 more MEDIUM issues in detailed findings)*

---

## 🟢 LOW (Summary — 28+ issues)

**homeproxy.lua**: Leading zeros in IP, no recursion depth limit in `clean()`, `split("")` returns `{""}`, `log()` spawns mkdir every call, `urldecode` applies `+`→space unconditionally

**subscription_parser**: Redundant address check, `ws_path=""` not coerced to `/`, `aslist` coerces non-strings

**firewall**: Empty interface list not warned, `lan_net6` only first prefix, DNS redirect ignores `lan_proxy_mode`, `routing_port` not validated, missing `2>/dev/null` on critical calls

**init.d**: No `set -u` (violates repo style), `respawn` no bounds → crash loop, `echo -e` portability, log truncation after `procd_close_instance`

**install.sh**: `/tmp/hp_sb` leaked on error, `ps w | grep` vs `pgrep` inconsistency, `rm -rf /etc/homeproxy` before symlink check

**generate_client**: `sniff_override` read but never applied, `hysteria_protocol` stored but not emitted, IPv6 nodes with `ipv6_support=0` no warning

---

## ✅ POSITIVE FINDINGS

1. **Consistent `shellQuote`** — all os.execute/io.popen calls safe ✓
2. **Fail-closed feature detection** — probe failure → all features false ✓
3. **Preserve-on-empty-fetch** — failed subscription doesn't wipe nodes ✓
4. **Idempotent iptables** — `-D` before `-A`, proper teardown ✓
5. **Within-fetch dedup** — confHash + nameHash ✓
6. **Modular design** — subscription_parser extraction clean ✓
7. **Proper IPv6 bracket handling** ✓
8. **No TODO/FIXME/HACK** — clean codebase ✓
9. **Comprehensive pcall wrappers** ✓
10. **DNS rule structure correct** — RDRC fallback, anti-ECH, geosite split ✓
11. **Route rule ordering correct** — sniff → direct-domain → UDP → final ✓
12. **No traffic leak through sing-box** — CN bypass happens before sing-box ✓

---

## FIX PRIORITY

### 🔥 Week 1: Security + Data Loss (7 issues)

| # | Issue | Effort |
|---|-------|--------|
| C1 | Cross-subscription collision | 2h |
| C2 | Download checksum verification | 4h |
| C5 | Reject non-HTTPS URLs | 0.5h |
| C6 | Tarball path-traversal | 2h |
| H12 | Command injection in cron | 0.5h |
| C3 | Rollback resources/ handling | 2h |
| C4 | die() triggers rollback | 3h |

### 📋 Week 2: Correctness (10 issues)

| # | Issue | Effort |
|---|-------|--------|
| H1 | Node update logic | 1h |
| H2 | Write error checking + atomic | 2h |
| H4/H5 | Single UCI commit + rollback | 4h |
| H6 | Port override regex fix | 0.5h |
| H8 | proxy_mainland_china warning | 1h |
| H9 | Init start rollback | 3h |
| H10 | Tun device leak | 0.5h |
| H16 | urltest empty node guard | 1h |
| M1 | Custom mode dns.final fix | 1h |
| M2 | dns_strategy name alignment | 0.5h |

### 🔧 Week 3: Robustness (20 issues)

| Area | Issues | Effort |
|------|--------|--------|
| install.sh | H13-H16 (backup, extraction, atomic, staging) | 6h |
| firewall.sh | H7, M17-M19 | 4h |
| generate_client | M3-M6 | 4h |
| subscription_parser | M7-M10 | 3h |
| homeproxy.lua | M11-M15 | 4h |
| update_subscriptions | M16 | 2h |
| init.d | H11, M20 | 2h |

**Total estimated effort**: ~3 weeks (1 engineer) to production-ready

---

## TESTING CHECKLIST

### Must Test Before Release

- [ ] Two subscriptions with identical node labels (C1)
- [ ] MITM attack on install (C2/C5/C6) — verify rejection
- [ ] Rollback with resources/ (C3) — verify geodata intact
- [ ] `curl | sh` interrupted with SIGPIPE (C4/H15) — verify rollback
- [ ] Filesystem full during config generation (H2)
- [ ] Subscription URL change while old has nodes (H4)
- [ ] Concurrent manual + cron update (M16)
- [ ] Config check fail after routing applied (H9)
- [ ] Rapid reloads during WAN flap (H10)
- [ ] `proxy_mainland_china` with empty CN ipset (H8)
- [ ] urltest main node with empty list (H16)
- [ ] Custom routing mode with stock config (M1)
- [ ] `auto_update_time` with shell metachars (H12)

### Should Test

- [ ] Node with new fields on subscription refresh (H1)
- [ ] vless/trojan URI with path before query (H6)
- [ ] vmess link with `#fragment` (M7)
- [ ] TLS `insecure=true` variant links (M8)
- [ ] tproxy-only mode DNS resolution (M3)
- [ ] Redirected subscription URL (M13)
- [ ] Duration input with existing suffix (M15)
- [ ] Invalid routing_mode typo (M18)
- [ ] Gaming mode in TUN vs redirect (M19)

---

## ASSESSMENT BY FILE

| File | LoC | Grade | Critical Issues |
|------|-----|-------|-----------------|
| `update_subscriptions.lua` | 388 | C+ | C1 (collision), H1 (update), H4 (atomic) |
| `subscription_parser.lua` | 274 | A- | H6 (port), M7-M10 |
| `homeproxy.lua` | 363 | B+ | H2 (write), H3 (temp), M11-M15 |
| `generate_client.lua` | 739 | B+ | H16 (urltest), M1-M6 |
| `firewall.sh` | 519 | B | H7 (rollback), H8 (warning), M17-M19 |
| `init.d/homeproxy` | 270 | B- | H9 (rollback), H10 (tun), H12 (injection) |
| `install.sh` | 331 | C+ | C2-C6 (security), H13-H16 (robustness) |

**Weakest files**: `install.sh` (security), `update_subscriptions.lua` (data integrity)  
**Strongest files**: `subscription_parser.lua` (clean module), `generate_client.lua` (complex but mostly correct)

---

## DETAILED FINDINGS COUNT

| File | Critical | High | Medium | Low | Total |
|------|----------|------|--------|-----|-------|
| update_subscriptions.lua | 1 | 4 | 9 | 5 | 19 |
| install.sh | 4 | 6 | 7 | 7 | 24 |
| firewall.sh | 0 | 2 | 10 | 8 | 20 |
| init.d/homeproxy | 0 | 5 | 10 | 9 | 24 |
| homeproxy.lua | 0 | 2 | 6 | 17 | 25 |
| subscription_parser.lua | 0 | 1 | 4 | 8 | 13 |
| generate_client.lua | 0 | 1 | 13 | 7 | 21 |
| **Cross-cutting** | 1 | — | — | — | 1 |
| **Total** | **6** | **16** | **34** | **28+** | **84+** |

---

## CONCLUSION

The homeproxy codebase has **good engineering fundamentals** but needs focused work before production deployment:

1. **install.sh** is the highest-risk file — 4 CRITICAL security issues (no checksum, HTTP allowed, path traversal, rollback gaps). For a `curl | sh` installer on a traffic-intercepting router, these are unacceptable.

2. **update_subscriptions.lua** has the worst correctness bug — C1 cross-subscription collision causes silent data loss on the most common real-world setup (multiple subs with same labels).

3. **init.d/homeproxy** needs architectural improvement — no rollback on start failure, tun device leaks, command injection vector.

4. **generate_client.lua** is complex but mostly correct — main risks are edge cases (empty urltest, custom mode defaults, DNS detour in non-redirect modes).

5. **firewall.sh** is solid but needs input validation and rollback — wrong warning for proxy_mainland_china is operationally dangerous.

6. **subscription_parser.lua** and **homeproxy.lua** are the strongest files — issues are mostly edge cases and robustness improvements.

**Recommendation**: Fix Week 1 items (7 issues, ~2 days) → beta-ready. Fix Week 2 items (10 issues, ~5 days) → production-ready. Address Week 3 items in maintenance.