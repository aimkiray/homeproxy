#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy subscription updater (Lua port of update_subscriptions.uc).
-- Fetches subscription URLs, parses common share-link schemes (ss, vmess,
-- vless, trojan, hysteria2, http(s), socks, anytls) and SIP008, then writes
-- nodes to /etc/config/homeproxy. Protocol parsing and the meow legality
-- precheck (spec-meow-migration-A §4.4/§9.1) are delegated to
-- subscription_parser.lua; nodes it rejects never reach UCI -- they are
-- logged with a reason, counted, and merged into unsupported-nodes.json.
-- Requires: lua, uci binding, luci.json, md5sum, wget/curl.

package.path = (os.getenv("HP_LUAPATH") or "/usr/lib/homeproxy") .. "/?.lua;" .. package.path

local hp        = require("homeproxy")
local sharelink = require("subscription_parser")
local uci       = require("uci").cursor(os.getenv("HP_CONFDIR") or "/etc/config")

local CFG = "homeproxy"

local UCIMAIN = "config"
local UCINODE = "node"
local UCISUB  = "subscription"

local function isEmpty(v) return hp.isEmpty(v) end
local function push(t, v) t[#t + 1] = v end
local function log(msg) hp.log(msg, "SUBSCRIBE") end

-- Concurrency lock: prevent cron + manual update from clobbering each other.
-- mkdir() is the only atomic check-and-create primitive available here --
-- the old timestamp file could be written simultaneously by two updaters
-- (check passes for both, both write, both proceed).  Stale detection is
-- pid-liveness FIRST: this run legitimately holds the lock past 120s
-- (multi-URL fetches), so mtime alone must never kill a live holder. A dead
-- pid -> reclaim at once; a pid-less lock (older build, or the window
-- before the holder writes its pid) falls back to the >120s mtime
-- heuristic. RUN_DIR is tmpfs so a stale lock never survives a reboot.
-- Shared with cgi-bin/api, init.d, the homeproxy CLI, update_crond.sh and
-- add_nodes.lua: serializes all writers to the homeproxy UCI package.
local lock_dir = hp.RUN_DIR .. "/uci-write.lock.d"
local MAX_LOCK_AGE = 120  -- seconds, pid-less fallback only
local lock_held = false
hp.mkdir_p(hp.RUN_DIR)
local function self_pid()
	local f = io.open("/proc/self/status")
	if not f then return nil end
	local s = f:read("*a"); f:close()
	return s and s:match("Pid:%s*(%d+)")
end
local function lock_is_live()
	local pf = io.open(lock_dir .. "/pid")
	local pid = pf and tonumber((pf:read("*a") or ""):match("%d+"))
	if pf then pf:close() end
	if pid then
		if os.execute("kill -0 " .. pid .. " 2>/dev/null") == 0 then
			return true
		end
		-- Holder is provably dead: reclaim regardless of lock age.
		os.execute("rm -f " .. hp.shellQuote(lock_dir .. "/pid"))
		os.execute("rmdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null")
		return false
	end
	-- No pid to check: fall back to the mtime heuristic.
	local h = io.popen("stat -c %Y " .. hp.shellQuote(lock_dir) .. " 2>/dev/null")
	local mt = h and tonumber(hp.trim(h:read("*a") or "")) or nil
	if h then h:close() end
	if mt == nil then return true end  -- cannot age it; assume live
	local age = os.time() - mt
	if age < MAX_LOCK_AGE then
		-- A negative age (backward clock step) is treated as live too:
		-- never reclaim a lock we cannot prove dead.
		return true
	end
	os.execute("rmdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null")
	return false
end
local function acquire_lock()
	for _ = 1, 15 do
		if os.execute("mkdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null") == 0 then
			local pid = self_pid()
			if pid then
				local f = io.open(lock_dir .. "/pid", "w")
				if f then f:write(tostring(pid)); f:close() end
			end
			lock_held = true
			return true
		end
		if lock_is_live() then os.execute("sleep 1") end
	end
	return false
end
local function release_lock()
	if lock_held then
		os.execute("rm -f " .. hp.shellQuote(lock_dir .. "/pid"))
		os.execute("rmdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null")
		lock_held = false
	end
end
if not acquire_lock() then
	-- Nonzero: a skipped update is NOT a success -- callers (web/CLI) must
	-- not treat it as "nodes refreshed" (e.g. by restarting the service).
	os.exit(3)
end

-- Snapshot the UCI package INSIDE the lock: loading before acquire_lock()
-- would freeze pre-lock state, and the post-fetch commit would then
-- clobber changes a cooperating writer staged in between (B3-U3).
local load_ok, load_err = pcall(function() uci:load(CFG) end)
if not load_ok then
	release_lock()
	log("[FATAL ERROR] uci:load(" .. CFG .. "): " .. tostring(load_err))
	os.exit(1)
end

local allow_insecure    = uci:get(CFG, UCISUB, "allow_insecure") or "0"
local filter_mode        = uci:get(CFG, UCISUB, "filter_nodes") or "disabled"
local filter_keywords    = uci:get(CFG, UCISUB, "filter_keywords") or {}
local packet_encoding    = uci:get(CFG, UCISUB, "packet_encoding") or "xudp"
local subscription_urls  = uci:get(CFG, UCISUB, "subscription_url") or {}
local user_agent         = uci:get(CFG, UCISUB, "user_agent")
local via_proxy          = uci:get(CFG, UCISUB, "update_via_proxy") or "0"
local mixed_port         = uci:get(CFG, "infra", "mixed_port") or "5330"

local routing_mode = uci:get(CFG, UCIMAIN, "routing_mode") or "bypass_mainland_china"
local main_node, main_udp_node
if routing_mode ~= "custom" then
	main_node = uci:get(CFG, UCIMAIN, "main_node") or "nil"
	main_udp_node = uci:get(CFG, UCIMAIN, "main_udp_node") or "nil"
end

if type(subscription_urls) ~= "table" then subscription_urls = { subscription_urls } end
if type(filter_keywords) ~= "table" then filter_keywords = { filter_keywords } end

local function filter_check(name)
	return sharelink.filter_check(hp, name, filter_mode, filter_keywords)
end

---------------------------------------------------------------------------
-- meow feature detection (spec-meow-migration-A §9.3). Upstream used
-- ubus("luci.homeproxy", "singbox_get_features"), unavailable on LuCI-less
-- routers. We probe the binary with minimal YAML configs: `meow -t` with
-- "strict":true turns an absent feature (unsupported proxy/listener type)
-- into a nonzero exit instead of a warn-and-skip pass.
-- Cache: /var/run/homeproxy/meow-features.json keyed by binary signature
-- (path + `meow --version` output + binary mtime, spec §8.4).
---------------------------------------------------------------------------
local MEOW_FEATURE_KEYS = {
	"with_quic", "with_utls", "with_hysteria", "with_ss_listener",
	"with_ss", "with_trojan", "with_vmess", "with_snell", "with_anytls",
}

local function meow_bin()
	-- Spec §10 env names: HP_MEOW / HP_MEOW_BIN both point at the binary.
	for _, var in ipairs({ "HP_MEOW_BIN", "HP_MEOW" }) do
		local p = os.getenv(var)
		if p and p ~= "" then local f = io.open(p, "rb"); if f then f:close(); return p end end
	end
	local f = io.popen("command -v meow 2>/dev/null")
	if f then local v = hp.trim(f:read("*a") or ""); f:close(); if v ~= "" then return v end end
	for _, cand in ipairs({ "/usr/bin/meow", "/data/other_vol/bin/meow" }) do
		local g = io.open(cand, "rb")
		if g then g:close(); return cand end
	end
	return "/usr/bin/meow"
end

local function exec_ok(code) return code == 0 or code == true end

local function meow_signature(bin)
	-- Spec §9.3 signature = hash(bin_path + `meow --version` output); we add
	-- binary mtime so a side-loaded same-version binary also invalidates.
	-- No sha256 helper exists on the router -- hp.md5 is the available hash.
	local p = io.popen(hp.shellQuote(bin) .. " --version 2>/dev/null")
	local version = p and hp.trim(p:read("*a") or "") or ""
	if p then p:close() end
	local h = io.popen("stat -c %Y " .. hp.shellQuote(bin) .. " 2>/dev/null")
	local mtime = h and hp.trim(h:read("*a") or "") or ""
	if h then h:close() end
	if version == "" then
		-- Binary cannot answer --version: return nil so callers never match
		-- or write a cache entry (an all-false probe from a broken meow must
		-- not be served from cache forever after the binary is fixed).
		return nil
	end
	return hp.md5(bin .. "\n" .. version .. "\n" .. (mtime ~= "" and mtime or "0"))
end

local function read_feature_cache(signature)
	local raw = hp.readfile(hp.RUN_DIR .. "/meow-features.json")
	if isEmpty(raw) then return nil end
	local ok, data = pcall(hp.decode_json, raw)
	if not ok or type(data) ~= "table" or data.signature ~= signature
		or type(data.features) ~= "table" then
		return nil
	end
	-- Reject corrupted cache entries: every feature flag must be a boolean.
	local f = data.features
	for _, k in ipairs(MEOW_FEATURE_KEYS) do
		if type(f[k]) ~= "boolean" then return nil end
	end
	return f
end

-- Minimal probe bodies (JSON text is valid YAML 1.2 for meow's parser).
-- "strict":true is REQUIRED: without it `meow -t` warns-and-skips an
-- unparseable proxy and still exits 0, so the probe could not discriminate.
local MEOW_PROBES = {
	-- with_quic == hysteria2 availability (spec D14).
	{ key = "with_quic",
	  yaml = '{"mode":"rule","strict":true,"proxies":[{"name":"q","type":"hysteria2","server":"127.0.0.1","port":443,"password":"p","sni":"n"}]}' },
	-- with_utls == vless client-fingerprint availability.
	{ key = "with_utls",
	  yaml = '{"mode":"rule","strict":true,"proxies":[{"name":"u","type":"vless","server":"127.0.0.1","port":443,"uuid":"00000000-0000-0000-0000-000000000000","tls":true,"servername":"n","client-fingerprint":"chrome"}]}' },
	-- with_ss_listener == listeners:[type:shadowsocks] (server side feature).
	{ key = "with_ss_listener",
	  yaml = '{"mode":"rule","strict":true,"listeners":[{"name":"s","type":"shadowsocks","listen":"127.0.0.1","port":18388,"cipher":"aes-128-gcm","password":"p"}]}' },
	{ key = "with_ss",
	  yaml = '{"mode":"rule","strict":true,"proxies":[{"name":"x","type":"ss","server":"127.0.0.1","port":443,"cipher":"aes-128-gcm","password":"p"}]}' },
	{ key = "with_trojan",
	  yaml = '{"mode":"rule","strict":true,"proxies":[{"name":"x","type":"trojan","server":"127.0.0.1","port":443,"password":"p","sni":"n"}]}' },
	{ key = "with_vmess",
	  yaml = '{"mode":"rule","strict":true,"proxies":[{"name":"x","type":"vmess","server":"127.0.0.1","port":443,"uuid":"00000000-0000-0000-0000-000000000000","alterId":0,"cipher":"auto"}]}' },
	{ key = "with_snell",
	  yaml = '{"mode":"rule","strict":true,"proxies":[{"name":"x","type":"snell","server":"127.0.0.1","port":443,"psk":"p","version":3}]}' },
	{ key = "with_anytls",
	  yaml = '{"mode":"rule","strict":true,"proxies":[{"name":"x","type":"anytls","server":"127.0.0.1","port":443,"password":"p","sni":"n"}]}' },
}

local function detect_features()
	local feat = {}
	for _, k in ipairs(MEOW_FEATURE_KEYS) do feat[k] = false end
	-- meow implements hysteria2 only; hysteria v1 is always absent (D14).
	feat.with_hysteria = false
	local bin = meow_bin()
	local signature = meow_signature(bin)
	local cached = signature and read_feature_cache(signature)
	if cached then
		log("Using cached meow feature detection.")
		return cached
	end
	for _, probe in ipairs(MEOW_PROBES) do
		-- One tmp file per probe + a checked write (L28): a shared file masks
		-- a failed write behind the previous probe's leftover contents.
		local tmp = os.tmpname()
		if hp.writefile(tmp, probe.yaml .. "\n")
			and exec_ok(os.execute(hp.shellQuote(bin) .. " -t -f " .. hp.shellQuote(tmp) .. " >/dev/null 2>&1")) then
			feat[probe.key] = true
		end
		os.remove(tmp)
	end
	-- Do not cache when the binary could not even report its version: an
	-- all-false probe caused by a missing/broken meow would otherwise be
	-- served from cache forever after the binary is fixed.
	if not signature then
		log("meow binary unresponsive; feature cache skipped.")
		return feat
	end
	local cache = hp.RUN_DIR .. "/meow-features.json"
	-- Keep the temporary cache beside the final file so rename stays atomic
	-- even when /tmp and RUN_DIR are different mounts.
	local temp_cache = cache .. ".tmp." .. tostring(os.time()) .. "." .. tostring(math.random(100000, 999999))
	if hp.writefile(temp_cache, hp.encode_json({ signature = signature, features = feat })) then
		if not os.rename(temp_cache, cache) then os.remove(temp_cache) end
	else
		os.remove(temp_cache)
	end
	log(string.format("meow features: quic=%s utls=%s ss_listener=%s ss=%s trojan=%s vmess=%s snell=%s anytls=%s",
		tostring(feat.with_quic), tostring(feat.with_utls), tostring(feat.with_ss_listener),
		tostring(feat.with_ss), tostring(feat.with_trojan), tostring(feat.with_vmess),
		tostring(feat.with_snell), tostring(feat.with_anytls)))
	return feat
end

-- Feature detection writes a cache under RUN_DIR before main() starts.
hp.mkdir_p(hp.RUN_DIR)
local sf_ok, sf = pcall(detect_features)
-- Fail closed when feature probing itself fails.  Assuming features exist
-- can write nodes that the installed meow cannot load; an unavailable
-- optional feature should only skip those nodes, not break the service.
local meow_features = (sf_ok and sf) or (function()
	-- All-false: validate_node gates on explicit `false`, so a crashed probe
	-- fails closed -- feature-gated node types get skipped until a working
	-- meow binary restores detection.
	local f = {}
	for _, k in ipairs(MEOW_FEATURE_KEYS) do f[k] = false end
	return f
end)()

-- Bind the subscription_parser module with runtime dependencies.
-- `log` lets the parser surface loud warnings (e.g. vless xhttp degrade).
local parser_opts = { features = meow_features, packet_encoding = packet_encoding, log = log }
local function parse_uri(uri)
	return sharelink.parse_uri(hp, parser_opts, uri)
end
local function decode_subscription_body(res)
	return sharelink.decode_subscription_body(hp, res)
end

local node_cache, node_result = {}, {}

-- Loopback/unspecified/link-local subscription hosts are never legitimate:
-- the router would fetch them blind (SSRF surface), and URLs can also be
-- written via UCI directly, bypassing the web API's validation.
-- One numeric IPv4 part: decimal, octal ("0NN"), or hex ("0xNN") spelling
-- (L27: resolvers read "0177.0.0.1" as 127.0.0.1).
local function v4_octet(s)
	local hx = s:match("^0[xX](%x+)$")
	if hx then return tonumber(hx, 16) end
	local oc = s:match("^0(%d+)$")
	if oc then return tonumber(oc, 8) end
	if s:match("^%d+$") then return tonumber(s, 10) end
	return nil
end

-- Numeric IPv4 in any resolver spelling (inet_aton): 1-4 dotted parts with
-- decimal/octal/hex parts, a bare integer ("2130706433"/"0x7f000001"), or
-- an ::ffff:-mapped IPv6 literal. Returns a,b,c,d octets, else nil (L27).
local function ipv4_from_host(h)
	if h:sub(1, 7) == "::ffff:" then
		local rest = h:sub(8)
		local hi, lo = rest:match("^(%x+):(%x+)$")
		if hi then
			local hi_n, lo_n = tonumber(hi, 16), tonumber(lo, 16)
			if not (hi_n and lo_n and hi_n <= 0xFFFF and lo_n <= 0xFFFF) then return nil end
			local n = hi_n * 65536 + lo_n
			return math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
				math.floor(n / 256) % 256, n % 256
		end
		if rest:find(":", 1, true) then return nil end
		h = rest -- "::ffff:a.b.c.d": validate the dotted tail as IPv4
	end
	local raw = {}
	for part in h:gmatch("[^%.]+") do raw[#raw + 1] = part end
	if #raw < 1 or #raw > 4 or table.concat(raw, ".") ~= h then return nil end
	local n, nparts = 0, #raw
	for i = 1, nparts do
		local v = v4_octet(raw[i])
		if not v then return nil end
		if i < nparts then
			if v > 255 then return nil end
			n = n * 256 + v
		else
			-- inet_aton packing: the last part holds the remaining bytes
			-- ("127.1" == 127.0.0.1; "2130706433" == 127.0.0.1).
			local wide = 2 ^ ((5 - nparts) * 8)
			if v >= wide then return nil end
			n = n * wide + v
		end
	end
	return math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
		math.floor(n / 256) % 256, n % 256
end

-- The router's own interface addresses, normalized the same way hosts are
-- (lowercase, %-zone stripped, leading hextet zeros removed): same rule as
-- the CGI's is_own_ip — a subscription pointed back at the box is
-- SSRF/DNS-loop surface regardless of subnet class.
local own_ip_set
local function is_own_ip_addr(ip)
	if not own_ip_set then
		own_ip_set = {}
		local h = io.popen("ip -o addr show 2>/dev/null")
		if h then
			for l in h:lines() do
				local a = l:match("inet6?%s+(%S+)")
				if a then
					a = a:gsub("/.*$", ""):gsub("%%.*$", ""):lower()
					own_ip_set[a] = true
					own_ip_set[a:gsub("0*(%x+)", "%1")] = true
				end
			end
			h:close()
		end
	end
	return own_ip_set[tostring(ip)] == true
end

local function is_local_url(url)
	local u = hp.parseURL(url)
	local h = u and u.hostname or nil
	if not h then
		-- parseURL rejects IPv4 shorthand ("127.1") and other spellings it
		-- cannot validate, but the fetcher would still resolve them to
		-- loopback: extract the raw authority host rather than fail open.
		local auth = tostring(url):match("^%a[%w+.-]*://([^?#/]*)")
		if auth then
			auth = auth:match("^.*@(.*)$") or auth
			h = auth:match("^%[(.-)%]") or auth:match("^([^:]*)")
		end
	end
	if not h or h == "" then return false end
	-- A DNS resolver treats "X." as "X" and is case-insensitive; normalize
	-- both before comparing (L27). IPv6 hextets additionally lose leading
	-- zeros so "00::1", "::0001" and expanded v4-mapped spellings cannot
	-- evade the literal checks below (mirrors cgi-bin/api is_local_addr).
	h = h:gsub("^%[(.*)%]$", "%1"):gsub("%.$", ""):lower()
	local hn = h:gsub("0*(%x+)", "%1")
	if h == "localhost" or h:match("%.localhost$") then
		return true
	end
	if is_own_ip_addr(h) or is_own_ip_addr(hn) then
		return true
	end
	-- v6 arms apply only to colon-bearing candidates, so a hostname like
	-- "ff.example.com" can never trip the ranges below.
	if h:find(":", 1, true) then
		local g0 = tonumber(hn:match("^(%x+)") or "", 16)
		if hn:match("^[0:]*:1$") or hn:match("^[0:]*$")
			or (g0 and ((g0 >= 0xfe80 and g0 <= 0xfeff)      -- link-local + site-local
				or (g0 >= 0xfc00 and g0 <= 0xfdff)           -- ULA
				or g0 >= 0xff00)) then                       -- multicast
			return true
		end
	end
	-- v4-mapped (::ffff:a.b.c.d and hex-group ::ffff:XXXX:XXXX) plus
	-- v4-compatible and NAT64-WKP embeddings: judge the embedded v4 too.
	-- Hex-group decode comes FIRST — a dotted tail only exists in
	-- spelled-out forms, and decoding "0:0:0:0:0:ffff:808:808" via its
	-- last group would misread it as a /8-class address.
	local o1, o2, o3, o4
	if h:find(":", 1, true) then
		local g7, g8 = hn:match("^[0:]*:ffff:(%x+):(%x+)$")
		if not g7 then g7, g8 = hn:match("^[0:]*:(%x+):(%x+)$") end
		if not g7 then g7, g8 = hn:match("^64:ff9b:[0:]*:(%x+):(%x+)$") end
		if g7 then
			local x, y = tonumber(g7, 16), tonumber(g8, 16)
			if x and y and x <= 65535 and y <= 65535 then
				o1, o2 = math.floor(x / 256) % 256, x % 256
				o3, o4 = math.floor(y / 256) % 256, y % 256
			end
		else
			-- Dotted tail only, and only behind the real embedding
			-- prefixes — "[abcd::ef01:192.168.0.1]" is an ordinary v6
			-- address, not an embedding (decoding its tail would desync
			-- from the CGI: stored in UCI yet silently skipped here).
			local head = hn:match("^(.-):%d+%.[%d%.]*$")
			if head then
				local hz = head:gsub("ffff$", "")
				if hz ~= head then
					if hz:match("^[0:]*$") then
						o1, o2, o3, o4 = ipv4_from_host(h:match(":([%d]+%.[%d%.]*)$") or "")
					end
				elseif head:match("^[0:]+$") or head:match("^64:ff9b:[0:]*$") then
					o1, o2, o3, o4 = ipv4_from_host(h:match(":([%d]+%.[%d%.]*)$") or "")
				end
			end
		end
	end
	if not o1 then o1, o2, o3, o4 = ipv4_from_host(h) end
	-- Embedded-v4 spelling of an own address (e.g. ::ffff:<wan-ip>).
	if o1 and is_own_ip_addr(o1 .. "." .. o2 .. "." .. o3 .. "." .. o4) then
		return true
	end
	-- 127/8 loopback, 169.254/16 link-local, 0/8 "this host", plus the
	-- private/bogon space a blind router-side fetch must never target —
	-- identical ranges to the CGI's is_private4.
	if o1 and (o1 == 0 or o1 == 10 or o1 == 127 or o1 >= 224
		or (o1 == 169 and o2 == 254)
		or (o1 == 172 and o2 >= 16 and o2 <= 31)
		or (o1 == 192 and (o2 == 168
			or (o2 == 0 and (o3 == 0 or o3 == 2))
			or (o2 == 88 and o3 == 99)
			or (o2 == 31 and o3 == 196)
			or (o2 == 52 and o3 == 193)
			or (o2 == 175 and o3 == 48)))
		or (o1 == 100 and o2 >= 64 and o2 <= 127)
		or (o1 == 198 and (o2 == 18 or o2 == 19 or (o2 == 51 and o3 == 100)))
		or (o1 == 203 and o2 == 0 and o3 == 113)) then
		return true
	end
	return false
end

local function have_cmd(bin)
	local rc = os.execute("command -v " .. bin .. " >/dev/null 2>&1")
	return rc == 0 or rc == true
end

-- Explicit mixed-port egress for update_via_proxy=1 (spec D15/§9.4). The
-- kernel-side OUTPUT transparent steering this used to rely on is gone, so
-- the fetch must name the mixed listener directly: curl gets `-x`, wget gets
-- http_proxy/https_proxy env vars. via_proxy=0 -> plain hp.wGET.
local function fetch_body(url)
	if via_proxy ~= "1" then
		return hp.wGET(url, user_agent)
	end
	local proxy = "http://127.0.0.1:" .. tostring(mixed_port)
	local qua = hp.shellQuote(user_agent or "Wget/1.21 (HomeProxy, like v2rayN)")
	local qurl = hp.shellQuote(url)
	local qpx = hp.shellQuote(proxy)
	local function try(cmd)
		local r = hp.executeCommand(cmd)
		if r.exitcode == 0 and not isEmpty(r.stdout) then
			return hp.trim(r.stdout)
		end
		return nil
	end
	if url:match("^https://") and have_cmd("curl") then
		local body = try("curl -fsSL -m 20 --max-filesize 16777216 -x " .. qpx .. " -A " .. qua .. " " .. qurl)
		if body then return body end
	end
	if have_cmd("wget") then
		local body = try("http_proxy=" .. qpx .. " https_proxy=" .. qpx
			.. " wget -qO- --user-agent " .. qua .. " --timeout=10 " .. qurl)
		if body then return body end
	end
	return try("curl -fsSL -m 20 --max-filesize 16777216 -x " .. qpx .. " -A " .. qua .. " " .. qurl)
end

-- Nodes the meow precheck dropped this run: kept here so the post-loop
-- merge into unsupported-nodes.json can record them even when the update
-- itself failed (e.g. every entry was a hard-unsupported protocol).
local dropped_records, dropped_kinds = {}, {}

-- Credential-safe identifier for a rejected link: userinfo is stripped so
-- passwords never reach the log/JSON record (M10).
local function link_hint(line, hint)
	if type(line) == "string" then
		local scheme = line:match("^(%w[%w+.-]*)://")
		local auth = line:match("^%w[%w+.-]*://([^?#/]*)")
		if auth then
			-- host:port sits after the LAST '@' -- userinfo may itself
			-- contain '@' (e.g. an unencoded "p@ss"), and taking the first
			-- one would echo the credential into logs/JSON.
			local hostport = auth:match("^.*@(.*)$")
			if not hostport and not auth:match("^[A-Za-z0-9%+%/_%-]+=?=?$") then
				-- A userinfo-less authority is safe to echo only when it is
				-- plainly host:port. A base64-shaped blob (ss://<b64>,
				-- vmess://<b64-json>, ssr://<b64>) may decode to credentials:
				-- collapse those to the scheme hint.
				hostport = auth
			end
			if hostport then
				if #hostport > 80 then hostport = hostport:sub(1, 80) .. "..." end
				if hostport ~= "" then return hostport end
			end
			return scheme or hint or "?"
		end
	end
	return hint or "?"
end

-- Subscription URLs may embed userinfo credentials or token query params:
-- logs must only carry the hostname (M10).
local function url_host(url)
	local u = hp.parseURL(url)
	return u and u.hostname or "(invalid URL)"
end

local function record_drop(name, typ, reason, kind)
	kind = kind or "malformed"
	dropped_kinds[kind] = (dropped_kinds[kind] or 0) + 1
	dropped_records[#dropped_records + 1] = {
		name = name, type = typ or "unknown", reason = reason or "unparseable",
		source = "subscription",
	}
end

-- Rewrite this run's drops into unsupported-nodes.json (spec §4.6 file
-- shape). This file owns the source="subscription" partition -- same merge
-- as generate_server.lua's flush_unsupported: every other writer's records
-- (uci client nodes, server quarantine) pass through untouched, stale
-- subscription records are dropped, and this run's drops are appended.
local function flush_dropped_records()
	local path = hp.RUN_DIR .. "/unsupported-nodes.json"
	local existing = {}
	local raw = hp.readfile(path)
	if not isEmpty(raw) then
		local ok, j = pcall(hp.decode_json, raw)
		if ok and type(j) == "table" then existing = j end
	end
	local seen, merged = {}, {}
	for _, e in ipairs(existing) do
		if type(e) == "table" and e.source ~= "subscription" then
			local k = tostring(e.name) .. "|" .. tostring(e.type) .. "|" .. tostring(e.reason)
			if not seen[k] then merged[#merged + 1] = e; seen[k] = true end
		end
	end
	for _, e in ipairs(dropped_records) do
		local k = tostring(e.name) .. "|" .. tostring(e.type) .. "|" .. tostring(e.reason)
		if not seen[k] then merged[#merged + 1] = e; seen[k] = true end
	end
	if #merged == 0 then
		-- Nothing quarantined anywhere: drop a stale file so `homeproxy
		-- nodes` / the API stop reporting ghosts (F3).
		os.remove(path)
		return
	end
	local tmp = path .. ".tmp." .. tostring(os.time()) .. "." .. tostring(math.random(100000, 999999))
	if hp.writefile(tmp, hp.encode_json(merged)) then
		if not os.rename(tmp, path) then os.remove(tmp) end
	else
		os.remove(tmp)
	end
end

local function dropped_summary()
	local n, parts = 0, {}
	for k, c in pairs(dropped_kinds) do parts[#parts + 1] = k .. "=" .. c; n = n + c end
	if n == 0 then return nil end
	table.sort(parts)
	return n, table.concat(parts, ", ")
end

-- Prune gone node names out of a urltest list UCI option; returns
-- (kept count, whether anything was removed).  Does NOT commit — the caller
-- folds the change into the final atomic commit.
local function prune_urltest_list(opt)
	local list = uci:get(CFG, UCIMAIN, opt) or {}
	if type(list) ~= "table" then list = { list } end
	local kept, changed = {}, false
	for _, v in ipairs(list) do
		local s = uci:get_all(CFG, v)
		if s and s[".type"] == UCINODE then
			kept[#kept + 1] = v
		else
			changed = true
			log("Node " .. tostring(v) .. " is gone, removing from urltest list.")
		end
	end
	if changed then
		if #kept > 0 then uci:set(CFG, UCIMAIN, opt, kept) else uci:delete(CFG, UCIMAIN, opt) end
	end
	return #kept, changed
end

-- Checked commit: aborts hard on persistence failure (H5) instead of silently
-- proceeding with a divergent in-memory/disk state.
local function commit_uci()
	if not uci:commit(CFG) then
		error("uci:commit failed — filesystem may be read-only or full")
	end
end

local function main()
	hp.mkdir_p(hp.RUN_DIR)
	if #subscription_urls == 0 then
		log("No subscription URL configured.")
		return
	end

	if via_proxy ~= "1" then
		log("Stopping service before subscription update.")
		os.execute("/etc/init.d/homeproxy stop >/dev/null 2>&1")
	end

	for _, configured_url in ipairs(subscription_urls) do
			configured_url = hp.trim(configured_url)
			if isEmpty(configured_url) then
			elseif not configured_url:match("^https?://") and not configured_url:match("^sip008://") then
				log("Skipping invalid URL: " .. url_host(configured_url))
			elseif is_local_url(configured_url) then
				log("Skipping loopback/link-local URL (SSRF guard): " .. url_host(configured_url))
			else
				-- A fragment identifies a local subscription label, not the remote
				-- resource.  Do not let it create a separate group or reach curl.
				local url = configured_url:gsub("#.*$", "")
				local groupHash = hp.md5(url)
				node_cache[groupHash] = {}
				local group_nodes = {}

				local fetch_url = url
				if fetch_url:match("^sip008://") then
					fetch_url = fetch_url:gsub("^sip008://", "https://")
				end

			local res = fetch_body(fetch_url)
			if isEmpty(res) then
				log("Failed to fetch: " .. url_host(fetch_url))
			else
				-- try JSON (SIP008) first, else base64 node list
				local nodes
				local ok, j = pcall(hp.decode_json, res)
				if ok and type(j) == "table" then
					-- Only recognize SIP008 when its first entry has the required
					-- server/method fields; unrelated JSON must fall through.
					local candidate = (type(j.servers) == "table") and j.servers
						or (j[1] ~= nil and j) or nil
					-- candidate[1] must be a table: indexing a string/number
					-- element (malformed JSON) would crash the whole update.
					local srvs = candidate and type(candidate[1]) == "table"
						and candidate[1].server and candidate[1].method and candidate or nil
					if srvs then
						nodes = {}
						for _, s in ipairs(srvs) do
							-- Elements past [1] are unguarded: a number/boolean
							-- entry would crash the whole update on s.remarks.
							if type(s) == "table" and s.server and s.method then
								push(nodes, { nodetype = "sip008",
									remarks = (type(s.remarks) == "string") and s.remarks or nil,
									server = s.server, server_port = s.server_port,
									method = s.method, password = s.password,
									plugin = s.plugin, plugin_opts = s.plugin_opts })
							end
						end
					end
				end
				if not nodes then
					res = decode_subscription_body(res)
					nodes = hp.split(res, "[\r\n]+")
				end

				local count, dropped = 0, 0
				for _, n in ipairs(nodes) do
					if not isEmpty(n) then
						-- pcall per entry: one malformed link must not abort
						-- the entire subscription update. parse_uri returns
						-- (nil, reason, kind, type/scheme hint) for anything
						-- the meow precheck or the link parser rejected.
						local pok, cfg, reason, kind, hint = pcall(parse_uri, n)
						if not pok then
							log("Node parse error (skipped): " .. tostring(cfg))
							record_drop(link_hint(n, nil), "unknown",
								"parser error: " .. tostring(cfg), "malformed")
							dropped = dropped + 1
							cfg = nil
						elseif isEmpty(cfg) then
							if reason then
								-- §9.1/AC-14: hard-unsupported protocols and
								-- §4.4-illegal fields are dropped loudly and
								-- counted, never silently.
								log(string.format("Skipping node %s: %s", link_hint(n, hint), reason))
								record_drop(link_hint(n, hint), hint, reason, kind)
								dropped = dropped + 1
							end
						end
						if not isEmpty(cfg) then
							local lbl = cfg.label
							cfg.label = nil
							local confHash = hp.md5(hp.encode_json(cfg))
							-- Use namespaced hash to match the section name scheme (C1 fix).
							-- "|" separator: a NUL byte cannot survive the shell pipeline
							-- inside hp.md5 (arg lists are NUL-terminated).
							local nameHash = lbl and hp.md5(groupHash .. "|" .. lbl) or nil
							cfg.label = lbl
							if filter_check(lbl) then
								log("Skipping filtered node: " .. tostring(lbl))
							elseif node_cache[groupHash][confHash] or (nameHash and node_cache[groupHash][nameHash]) then
								log("Skipping duplicate node: " .. tostring(lbl))
							else
								if cfg.tls == "1" and allow_insecure == "1" then
									cfg.tls_insecure = "1"
								end
								if cfg.type == "vless" or cfg.type == "vmess" then
									cfg.packet_encoding = packet_encoding
								end
								cfg.grouphash = groupHash
								push(group_nodes, cfg)
								node_cache[groupHash][confHash] = cfg
								if nameHash then node_cache[groupHash][nameHash] = cfg end
								count = count + 1
							end
						end
					end
				end
				if count == 0 then
					log("No valid node found in " .. url_host(url))
				else
					log(string.format("Fetched %s of %s nodes from %s%s.", count, #nodes, url_host(url),
						dropped > 0 and string.format(" (%s dropped by meow precheck)", dropped) or ""))
				end
				if count > 0 then push(node_result, group_nodes) end
			end
		end
	end

	-- Persist precheck drops + log the aggregate even if no node survived:
	-- the unsupported nodes are exactly the information a failed update owes
	-- the operator.
	local dn, dparts = dropped_summary()
	if dn then
		log(string.format("Subscription precheck dropped %s node(s): %s.", dn, dparts))
	end
	flush_dropped_records()

	if isEmpty(node_result) or #node_result == 0 then
		log("Failed to update subscriptions: no valid node found.")
		if via_proxy ~= "1" then
			log("Starting service...")
			-- Hold time ends here: init.d re-enters the same lockdir for
			-- migrate, and a held lock would cost it the full retry budget.
			release_lock()
			os.execute("/etc/init.d/homeproxy start >/dev/null 2>&1")
		end
		-- Failure must reach the caller: previously this returned normally
		-- so the web API reported a successful update after every fetch died.
		return false
	end

	-- remove stale nodes + update existing.
	-- Collect deletions first: deleting a section inside uci:foreach mutates
	-- the very list being iterated.
	local added, removed, nodes_changed = 0, 0, false
	local to_delete = {}
	uci:foreach(CFG, UCINODE, function(cfg)
		if not cfg.grouphash then return end -- user-created node
		local gh = cfg.grouphash
		-- An empty cache means this subscription failed or returned no usable
		-- nodes.  Preserve its old nodes to avoid destructive transient updates.
		if node_cache[gh] and next(node_cache[gh]) == nil then
			return
		elseif not node_cache[gh] or not node_cache[gh][cfg[".name"]] then
			to_delete[#to_delete + 1] = cfg[".name"]
			log("Removing node: " .. tostring(cfg.label))
		else
			local newcfg = node_cache[gh][cfg[".name"]]
			-- Apply all fields from the new node (handles field additions).
			for k, v in pairs(newcfg) do
				if k:sub(1, 1) ~= "." and k ~= "isExisting" then
					local old = cfg[k]
					local same
					if type(old) == "table" and type(v) == "table" and #old == #v then
						same = true
						for i = 1, #v do if tostring(old[i]) ~= tostring(v[i]) then same = false; break end end
					else
						same = tostring(old) == tostring(v)
					end
					if not same then nodes_changed = true end
					uci:set(CFG, cfg[".name"], k, v)
				end
			end
			-- Delete fields present in the old node but absent from the new.
			for k in pairs(cfg) do
				if k:sub(1, 1) ~= "." and newcfg[k] == nil then
					nodes_changed = true
					uci:delete(CFG, cfg[".name"], k)
				end
			end
			newcfg.isExisting = true
		end
	end)
	for _, sname in ipairs(to_delete) do
		uci:delete(CFG, sname)
		removed = removed + 1
	end

	-- add new nodes
	for _, nodes in ipairs(node_result) do
		for _, node in ipairs(nodes) do
			if not node.isExisting then
				-- Namespace section name by groupHash to prevent cross-subscription
				-- label collisions (C1): two subs with "HK 01" would otherwise
				-- overwrite each other's UCI section every run.
				local nameHash = hp.md5(node.grouphash .. "|" .. tostring(node.label))
				uci:set(CFG, nameHash, "node")
				for k, v in pairs(node) do
					if k ~= "isExisting" then uci:set(CFG, nameHash, k, v) end
				end
				added = added + 1
				log("Adding node: " .. tostring(node.label))
			end
		end
	end

	-- Clean references to nodes just removed: custom-mode routing_node.node /
	-- urltest_nodes pointing at a deleted node would dangle (the generator
	-- used to re-wire the rule onto the previous outbound).
	uci:foreach(CFG, "routing_node", function(s)
		local n = s.node
		if not isEmpty(n) and n ~= "urltest" then
			local sec = uci:get_all(CFG, n)
			if not sec or sec[".type"] ~= UCINODE then
				uci:delete(CFG, s[".name"], "node")
				nodes_changed = true
				log("routing_node " .. tostring(s[".name"]) .. " referenced removed node " .. tostring(n) .. " -- cleared.")
			end
		end
		local l = s.urltest_nodes
		if type(l) == "table" then
			local kept, ch = {}, false
			for _, v in ipairs(l) do
				local sec = uci:get_all(CFG, v)
				if sec and sec[".type"] == UCINODE then kept[#kept + 1] = v else ch = true end
			end
			if ch then
				nodes_changed = true
				if #kept > 0 then uci:set(CFG, s[".name"], "urltest_nodes", kept)
				else uci:delete(CFG, s[".name"], "urltest_nodes") end
			end
		end
	end)

	-- When updating via proxy the service was never stopped, so it must be
	-- restarted whenever the node set actually changed -- previously it was
	-- only restarted when the main node needed repair, so committed nodes
	-- never took effect (H5).
	local need_restart = (via_proxy ~= "1") or added > 0 or removed > 0 or nodes_changed
	-- Prune the urltest member lists UNCONDITIONALLY: stale entries left while
	-- a plain node is active would dangle the moment the user switches to
	-- urltest before the next update run.
	local ut_n, ut_changed = prune_urltest_list("main_urltest_nodes")
	local utu_n, utu_changed = prune_urltest_list("main_udp_urltest_nodes")
	if ut_changed or utu_changed then need_restart = true end
	if not isEmpty(main_node) then
		local first
		uci:foreach(CFG, UCINODE, function(s) first = s[".name"]; return false end)
		if first then
			local function is_node(name)
				local sec = uci:get_all(CFG, name)
				return sec ~= nil and sec[".type"] == UCINODE
			end
			if main_node == "urltest" then
				if ut_n == 0 then
					uci:set(CFG, UCIMAIN, "main_node", first)
					need_restart = true
					log("Main node is gone, switching to the first node.")
				end
			elseif not is_node(main_node) then
				uci:set(CFG, UCIMAIN, "main_node", first)
				need_restart = true
				log("Main node is gone, switching to the first node.")
			end
			if not isEmpty(main_udp_node) and main_udp_node ~= "same" then
				if main_udp_node == "urltest" then
					if utu_n == 0 then
						uci:set(CFG, UCIMAIN, "main_udp_node", first)
						need_restart = true
						log("Main UDP node is gone, switching to the first node.")
					end
				elseif not is_node(main_udp_node) then
					uci:set(CFG, UCIMAIN, "main_udp_node", first)
					need_restart = true
					log("Main UDP node is gone, switching to the first node.")
				end
			end
		else
			uci:set(CFG, UCIMAIN, "main_node", "nil")
			uci:set(CFG, UCIMAIN, "main_udp_node", "nil")
			need_restart = true
			log("No available node, disable tproxy.")
		end
	end

	-- Single atomic commit for all node + main_node + urltest changes (H4).
	commit_uci()

	-- Nothing UCI-bound remains: release BEFORE the service restart so
	-- init.d's migrate step can take the lock instead of spinning its full
	-- retry budget and then running unlocked.
	release_lock()

	if need_restart then
		log("Restarting service...")
		os.execute("/etc/init.d/homeproxy restart >/dev/null 2>&1")
	end
	log(string.format("%s nodes added, %s removed. Successfully updated subscriptions.", added, removed))
end

local ok, res = pcall(main)
if not ok and lock_held then
	-- Drop staged uci deltas: /tmp/.uci persists across processes, so the
	-- next `uci commit homeproxy` by an unrelated caller would otherwise
	-- flush our half-written node set. Skipped once the lock was released
	-- early (post-commit nothing of ours is staged; a revert then would
	-- wipe ANOTHER writer's staged work).
	pcall(function() uci:revert(CFG) end)
end
-- Always release the concurrency lock (no-op if already released early).
release_lock()
if not ok then
	log("[FATAL ERROR] " .. tostring(res))
	if via_proxy ~= "1" then
		os.execute("/etc/init.d/homeproxy stop >/dev/null 2>&1")
		os.execute("/etc/init.d/homeproxy start >/dev/null 2>&1")
	else
		os.execute("/etc/init.d/homeproxy restart >/dev/null 2>&1")
	end
	os.exit(1)
end
if res == false then
	-- main() already logged the reason and recovered the service.
	os.exit(1)
end
