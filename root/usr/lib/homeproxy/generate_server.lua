#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy server config generator (meow-rs kernel).
-- Reads /etc/config/homeproxy `server` sections and emits the meow server
-- config to /var/run/homeproxy/meow-s.yaml. The file holds JSON text,
-- which is valid YAML 1.2 for meow's serde_yaml parser (migration spec
-- 4.1/5). Only `enabled=1` + `type=shadowsocks` sections become
-- `listeners:` entries; every other enabled server section is skipped
-- with a stderr warning and recorded in unsupported-nodes.json
-- (role="server").

package.path = (os.getenv("HP_LUAPATH") or "/usr/lib/homeproxy") .. "/?.lua;" .. package.path

local hp  = require("homeproxy")
local uci = require("uci").cursor(os.getenv("HP_CONFDIR") or "/etc/config")

local UCICONFIG = "homeproxy"
local UCISERVER = "server"
uci:load(UCICONFIG)

local OUT_PATH = hp.RUN_DIR .. "/meow-s.yaml"
local UNSUPPORTED_PATH = hp.RUN_DIR .. "/unsupported-nodes.json"

local function strToInt(v) return hp.strToInt(v) end
local function isEmpty(v) return hp.isEmpty(v) end
local function push(t, v) t[#t + 1] = v end

local log_level = uci:get(UCICONFIG, UCISERVER, "log_level") or "warn"
-- Same mapping as the client generator (spec 4.2): meow's tracing
-- EnvFilter has no fatal/panic levels; they degrade to error. "trace" is
-- not in meow's level whitelist at all -- map it down to debug.
if log_level == "fatal" or log_level == "panic" then log_level = "error" end
if log_level == "trace" then log_level = "debug" end

-- Server-relayed egress is a DIRECT outbound socket; routing-mark tags it
-- with self_mark so client-side steering on the same box never recaptures
-- it (advisory only -- spec 5/D9). routing-mark is a u32 fwmark: clamp or
-- fall back to the infra default rather than emitting a rejected value.
local self_mark = strToInt(uci:get(UCICONFIG, "infra", "self_mark")) or 100
if self_mark < 0 or self_mark > 4294967295 then
	io.stderr:write("homeproxy: WARNING: infra.self_mark=" .. tostring(self_mark)
		.. " is out of u32 range -- using 100\n")
	self_mark = 100
end
local ipv6_support = uci:get(UCICONFIG, "config", "ipv6_support") == "1"

-- Ports the co-located client instance already owns (spec 5): a listener
-- asked to bind one would fail at runtime (meow skips the listener, the
-- process stays up), so warn at generation time. The API controller port
-- is hardcoded in generate_client.lua.
local reserved_ports = { [19290] = true }
for opt, def in pairs({ mixed_port = 5330, redirect_port = 5331, dns_port = 5333, v6_port = 5334 }) do
	reserved_ports[strToInt(uci:get(UCICONFIG, "infra", opt)) or def] = true
end

-- Listen address for every emitted listener: dual-stack wildcard while
-- ipv6_support=1, IPv4-only wildcard otherwise (a "::" bind with IPv6
-- disabled would be a dead listener).
local listen_addr = ipv6_support and "::" or "0.0.0.0"

-- Drop any stale output first: an abort mid-generation must not leave an
-- old meow-s.yaml for init.d's existence check to pick up. RUN_DIR is
-- created up front so both outputs below can always write.
os.remove(OUT_PATH)
hp.mkdir_p(hp.RUN_DIR)

-- Same WAN-resolver discovery as generate_client.lua: loopback/unspecified
-- resolvers point back at local dnsmasq and would loop. The server-side
-- meow resolver exists to resolve SS target domain names.
local function get_wan_dns()
	local function valid_ns(ns)
		if type(ns) == "table" then ns = ns[1] end
		if type(ns) ~= "string" or ns == "" then return nil end
		if ns:match("^127%.") or ns == "::1" or ns == "0.0.0.0" or ns == "::" then return nil end
		return hp.validation("ipaddr", ns) and ns or nil
	end
	for _, p in ipairs({ "/tmp/resolv.conf.auto", "/tmp/resolv.conf.d/resolv.conf.auto",
	                    "/tmp/resolv.conf" }) do
		local f = io.open(p, "r")
		if f then
			for line in f:lines() do
				local ns = valid_ns(line:match("^%s*nameserver%s+([%d%.:%a]+)"))
				if ns then f:close(); return ns end
			end
			f:close()
		end
	end
	return valid_ns(uci:get("network", "wan", "dns"))
end

local wan_dns = get_wan_dns()
if isEmpty(wan_dns) then wan_dns = "223.5.5.5" end

-- spec 5 cipher set for the ss listener (errata: xchacha20 removed).
-- Measured against the local v0.24.0 reference binary (Windows release
-- build, `full listener-shadowsocks`): `meow -t` accepts ANY cipher
-- string in a listener (config validation never parses it -- the probe
-- passes even for stream ciphers), but at runtime bind the shadowsocks
-- crate's CipherKind::from_str runs and this build lacks `v1-aead-extra`,
-- so 'xchacha20-ietf-poly1305' is rejected with "unknown cipher" -- a
-- zombie listener. It is therefore NOT in the set below: sections using
-- it go through standard quarantine like any other unsupported cipher.
local SS_LISTENER_CIPHERS = {
	["aes-128-gcm"] = true,
	["aes-256-gcm"] = true,
	["chacha20-ietf-poly1305"] = true,
	["2022-blake3-aes-128-gcm"] = true,
	["2022-blake3-aes-256-gcm"] = true,
	["2022-blake3-chacha20-poly1305"] = true,
}

-- Quarantine records, same file shape as the other writers (spec 4.6,
-- U2 merge format): {name,type,reason,source,role}. Server records carry
-- source="uci" + role="server".
local unsupported = {}
local function record_skip(cfg, reason)
	local name = tostring(cfg[".name"] or "?")
	io.stderr:write("homeproxy: WARNING: server section '" .. name
		.. "' skipped: " .. reason .. "\n")
	push(unsupported, {
		name = name,
		type = tostring(cfg.type or "unknown"),
		reason = reason,
		source = "uci",
		role = "server",
	})
end

-- tmp+rename atomic write (spec 4.1 / hard constraint 5).
local function atomic_write(path, content)
	local tmp = path .. ".tmp." .. tostring(os.time()) .. "." .. tostring(math.random(100000, 999999))
	if hp.writefile(tmp, content) and os.rename(tmp, path) then return true end
	os.remove(tmp)
	return false
end

-- Merge this run's skips into unsupported-nodes.json. This file owns the
-- role="server" partition: prior server records are rewritten from live
-- UCI sections on every run, while every other writer's records (client
-- nodes from the generator, link drops from update_subscriptions) are
-- preserved untouched.
local function flush_unsupported()
	local existing = {}
	local raw = hp.readfile(UNSUPPORTED_PATH)
	if not isEmpty(raw) then
		local ok, j = pcall(hp.decode_json, raw)
		if ok and type(j) == "table" then existing = j end
	end
	local seen, merged = {}, {}
	for _, e in ipairs(existing) do
		if type(e) == "table" and e.role ~= "server" then
			local k = tostring(e.name) .. "|" .. tostring(e.type) .. "|" .. tostring(e.reason)
			if not seen[k] then merged[#merged + 1] = e; seen[k] = true end
		end
	end
	for _, e in ipairs(unsupported) do
		local k = tostring(e.name) .. "|" .. tostring(e.type) .. "|" .. tostring(e.reason)
		if not seen[k] then merged[#merged + 1] = e; seen[k] = true end
	end
	if #merged == 0 then
		-- Nothing quarantined anywhere: remove a stale file so
		-- `homeproxy nodes` / the API stop reporting ghosts.
		os.remove(UNSUPPORTED_PATH)
		return
	end
	if not atomic_write(UNSUPPORTED_PATH, hp.encode_json(merged)) then
		io.stderr:write("homeproxy: WARNING: failed to write " .. UNSUPPORTED_PATH .. "\n")
	end
end

local listeners = {}
local used_ports = {}
local saw_enabled = false   -- any enabled server section at all (rc split below)

uci:foreach(UCICONFIG, UCISERVER, function(cfg)
	if cfg.enabled ~= "1" then return end
	saw_enabled = true
	local name = tostring(cfg[".name"] or "?")

	-- meow's server side is shadowsocks-only (spec 5/D12); every other
	-- enabled server type is a quarantine case.
	if cfg.type ~= "shadowsocks" then
		record_skip(cfg, string.format(
			"server type '%s' is not supported by meow (shadowsocks listeners only)",
			tostring(cfg.type)))
		return
	end

	local cipher = cfg.shadowsocks_encrypt_method
	if isEmpty(cipher) then
		record_skip(cfg, "missing shadowsocks_encrypt_method")
		return
	end
	if not SS_LISTENER_CIPHERS[cipher] then
		record_skip(cfg, string.format(
			"shadowsocks cipher '%s' is not in the meow listener cipher set", tostring(cipher)))
		return
	end

	if isEmpty(cfg.password) then
		record_skip(cfg, "missing password")
		return
	end
	-- 2022-blake3 ciphers: the password must be a base64 key of exactly
	-- the cipher's key length, else the listener fails its runtime bind
	-- (`meow -t` does not check this). Same rule the client-side precheck
	-- applies to outbound nodes (subscription_parser.lua).
	if cipher:sub(1, 12) == "2022-blake3-" then
		local need = (cipher == "2022-blake3-aes-128-gcm") and 16 or 32
		local decoded = type(cfg.password) == "string"
			and cfg.password:match("^[A-Za-z0-9%+%/_%-]+=?=?$")
			and hp.decodeBase64Str(cfg.password) or nil
		if not decoded or #decoded ~= need then
			record_skip(cfg, string.format(
				"shadowsocks %s requires a base64 key of %d bytes", cipher, need))
			return
		end
	end

	local port = strToInt(cfg.port)
	if not port or not hp.validation("port", cfg.port) then
		record_skip(cfg, "missing or invalid port '" .. tostring(cfg.port) .. "'")
		return
	end
	-- meow hard-fails `meow -t` on duplicate listener ports (Class A), so
	-- a colliding section is skipped here instead.
	if used_ports[port] then
		record_skip(cfg, string.format(
			"port %d already used by server section '%s'", port, used_ports[port]))
		return
	end
	-- An infra-reserved port is not a quarantine case (the listener is
	-- still emitted per spec) but its bind will fail at runtime while the
	-- client instance owns the port -- make that visible now.
	if reserved_ports[port] then
		io.stderr:write("homeproxy: WARNING: server section '" .. name
			.. "': port " .. port .. " collides with a homeproxy infra/api port"
			.. " (5330/5331/5333/5334/19290) -- listener bind will fail at runtime\n")
	end
	-- server.address is silently ignored by design: listeners always bind
	-- the wildcard so relayed LAN/WAN clients can reach them. Say so.
	if not isEmpty(cfg.address) then
		io.stderr:write("homeproxy: WARNING: server section '" .. name
			.. "': address '" .. tostring(cfg.address) .. "' ignored, binding "
			.. listen_addr .. "\n")
	end

	local listener = {
		name = "cfg-" .. name .. "-in",
		type = "shadowsocks",
		listen = listen_addr,
		port = port,
		cipher = cipher,
		password = cfg.password,
		udp = true,     -- meow default is already true; emit it explicitly (spec 5)
	}
	-- The hysteria_obfs_* UCI fields double as the SS simple-obfs source
	-- (spec 5). meow's server-side codec needs only the mode (http|tls);
	-- anything else would hard-fail `meow -t`, so it is dropped with a
	-- warning rather than emitted.
	local obfs_mode = cfg.hysteria_obfs_type
	if not isEmpty(obfs_mode) then
		if obfs_mode == "http" or obfs_mode == "tls" then
			listener["simple-obfs"] = { enable = true, mode = obfs_mode }
		else
			io.stderr:write("homeproxy: WARNING: server section '" .. name
				.. "': hysteria_obfs_type '" .. tostring(obfs_mode)
				.. "' is not a meow simple-obfs mode (http|tls) -- obfs dropped\n")
		end
	end

	used_ports[port] = name
	push(listeners, listener)
end)

flush_unsupported()

if #listeners == 0 then
	-- Leave no output behind (the stale file was already removed above).
	-- Exit code splits the two cases so the caller can react differently:
	--   rc=2 -- enabled server sections existed but every one landed in
	--           quarantine: the server side is "configured but unusable",
	--           init.d logs it and continues with the client config.
	--   rc=1 -- no enabled server section at all (or a real failure
	--           below): the original error path.
	os.exit(saw_enabled and 2 or 1)
end

local config = {
	mode = "rule",
	["log-level"] = log_level,
	ipv6 = ipv6_support,
	["routing-mark"] = self_mark,
	-- No external-controller: it would collide with the client instance on
	-- 127.0.0.1:19290 (spec 5). dns.listen is likewise omitted -- the
	-- resolver exists for SS target domain resolution only (12-Q8:
	-- measured, `dns.enable` without `listen` passes `meow -t`).
	dns = { enable = true, nameserver = { "udp://" .. wan_dns } },
	listeners = listeners,
	-- Inbound traffic terminates here and egresses via DIRECT.
	rules = { "MATCH,DIRECT" },
}

if not atomic_write(OUT_PATH, hp.encode_json(config)) then
	io.stderr:write("homeproxy: ERROR: failed to write " .. OUT_PATH .. "\n")
	os.exit(1)
end
