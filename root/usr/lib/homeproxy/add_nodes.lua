#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy manual node importer. Reads share links (ss/vmess/vless/trojan/
-- hysteria2/anytls/socks/http/sip008 single-entry, ...) from argv or stdin
-- (one per line), parses them via subscription_parser.lua, runs the shared
-- meow legality precheck (spec-meow-migration-A §4.4/§9.1) and upserts UCI
-- "node" sections into /etc/config/homeproxy. Rejected links never reach
-- UCI; the JSON response carries their reasons.
--
-- Manual nodes intentionally carry NO grouphash: update_subscriptions.lua
-- only garbage-collects nodes that belong to a fetched subscription group,
-- so user-added nodes survive every subscription update.
--
-- Output: one JSON line
--   {"ok":true,"added":[labels],"skipped":[lines],
--    "rejected":[{"input":line,"reason":str,"kind":str,"type":str}]}

package.path = (os.getenv("HP_LUAPATH") or "/usr/lib/homeproxy") .. "/?.lua;" .. package.path

local hp        = require("homeproxy")
local sharelink = require("subscription_parser")
local uci       = require("uci").cursor(os.getenv("HP_CONFDIR") or "/etc/config")

local CFG = "homeproxy"
local UCINODE = "node"

-- Serialize UCI writes against update_subscriptions.lua (same lock dir +
-- same pid-liveness protocol as cgi-bin/api / init.d / the CLI): a live
-- holder may hold past 120s, so stale detection checks the holder's pid
-- first; a dead pid is reclaimed at once, a pid-less lock falls back to
-- the >120s mtime rule.
local lock_dir = hp.RUN_DIR .. "/uci-write.lock.d"
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
		os.execute("rm -f " .. hp.shellQuote(lock_dir .. "/pid"))
		os.execute("rmdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null")
		return false
	end
	local h = io.popen("stat -c %Y " .. hp.shellQuote(lock_dir) .. " 2>/dev/null")
	local mt = h and tonumber(hp.trim(h:read("*a") or "")) or nil
	if h then h:close() end
	if mt == nil then return true end
	local age = os.time() - mt
	if age < 120 then return true end  -- negative age counts as live
	os.execute("rmdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null")
	return false
end
for _ = 1, 15 do
	if os.execute("mkdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null") == 0 then
		local pid = self_pid()
		if pid then
			local f = io.open(lock_dir .. "/pid", "w")
			if f then f:write(tostring(pid)); f:close() end
		end
		lock_held = true
		break
	end
	if lock_is_live() then os.execute("sleep 1") end
end
if not lock_held then
	io.write(hp.encode_json({ ok = false, error = "another update is in progress",
		added = {}, skipped = {} }) .. "\n")
	io.flush()
	os.exit(3)
end

local function release_lock()
	if lock_held then
		os.execute("rm -f " .. hp.shellQuote(lock_dir .. "/pid"))
		os.execute("rmdir " .. hp.shellQuote(lock_dir) .. " 2>/dev/null")
		lock_held = false
	end
end

-- Reuse the subscription meow feature cache when present (written by
-- update_subscriptions.lua, keyed by path + `meow --version` + mtime).
-- The cache is only valid when its signature matches the binary that would
-- be probed today -- otherwise a silent binary swap/upgrade would serve a
-- stale feature set (L24). Absent a usable cache, assume a full official
-- meow build; a node the installed binary cannot actually load is still
-- caught by `meow -t` on the next generate/start.
local MEOW_FEATURE_KEYS = {
	"with_quic", "with_utls", "with_hysteria", "with_ss_listener",
	"with_ss", "with_trojan", "with_vmess", "with_snell", "with_anytls",
}

-- Same binary resolution + signature as update_subscriptions.lua (spec
-- §8.4/§9.3).
local function meow_bin()
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

local function meow_signature(bin)
	local p = io.popen(hp.shellQuote(bin) .. " --version 2>/dev/null")
	local version = p and hp.trim(p:read("*a") or "") or ""
	if p then p:close() end
	local h = io.popen("stat -c %Y " .. hp.shellQuote(bin) .. " 2>/dev/null")
	local mtime = h and hp.trim(h:read("*a") or "") or ""
	if h then h:close() end
	if version == "" then return nil end
	return hp.md5(bin .. "\n" .. version .. "\n" .. (mtime ~= "" and mtime or "0"))
end

local function detect_features()
	local raw = hp.readfile(hp.RUN_DIR .. "/meow-features.json")
	if raw then
		-- luci.jsonc's parse() raises on bad JSON (luci.json's decode returns
		-- nil) -- pcall keeps a corrupt cache from killing the whole import.
		local _, data = pcall(hp.decode_json, raw)
		if type(data) == "table" then
			local f = data.features
			local sig = meow_signature(meow_bin())
			if type(f) == "table" and sig and data.signature == sig then
				local complete = true
				for _, k in ipairs(MEOW_FEATURE_KEYS) do
					if type(f[k]) ~= "boolean" then
						complete = false -- incomplete cache: use the default set
						break
					end
				end
				if complete then return f end
			end
		end
	end
	-- hysteria v1 is never in meow; everything else defaults to present.
	return {
		with_quic = true, with_utls = true, with_hysteria = false,
		with_ss_listener = true, with_ss = true, with_trojan = true,
		with_vmess = true, with_snell = true, with_anytls = true,
	}
end

local added, skipped, rejected = {}, {}, {}
-- Everything that can hard-error sits inside the pcall: a death between
-- acquire and here would otherwise leak the lock (stale reclaim would
-- cover it eventually, but instantly is better) and leave staged deltas.
local ok_run, run_err = pcall(function()
uci:load(CFG)
local parser_opts = {
	log = function() end,
	features = detect_features(),
	packet_encoding = uci:get(CFG, "subscription", "packet_encoding") or "xudp",
}
local allow_insecure = uci:get(CFG, "subscription", "allow_insecure")

local input
if arg and arg[1] then
	input = table.concat(arg, "\n")
else
	input = io.read("*a") or ""
end

for line in input:gmatch("[^\r\n]+") do
	line = hp.trim(line)
	if line ~= "" then
		local pok, cfg, reason, kind, hint = pcall(sharelink.parse_uri, hp, parser_opts, line)
		if not pok then
			reason, kind, hint = "parser error: " .. tostring(cfg), "malformed", nil
			cfg = nil
		end
		if cfg and not hp.isEmpty(cfg) then
			local label = cfg.label
			if hp.isEmpty(label) then
				label = tostring(cfg.address) .. ":" .. tostring(cfg.port)
				cfg.label = label
			end
			if cfg.tls == "1" and allow_insecure == "1" then
				cfg.tls_insecure = "1"
			end
			-- Same naming as `homeproxy add` (md5(label)): manual nodes share
			-- one namespace regardless of which command created them, and can
			-- never collide with subscription nodes (md5(grouphash|label)).
			-- Re-importing the same label updates the section in place.
			local name = hp.md5(label)
			local old = uci:get_all(CFG, name)
			if old and old[".type"] ~= UCINODE then
				skipped[#skipped + 1] = line
			else
				if old then
					for k in pairs(old) do
						if k:sub(1, 1) ~= "." then uci:delete(CFG, name, k) end
					end
				end
				uci:set(CFG, name, UCINODE)
				for k, v in pairs(cfg) do
					uci:set(CFG, name, k, v)
				end
				added[#added + 1] = label
			end
		else
			skipped[#skipped + 1] = line
			if reason then
				-- Every meow-precheck rejection is reported with its reason so
				-- callers can show why a link was refused (§9.1/AC-14).
				rejected[#rejected + 1] = {
					input = line, reason = tostring(reason),
					kind = kind or "malformed",
					type = hint or "unknown",
				}
			end
		end
	end
end

if #added > 0 then
	-- Checked commit (same convention as update_subscriptions' commit_uci):
	-- a full/read-only filesystem must surface as an error, not a fake
	-- success listing nodes that were never persisted.
	if not uci:commit(CFG) then error("uci commit failed") end
end
end)

if not ok_run then
	-- Drop the staged delta: uncommitted uci changes live in /tmp/.uci and
	-- the NEXT `uci commit homeproxy` by any process would flush this
	-- half-applied import along with its own change.
	pcall(function() uci:revert(CFG) end)
end
release_lock()

if not ok_run then
	io.write(hp.encode_json({ ok = false, error = tostring(run_err),
		added = {}, skipped = skipped, rejected = rejected }) .. "\n")
	io.flush()
	os.exit(1)
end

io.write(hp.encode_json({ ok = true, added = added, skipped = skipped,
	rejected = rejected }) .. "\n")
io.flush()
