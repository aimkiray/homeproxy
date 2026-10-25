#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy client config generator for meow-rs (mihomo schema).
-- Reads /etc/config/homeproxy via the uci Lua binding and emits the client
-- config to /var/run/homeproxy/meow-c.yaml. The payload is JSON text, which
-- is also valid YAML 1.2, so the existing luci.json encoder is reused.

package.path = (os.getenv("HP_LUAPATH") or "/usr/lib/homeproxy") .. "/?.lua;" .. package.path

local hp   = require("homeproxy")
local sp   = require("subscription_parser")
local uci  = require("uci").cursor(os.getenv("HP_CONFDIR") or "/etc/config")

local UCICONFIG = "homeproxy"
uci:load(UCICONFIG)

-- Remove any stale output up front: an error()/os.exit mid-generation must
-- not leave a previous file that init.d's existence check would then pass.
-- unsupported-nodes.json is deliberately NOT pre-deleted: it is a shared
-- file partitioned by `role` (see flush_unsupported at the bottom); this
-- run only replaces the role="client" partition on a successful write.
os.remove(hp.RUN_DIR .. "/meow-c.yaml")

local UCIINFRA = "infra"
local UCIMAIN  = "config"
local UCICONTROL = "control"
local UCIDNS = "dns"
local UCIDNSSERVER = "dns_server"
local UCIDNSRULE = "dns_rule"
local UCIROUTING = "routing"
local UCIROUTINGNODE = "routing_node"
local UCIROUTINGRULE = "routing_rule"
local UCINODE = "node"
local UCIRULESET = "ruleset"

local MEOW_FILE = hp.RUN_DIR .. "/meow-c.yaml"
local UNSUPPORTED_FILE = hp.RUN_DIR .. "/unsupported-nodes.json"

local function uget(sec, opt) return uci:get(UCICONFIG, sec, opt) end
local function isEmpty(v) return hp.isEmpty(v) end
local function strToBool(v) return hp.strToBool(v) end
local function strToInt(v) return hp.strToInt(v) end
local function push(t, v) t[#t + 1] = v end
local function filter(arr, fn)
	if not arr then return {} end
	if type(arr) ~= "table" then arr = { arr } end
	local out = {}
	for _, v in ipairs(arr) do if fn(v) then out[#out + 1] = v end end
	return out
end
local function contains(arr, val)
	if not arr then return false end
	if type(arr) ~= "table" then arr = { arr } end
	for _, v in ipairs(arr) do if v == val then return true end end
	return false
end
local function warn(fmt, ...)
	local msg = select("#", ...) > 0 and string.format(fmt, ...) or fmt
	io.stderr:write("homeproxy: WARNING: " .. msg .. "\n")
end

-- Normalize "60"/"60s"/"2m"/"1h"/"1d" to integer seconds; meow wants u64.
local function secs(v)
	if isEmpty(v) then return nil end
	if type(v) == "number" then return math.floor(v) end
	local n, unit = tostring(v):match("^%s*(%d+)%s*([smhd]?)%s*$")
	if not n then return nil end
	n = tonumber(n)
	if unit == "m" then n = n * 60
	elseif unit == "h" then n = n * 3600
	elseif unit == "d" then n = n * 86400 end
	return n
end

-- Comma string or UCI list -> array of trimmed strings.
local function str_list(v)
	if type(v) ~= "table" then
		if isEmpty(v) then return nil end
		v = { v }
	end
	local out = {}
	for _, item in ipairs(v) do
		for part in tostring(item):gmatch("[^,]+") do
			part = part:match("^%s*(.-)%s*$")
			if part ~= "" then out[#out + 1] = part end
		end
	end
	return out
end

local function get_wan_dns()
	local function valid_ns(ns)
		if isEmpty(ns) or
			ns == "0.0.0.0" or ns == "127.0.0.1" or ns == "::" or ns == "::1" or
			ns:match("^127%.") then
			return false
		end
		return true
	end
	local wan_dns
	local f = {"/tmp/resolv.conf.auto", "/tmp/resolv.conf.d/resolv.conf.auto", "/tmp/resolv.conf"}
	for _, file in ipairs(f) do
		local resolv = hp.readfile(file)
		if resolv then
			for ns in resolv:gmatch("nameserver%s+([%x:%.%x]+)") do
				if valid_ns(ns) then
					wan_dns = ns
					break
				end
			end
		end
		if wan_dns then break end
	end
	if not wan_dns then
		local net_dump = uci:get_all("network", "wan") or {}
		local uci_dns = net_dump.dns
		if type(uci_dns) ~= "table" then uci_dns = uci_dns and { uci_dns } or {} end
		for _, ns in ipairs(uci_dns) do
			if valid_ns(ns) then
				wan_dns = ns
				break
			end
		end
	end
	return wan_dns
end

---------------------------------------------------------------------------
-- Quarantine bookkeeping (spec §4.6): every rejected node/provider is warned
-- once on stderr and accumulated for unsupported-nodes.json.
---------------------------------------------------------------------------
local unsupported_nodes = {}
local quarantined = {}          -- section name -> true
local function quarantine(name, type_, reason)
	if not quarantined[name] then
		quarantined[name] = true
		push(unsupported_nodes, { name = name, type = type_, reason = reason,
			source = "uci", role = "client" })
	end
	warn("node '%s' (%s) quarantined: %s", tostring(name), tostring(type_), tostring(reason))
end

---------------------------------------------------------------------------
-- Config extraction (same UCI reads as the sing-box generator; only the
-- semantics of the emitted fields changed).
---------------------------------------------------------------------------
local routing_mode = uget(UCIMAIN, "routing_mode") or "bypass_mainland_china"
if not contains({ "bypass_mainland_china", "proxy_mainland_china", "gfwlist", "global", "custom" }, routing_mode) then
	warn("unknown routing_mode '%s' -- using bypass_mainland_china.", tostring(routing_mode))
	routing_mode = "bypass_mainland_china"
end

local wan_dns = get_wan_dns()
if isEmpty(wan_dns) then
	wan_dns = (routing_mode == "proxy_mainland_china" or routing_mode == "global")
		and "8.8.8.8" or "223.5.5.5"
end

local dns_port = strToInt(uget(UCIINFRA, "dns_port")) or 5333
local ipv6_support = uget(UCIMAIN, "ipv6_support") or "0"

local main_node, main_udp_node, dedicated_udp_node, default_outbound,
      dns_server, china_dns_server,
      direct_domain_list, proxy_domain_list

if routing_mode ~= "custom" then
	main_node = uget(UCIMAIN, "main_node") or "nil"
	main_udp_node = uget(UCIMAIN, "main_udp_node") or "nil"

	-- A main_node/main_udp_node pointing at a deleted section would emit a
	-- dangling target; fall back to direct instead of breaking the config.
	local function node_exists(name)
		local s = not isEmpty(name) and uci:get_all(UCICONFIG, name) or nil
		return type(s) == "table" and s[".type"] == UCINODE
	end
	if main_node ~= "urltest" and not isEmpty(main_node) and not node_exists(main_node) then
		warn("main_node '%s' does not exist -- falling back to direct.", tostring(main_node))
		main_node = "nil"
	end

	-- main_udp_node="urltest" names an independent group even when main_node
	-- is also "urltest"; the plain ~= comparison would treat them as one.
	dedicated_udp_node = not isEmpty(main_udp_node)
		and main_udp_node ~= "same"
		and (main_udp_node == "urltest" or main_udp_node ~= main_node)
	if dedicated_udp_node and main_udp_node ~= "urltest" and not node_exists(main_udp_node) then
		warn("main_udp_node '%s' does not exist -- UDP falls back to the main node.", tostring(main_udp_node))
		main_udp_node = "same"
		dedicated_udp_node = false
	end

	dns_server = uget(UCIMAIN, "dns_server")
	if isEmpty(dns_server) or dns_server == "wan" then
		dns_server = wan_dns
	end
	if routing_mode == "bypass_mainland_china" then
		china_dns_server = uget(UCIMAIN, "china_dns_server")
		if isEmpty(china_dns_server) or type(china_dns_server) ~= "string" or china_dns_server == "wan" then
			china_dns_server = wan_dns
		end
	else
		china_dns_server = wan_dns
	end

	local function load_list(name)
		local d = hp.readfile(hp.HP_DIR .. "/resources/" .. name)
		if not d then return nil end
		local cl = {}
		for v in (d .. "\n"):gmatch("([^\r\n]*)") do
			v = v:match("^%s*(.-)%s*$")
			if v ~= "" and not v:match("^#") and v:match("^[A-Za-z0-9._-]+$") then
				cl[#cl + 1] = v
			end
		end
		return next(cl) ~= nil and cl or nil
	end
	direct_domain_list = load_list("direct_list.txt")
	proxy_domain_list  = load_list("proxy_list.txt")
else
	-- custom mode: routing defaults resolve routing_node / dns_server names.
	default_outbound = uget(UCIROUTING, "default_outbound") or "nil"
end

local proxy_mode = uget(UCIMAIN, "proxy_mode") or "redirect_tproxy"
-- Same {redirect,tproxy,redirect_tproxy} vocabulary as init.d /
-- firewall.sh / the web API: legacy TUN modes and unknown values degrade
-- to redirect_tproxy (migrate_config already rewrote them; defensive only).
if not contains({ "redirect", "tproxy", "redirect_tproxy" }, proxy_mode) then
	warn("unknown/legacy proxy_mode '%s' -- treating as redirect_tproxy.", tostring(proxy_mode))
	proxy_mode = "redirect_tproxy"
end
local mixed_port = strToInt(uget(UCIINFRA, "mixed_port")) or 5330
local self_mark = strToInt(uget(UCIINFRA, "self_mark")) or 100
local redirect_port = strToInt(uget(UCIINFRA, "redirect_port")) or 5331
local v6_port = strToInt(uget(UCIINFRA, "v6_port")) or 5334
local udp_timeout = (routing_mode == "custom")
	and uget(UCIROUTING, "udp_timeout") or uget(UCIINFRA, "udp_timeout")
udp_timeout = secs(udp_timeout) or 60
if udp_timeout < 1 then udp_timeout = 1 elseif udp_timeout > 86400 then udp_timeout = 86400 end

local log_level = uget(UCIMAIN, "log_level") or "warn"
-- meow's level whitelist is {debug,info,warning,warn,error,silent}: trace
-- has no equivalent and degrades to debug; fatal/panic degrade to error
-- (same mapping as generate_server.lua).
if log_level == "trace" then log_level = "debug" end
if log_level == "fatal" or log_level == "panic" then log_level = "error" end

---------------------------------------------------------------------------
-- Node -> proxies[] entry. Returns the meow table or nil after quarantine.
-- Legality precheck is shared with the subscription parser (§4.4).
---------------------------------------------------------------------------
local function build_smux(node, mtype)
	if node.multiplex ~= "1" then return nil end
	local proto = not isEmpty(node.multiplex_protocol) and node.multiplex_protocol or nil
	if proto == "muxcool" and mtype ~= "vless" and mtype ~= "vmess" then
		return nil, "mux protocol 'muxcool' is VLESS/VMess-only on meow"
	end
	if mtype == "vless" and node.vless_flow == "xtls-rprx-vision" and proto ~= "muxcool" then
		return nil, "vless flow xtls-rprx-vision requires muxcool (or no) multiplexing"
	end
	local padding = strToBool(node.multiplex_padding)
	if proto == "muxcool" and padding then
		return nil, "smux 'padding' is sing-mux only; muxcool has no padding layer"
	end
	-- statistic/brutal-opts are parsed-but-unsupported upstream: drop silently.
	return {
		enabled = true,
		protocol = proto,
		["max-connections"] = strToInt(node.multiplex_max_connections),
		["min-streams"] = strToInt(node.multiplex_min_streams),
		["max-streams"] = strToInt(node.multiplex_max_streams),
		padding = padding,
		["only-tcp"] = strToBool(node.multiplex_only_tcp),
	}
end

local function apply_transport(p, node)
	local t = node.transport
	if isEmpty(t) or t == "tcp" then return end
	p.network = t
	if t == "ws" then
		p["ws-opts"] = {
			path = node.ws_path,
			headers = not isEmpty(node.ws_host) and { Host = node.ws_host } or nil,
			["max-early-data"] = strToInt(node.websocket_early_data),
			["early-data-header-name"] = node.websocket_early_data_header,
		}
	elseif t == "grpc" then
		p["grpc-opts"] = { ["grpc-service-name"] = node.grpc_servicename }
	elseif t == "h2" then
		p["h2-opts"] = {
			host = str_list(node.http_host),
			path = (type(node.http_path) == "table") and node.http_path[1] or node.http_path,
			["idle-timeout"] = secs(node.http_idle_timeout),
			["ping-timeout"] = secs(node.http_ping_timeout),
		}
	elseif t == "httpupgrade" then
		p["http-upgrade-opts"] = {
			host = node.httpupgrade_host,
			path = (type(node.http_path) == "table") and node.http_path[1] or node.http_path,
		}
	end
	-- xhttp carries no extra UCI fields; meow xhttp-opts defaults apply.
end

-- Returns proxy map or nil,reason.
local function build_proxy(node, tag)
	local ok, err = sp.validate_node(hp, node, nil)
	if not ok then return nil, err end

	local t = node.type
	local mtype = sp.SUPPORTED_TYPES[t]
	local p = { name = tag, type = mtype, server = node.address, port = strToInt(node.port) }

	if t == "shadowsocks" then
		p.cipher = node.shadowsocks_encrypt_method
		p.password = node.password
		p.udp = true
		p["client-fingerprint"] = node.tls_utls
		if not isEmpty(node.shadowsocks_plugin) then
			p.plugin = node.shadowsocks_plugin
			p["plugin-opts"] = node.shadowsocks_plugin_opts
		end
	elseif t == "vmess" then
		p.uuid = node.uuid
		p.alterId = strToInt(node.vmess_alterid) or 0
		if node.vmess_encrypt == "zero" then
			return nil, "vmess cipher 'zero' is rejected by meow (security gap)"
		end
		p.cipher = not isEmpty(node.vmess_encrypt) and node.vmess_encrypt or nil
		p.udp = true
		p.tls = strToBool(node.tls)
		p["skip-cert-verify"] = strToBool(node.tls_insecure)
		p.servername = node.tls_sni
		p.alpn = str_list(node.tls_alpn)
		p["client-fingerprint"] = node.tls_utls
		if node.tls_reality == "1" then
			return nil, "vmess over REALITY is not supported by meow"
		end
		apply_transport(p, node)
	elseif t == "vless" then
		p.uuid = node.uuid
		p.udp = true
		p.tls = strToBool(node.tls)
		p["skip-cert-verify"] = strToBool(node.tls_insecure)
		p.servername = node.tls_sni
		p.alpn = str_list(node.tls_alpn)
		p["client-fingerprint"] = node.tls_utls
		p.flow = not isEmpty(node.vless_flow) and node.vless_flow or nil
		p.encryption = not isEmpty(node.vless_encryption) and node.vless_encryption or nil
		if node.tls_reality == "1" then
			p["reality-opts"] = {
				["public-key"] = node.tls_reality_public_key,
				["short-id"] = node.tls_reality_short_id,
			}
		end
		apply_transport(p, node)
		if p.flow == "xtls-rprx-vision" and p.network and p.network ~= "tcp" then
			return nil, "vless flow xtls-rprx-vision only works over network tcp"
		end
	elseif t == "trojan" then
		p.password = node.password
		p.udp = true
		p.sni = node.tls_sni
		p["skip-cert-verify"] = strToBool(node.tls_insecure)
	elseif t == "hysteria2" then
		p.password = node.password
		p.udp = true
		local ports = node.hysteria_hopping_port
		if type(ports) == "table" then ports = table.concat(ports, ",") end
		p.ports = not isEmpty(ports) and tostring(ports) or nil
		if not isEmpty(node.hysteria_hop_interval) then
			-- meow accepts a bare u64 or one "start-end" range (Q6 probe).
			local hi = tostring(node.hysteria_hop_interval):match("^%s*(.-)%s*$")
			if hi:match("^%d+s?$") then
				p["hop-interval"] = tonumber(hi:match("^(%d+)"))
			elseif hi:match("^%d+%-%d+$") then
				p["hop-interval"] = hi
			else
				return nil, "hysteria2 hop-interval '" .. hi .. "' is not a number or range"
			end
		end
		local function bw(v, field)
			if isEmpty(v) then return nil end
			v = tostring(v):match("^%s*(.-)%s*$")
			-- meow accepts integer Mbps, "N Mbps", or <num>[KMGT]?bps.
			if v:match("^%d+$") then return v .. " Mbps" end
			if v:match("^%d+%s*[KMGTkmgt]?[Bb]ps$") then return v end
			return nil, "hysteria2 " .. field .. " '" .. v .. "' is not a valid bandwidth"
		end
		local berr
		p.up, berr = bw(node.hysteria_up_mbps, "up")
		if berr then return nil, berr end
		p.down, berr = bw(node.hysteria_down_mbps, "down")
		if berr then return nil, berr end
		if node.hysteria_obfs_type == "salamander" then
			p.obfs = "salamander"
			p["obfs-password"] = node.hysteria_obfs_password
		end
		local alpn = str_list(node.tls_alpn)
		if alpn then
			for _, a in ipairs(alpn) do
				if a ~= "h3" then
					return nil, "hysteria2 alpn '" .. a .. "' invalid (h3 only)"
				end
			end
			p.alpn = alpn
		end
		p.sni = node.tls_sni
		p["skip-cert-verify"] = strToBool(node.tls_insecure)
		p["fast-open"] = strToBool(node.tcp_fast_open)
		-- port may be absent when `ports` hopping is configured (meow derives
		-- it); port=0 with no ports is a hard error, so normalize it away.
		if p.port == 0 then p.port = nil end
		if not p.port and not p.ports then
			return nil, "hysteria2 requires port or ports"
		end
	elseif t == "anytls" then
		-- meow's anytls surface is server/port/password/sni/skip-cert-verify/udp
		-- only (proxy_parser.rs); idle-session-* keys are silently ignored.
		p.password = node.password
		p.udp = true
		p.sni = node.tls_sni
		p["skip-cert-verify"] = strToBool(node.tls_insecure)
	elseif t == "snell" then
		p.psk = not isEmpty(node.snell_psk) and node.snell_psk or node.password
		local sv = not isEmpty(node.snell_version) and node.snell_version or node.version
		-- Extra parens truncate gsub's second return (replace count); without
		-- them it leaks into tonumber's base arg and non-decimal spellings
		-- ("v6"/absent) hard-error the whole generate (same idiom as
		-- subscription_parser.lua's version check).
		p.version = strToInt(sv) or tonumber((tostring(sv or ""):gsub("^%s*[vV]", "")))
		-- The reference v0.24.0 build implements v3/v4/v5/v6 (SnellVersion::V6
		-- + v6-only `mode`); keep the generator-side gate aligned with the
		-- subscription parser's {3..6} precheck so a bad UCI value quarantines
		-- instead of hard-erroring `meow -t`.
		if p.version and not contains({ 3, 4, 5, 6 }, p.version) then
			return nil, "snell version '" .. p.version .. "' is not supported by meow (v3-v6)"
		end
		p.udp = true
		local om = node.snell_obfs_mode or node.obfs_mode
		if not isEmpty(om) then
			-- v6 servers carry no obfs: meow hard-errors obfs-opts on
			-- version 6 ("obfs-opts is not supported by snell v6").
			if p.version == 6 then
				return nil, "snell v6 does not support obfs-opts (v3-v5 only)"
			end
			p["obfs-opts"] = {
				mode = om,
				host = node.snell_obfs_host or node.obfs_host,
				path = node.snell_obfs_path or node.obfs_path,
			}
		end
		p.reuse = strToBool(node.snell_reuse)
	elseif t == "socks" then
		p.username = node.username
		p.password = node.password
		p.udp = true
		p.tls = strToBool(node.tls)
		p["skip-cert-verify"] = strToBool(node.tls_insecure)
	elseif t == "http" then
		p.username = node.username
		p.password = node.password
		p.tls = strToBool(node.tls)
		p["skip-cert-verify"] = strToBool(node.tls_insecure)
		p.sni = node.tls_sni
	end

	-- meow parses smux only on ss/trojan/vless/vmess (pp.rs call sites).
	if mtype == "ss" or mtype == "trojan" or mtype == "vless" or mtype == "vmess" then
		local smux, serr = build_smux(node, mtype)
		if serr then return nil, serr end
		p.smux = smux
	end

	if t ~= "hysteria2" then
		if isEmpty(p.server) then return nil, "missing server/address" end
		-- port 0 is truthy in Lua but a hard error for meow (required_port).
		if not p.port or p.port == 0 then return nil, "missing or invalid port" end
	elseif isEmpty(p.server) then
		return nil, "missing server/address"
	end
	return p
end

---------------------------------------------------------------------------
-- Emission state. `emitted[tag]` marks proxies/groups already written under
-- that name; `pseudo_targets[section]` maps routing_node/node sections that
-- resolve to meow builtins (DIRECT/REJECT) instead of a cfg-*-out entry.
---------------------------------------------------------------------------
local proxies, groups, rule_providers = {}, {}, {}
local emitted = {}
local pseudo_targets = {}
local expanding = {}
local member_tag            -- forward decl: emit_node_group <-> member_tag recurse
local emit_node_proxy       -- forward decl: used by member_tag/emit_as below

local function emit_node_group(sec_name, sec, name_override)
	local gname = name_override or ("cfg-" .. sec_name .. "-out")
	if emitted[gname] then return true end
	if expanding[sec_name] then
		warn("cyclic urltest/selector membership at node '%s' -- dropped.", tostring(sec_name))
		return false
	end
	expanding[sec_name] = true
	local gtype = (sec.type == "selector") and "select" or "url-test"
	local members = sec.urltest_nodes or sec.selector_nodes
	if type(members) ~= "table" then members = members and { members } or {} end
	local tags = {}
	for _, m in ipairs(members) do
		if m ~= sec_name and not expanding[m] then
			local tag = member_tag(m, "group " .. gname)
			if tag then push(tags, tag) end
		else
			warn("cyclic urltest/selector membership at node '%s' -- dropped.", tostring(m))
		end
	end
	expanding[sec_name] = nil
	if #tags == 0 then
		warn("group node '%s' has no usable members -- skipped.", tostring(sec_name))
		return false
	end
	push(groups, {
		name = gname,
		type = gtype,
		proxies = tags,
		url = not isEmpty(sec.urltest_url) and sec.urltest_url or "http://www.gstatic.com/generate_204",
		interval = secs(sec.urltest_interval) or 300,
		tolerance = strToInt(sec.urltest_tolerance) or 50,
		lazy = true,
	})
	emitted[gname] = true
	return true
end

-- url-test/select group; members is a list of node-section names. Pseudo
-- members map to builtins; nested urltest/selector sections expand to their
-- own cfg-<name>-out group (guarded against cycles).
member_tag = function(name, owner)
	local sec = uci:get_all(UCICONFIG, name)
	if type(sec) ~= "table" or sec[".type"] ~= UCINODE then
		warn("%s references missing node '%s' -- dropped.", owner, tostring(name))
		return nil
	end
	if quarantined[name] then
		warn("%s member '%s' is quarantined -- dropped.", owner, tostring(name))
		return nil
	end
	local t = sec.type
	if t == "direct" then return "DIRECT" end
	if t == "block" then return "REJECT" end
	if t == "dns" then
		warn("%s member '%s' is a dns pseudo node -- dropped.", owner, tostring(name))
		return nil
	end
	if t == "urltest" or t == "selector" then
		if not emit_node_group(name, sec) then return nil end
	elseif not emit_node_proxy(name, "cfg-" .. name .. "-out") then
		return nil
	end
	return "cfg-" .. name .. "-out"
end

-- Emit a url-test/select group under an arbitrary name from an explicit
-- member list + flat opts {url,interval,tolerance}.
local function emit_named_group(gname, gtype, members, opts, owner)
	if emitted[gname] then return true end
	local tags = {}
	for _, m in ipairs(members or {}) do
		local tag = member_tag(m, owner)
		if tag then push(tags, tag) end
	end
	if #tags == 0 then return false end
	push(groups, {
		name = gname,
		type = gtype,
		proxies = tags,
		url = not isEmpty(opts.url) and opts.url or "http://www.gstatic.com/generate_204",
		interval = secs(opts.interval) or 300,
		tolerance = strToInt(opts.tolerance) or 50,
		lazy = true,
	})
	emitted[gname] = true
	return true
end

emit_node_proxy = function(sec_name, tag, dialer)
	if emitted[tag] then return true end
	local node = uci:get_all(UCICONFIG, sec_name)
	if type(node) ~= "table" or node[".type"] ~= UCINODE then
		warn("node section '%s' does not exist -- skipped.", tostring(sec_name))
		return false
	end
	local p, err = build_proxy(node, tag)
	if not p then
		quarantine(node[".name"], node.type, err or "generation failed")
		return false
	end
	if dialer then p["dialer-proxy"] = dialer end
	push(proxies, p)
	emitted[tag] = true
	return true
end

---------------------------------------------------------------------------
-- Outbound-name resolution (custom mode + dns_rule outbound fields).
--   direct-out -> DIRECT, block-out -> REJECT, pseudo nodes -> builtins,
--   routing_node/node name -> cfg-<name>-out (must have been emitted).
---------------------------------------------------------------------------
local function resolve_outbound(name)
	if type(name) == "table" then
		if #name > 1 then
			warn("outbound list of %d entries has no meow equivalent -- using the first.", #name)
		end
		name = name[1]
	end
	if isEmpty(name) or name == "nil" then return "DIRECT" end
	if name == "direct-out" or name == "direct" then return "DIRECT" end
	if name == "block-out" or name == "block" then return "REJECT" end
	if name == "any-out" or name == "any" then
		warn("outbound 'any-out' has no meow equivalent -- using DIRECT.")
		return "DIRECT"
	end
	if pseudo_targets[name] then return pseudo_targets[name] end
	local sec = uci:get_all(UCICONFIG, name)
	if type(sec) ~= "table" then
		warn("outbound target '%s' does not exist -- using DIRECT.", tostring(name))
		return "DIRECT"
	end
	local tag = "cfg-" .. name .. "-out"
	if sec[".type"] == UCIROUTINGNODE then
		if sec.enabled ~= "1" or not emitted[tag] then
			warn("outbound target routing_node '%s' was not emitted -- using DIRECT.", tostring(name))
			return "DIRECT"
		end
		return tag
	end
	if sec[".type"] == UCINODE then
		if quarantined[name] then
			warn("outbound target node '%s' is quarantined -- using DIRECT.", tostring(name))
			return "DIRECT"
		end
		if sec.type == "direct" then return "DIRECT" end
		if sec.type == "block" then return "REJECT" end
		if sec.type == "dns" then
			warn("outbound target '%s' is a dns pseudo node -- using DIRECT.", tostring(name))
			return "DIRECT"
		end
		if not emitted[tag] then
			if sec.type == "urltest" or sec.type == "selector" then
				emit_node_group(name, sec)
			else
				emit_node_proxy(name, tag)
			end
		end
		return emitted[tag] and tag or "DIRECT"
	end
	warn("outbound target '%s' is a %s section -- using DIRECT.", tostring(name), tostring(sec[".type"]))
	return "DIRECT"
end

---------------------------------------------------------------------------
-- ruleset sections -> rule-providers (spec §4.7/§4.9).
---------------------------------------------------------------------------
local MEOW_RP_FORMAT = { text = true, yaml = true, mrs = true }
local function ruleset_provider(sec)
	-- Returns provider name or nil (warned inside).
	local name = "cfg-" .. sec[".name"] .. "-rule"
	local t = sec.type
	local p = { behavior = "domain", format = "text" }
	if not isEmpty(sec.format) then
		if not MEOW_RP_FORMAT[sec.format] then
			warn("ruleset '%s': sing-box format '%s' cannot be read by meow (text/yaml/mrs only) -- skipped.",
				tostring(sec[".name"]), tostring(sec.format))
			return nil
		end
		p.format = sec.format
	end
	if not isEmpty(sec.behavior) then
		if not contains({ "domain", "ipcidr", "classical" }, sec.behavior) then
			warn("ruleset '%s': unknown behavior '%s' -- skipped.", tostring(sec[".name"]), tostring(sec.behavior))
			return nil
		end
		p.behavior = sec.behavior
	end
	if t == "local" or t == "file" then
		if isEmpty(sec.path) then
			warn("ruleset '%s': file provider requires a path -- skipped.", tostring(sec[".name"]))
			return nil
		end
		p.type, p.path = "file", sec.path
	elseif t == "remote" or t == "http" then
		if isEmpty(sec.url) then
			warn("ruleset '%s': http provider requires a url -- skipped.", tostring(sec[".name"]))
			return nil
		end
		p.type, p.url = "http", sec.url
		p.interval = secs(sec.update_interval)
		local detour = resolve_outbound(sec.outbound)
		if detour == "REJECT" then
			-- A reject detour cannot carry provider fetches (every fetch
			-- would die); same nil-handling as DIRECT.
			warn("ruleset '%s': outbound detour resolves to REJECT -- dropped (fetches go direct).",
				tostring(sec[".name"]))
			detour = "DIRECT"
		end
		if detour ~= "DIRECT" then p.proxy = detour end
	elseif t == "inline" then
		-- Only scalar payloads go through str_list: a table is already a
		-- list, and re-splitting it would shred classical entries that
		-- legitimately contain commas ('DOMAIN-SUFFIX,x.com').
		local payload = sec.payload
		if type(payload) ~= "table" then payload = str_list(payload) end
		if isEmpty(payload) then
			warn("ruleset '%s': inline provider requires a payload list -- skipped.", tostring(sec[".name"]))
			return nil
		end
		p.type, p.payload = "inline", payload
	else
		warn("ruleset '%s': type '%s' unsupported by meow -- skipped.", tostring(sec[".name"]), tostring(t))
		return nil
	end
	rule_providers[name] = p
	return name, p
end

local function provider_name_for(ruleset_name)
	-- Resolve a UCI ruleset reference to an emitted provider (or emit it now).
	for pname, p in pairs(rule_providers) do
		if pname == "cfg-" .. ruleset_name .. "-rule" or pname == ruleset_name then
			return pname, p
		end
	end
	local sec = uci:get_all(UCICONFIG, ruleset_name)
	if type(sec) == "table" and sec[".type"] == UCIRULESET and sec.enabled == "1" then
		return ruleset_provider(sec)
	end
	warn("rule_set '%s' does not name an enabled ruleset section -- dropped.", tostring(ruleset_name))
	return nil
end

---------------------------------------------------------------------------
-- routing_rule -> meow rule string (spec §4.9).
---------------------------------------------------------------------------
local SINGBOX_RULE_FIELDS = {
	ip_version = "ip_version", protocol = "protocol",
	source_ip_is_private = "source_ip_is_private", ip_is_private = "ip_is_private",
	process_name = "process_name", process_path = "process_path",
	process_path_regex = "process_path_regex", user = "user",
	invert = "invert", rule_set_ip_cidr_match_source = "rule_set_ip_cidr_match_source",
	rule_set_ip_cidr_accept_empty = "rule_set_ip_cidr_accept_empty",
	override_address = "override_address", override_port = "override_port",
	udp_connect = "udp_connect", udp_disable_domain_unmapping = "udp_disable_domain_unmapping",
	udp_timeout = "udp_timeout", tls_fragment = "tls_fragment",
	tls_fragment_fallback_delay = "tls_fragment_fallback_delay",
	tls_record_fragment = "tls_record_fragment",
}

-- Build one condition string per field group; returns list of conditions.
local function rule_conditions(cfg, owner)
	local conds = {}
	local function add(list, mk)
		if type(list) ~= "table" then list = str_list(list) end
		if not list or #list == 0 then return end
		if #list == 1 then
			push(conds, mk(list[1]))
		else
			local inner = {}
			for _, v in ipairs(list) do push(inner, "(" .. mk(v) .. ")") end
			-- Kernel form OR,(<sub>,<sub>,...) expects one outer pair; each
			-- sub already carries its own parentheses.
			push(conds, "OR,(" .. table.concat(inner, ",") .. ")")
		end
	end
	add(cfg.domain, function(v) return "DOMAIN," .. v end)
	add(cfg.domain_suffix, function(v) return "DOMAIN-SUFFIX," .. v end)
	add(cfg.domain_keyword, function(v) return "DOMAIN-KEYWORD," .. v end)
	add(cfg.domain_regex, function(v) return "DOMAIN-REGEX," .. v end)
	if not isEmpty(cfg.geosite) then
		warn("%s: geosite rules need geo data files meow does not ship -- dropped.", owner)
	end
	add(cfg.ip_cidr, function(v) return "IP-CIDR," .. v .. ",no-resolve" end)
	add(cfg.source_ip_cidr, function(v) return "SRC-IP-CIDR," .. v end)
	add(cfg.port, function(v) return "DST-PORT," .. v end)
	add(cfg.port_range, function(v) return "DST-PORT," .. v:gsub(":", "-") end)
	add(cfg.source_port, function(v) return "SRC-PORT," .. v end)
	add(cfg.source_port_range, function(v) return "SRC-PORT," .. v:gsub(":", "-") end)
	local nets = str_list(cfg.network)
	if nets then
		nets = filter(nets, function(v)
			if v == "tcp" or v == "udp" then return true end
			warn("%s: network '%s' is not tcp/udp -- dropped.", owner, tostring(v))
			return false
		end)
		add(nets, function(v) return "NETWORK," .. v end)
	end
	if not isEmpty(cfg.rule_set) then
		for _, rs in ipairs(str_list(cfg.rule_set) or {}) do
			local pname = provider_name_for(rs)
			if pname then
				push(conds, "RULE-SET," .. pname)
			end
		end
	end
	return conds
end

local function translate_routing_rule(cfg)
	local owner = "routing_rule " .. tostring(cfg[".name"])
	local action = cfg.action or "route"
	if action ~= "route" and action ~= "block" then
		warn("%s: action '%s' has no meow equivalent -- skipped.", owner, tostring(action))
		return
	end
	for k in pairs(SINGBOX_RULE_FIELDS) do
		if not isEmpty(cfg[k]) then
			warn("%s: sing-box-only field '%s' -- dropped.", owner, k)
		end
	end
	local target
	if action == "block" then
		target = "REJECT"
	else
		target = resolve_outbound(cfg.outbound)
	end
	-- RULE-SET is a top-level-only type: inside a logic group the kernel
	-- rejects it outright, so bucket it before any AND/OR assembly.
	local conds, rs_conds = {}, {}
	for _, c in ipairs(rule_conditions(cfg, owner)) do
		if c:match("^RULE%-SET,") then push(rs_conds, c) else push(conds, c) end
	end
	if #conds == 0 and #rs_conds == 0 then
		-- Condition fields were configured but every one was dropped (a bad
		-- network value, a missing ruleset, ...). Emitting MATCH here would
		-- silently swallow every later rule, so skip this rule instead.
		for _, k in ipairs({ "domain", "domain_suffix", "domain_keyword",
			"domain_regex", "geosite", "ip_cidr", "source_ip_cidr", "port",
			"port_range", "source_port", "source_port_range", "network",
			"rule_set" }) do
			if not isEmpty(cfg[k]) then
				warn("%s: all conditions were dropped -- rule skipped (it would degrade to a catch-all MATCH).", owner)
				return
			end
		end
		-- A rule with no conditions matches everything.
		return { "MATCH," .. target }
	end
	-- Returns a list of top-level lines: one RULE-SET,<p>,<target> per
	-- resolved provider plus one line for the ordinary conditions.
	local lines = {}
	for _, c in ipairs(rs_conds) do push(lines, c .. "," .. target) end
	if #conds > 0 then
		if #rs_conds > 0 then
			-- meow cannot express AND(rule_set, other); degrade to OR by
			-- emitting both sides as independent top-level lines.
			warn("%s: rule_set cannot combine with other conditions on meow -- degraded to separate lines (OR).", owner)
		end
		if #conds == 1 then
			-- A trailing ,no-resolve is an EXTRA flag after the adapter
			-- slot, not part of the condition payload.
			local bare = conds[1]:match("^(.*),no%-resolve$")
			push(lines, (bare or conds[1]) .. "," .. target .. (bare and ",no-resolve" or ""))
		else
			local inner = {}
			for _, c in ipairs(conds) do push(inner, "(" .. c .. ")") end
			push(lines, "AND,(" .. table.concat(inner, ",") .. ")," .. target)
		end
	end
	return lines
end

---------------------------------------------------------------------------
-- dns_server sections -> meow nameserver URLs (custom mode, §7.4).
---------------------------------------------------------------------------
-- meow's rcode:// parser matches case-sensitively and accepts exactly these
-- six labels (upstream.rs parse_rcode); anything else fails `meow -t`.
local MEOW_RCODES = {
	success = true, format_error = true, server_failure = true,
	name_error = true, not_implemented = true, refused = true,
}

local function dns_url_for_outbound(url, outbound)
	-- "#PROXY" suffix is legal on plain udp://tcp://bare forms only.
	local ob = resolve_outbound(outbound)
	if ob == "DIRECT" then return url end
	if ob == "REJECT" then
		-- REJECT cannot carry DNS queries; same nil-detour as DIRECT.
		warn("dns server '%s': outbound detour resolves to REJECT -- dropped (queries go direct).", tostring(url))
		return url
	end
	if url:match("^tls://") or url:match("^https://") then
		warn("dns server '%s': outbound detour cannot ride an encrypted URL -- # is SNI there.", tostring(url))
		return url
	end
	return url:gsub("#.*$", "") .. "#" .. ob
end

-- Bracket a bare IPv6 literal so the URL parser sees host[:port]; a single
-- colon means host:port and must NOT be bracketed.
local function bracket_v6(s)
	if type(s) ~= "string" then return s end
	if s:match("^%[") then return s end
	if select(2, s:gsub(":", "")) >= 2 then return "[" .. s .. "]" end
	return s
end

local function wan_dns_url()
	local h = wan_dns
	h = bracket_v6(h)
	return "udp://" .. h
end

local function dns_server_url(cfg)
	-- Returns a meow nameserver URL for an enabled dns_server section.
	for _, k in ipairs({ "headers", "address_resolver", "address_strategy" }) do
		if not isEmpty(cfg[k]) then
			warn("dns server '%s': sing-box-only field '%s' -- dropped.", tostring(cfg[".name"]), k)
		end
	end
	local t = cfg.type or "udp"
	local host = cfg.server
	local port = strToInt(cfg.server_port)
	if not isEmpty(host) then
		host = bracket_v6(host)
	end
	local hostport = tostring(host or "") .. ((port and port ~= 0) and (":" .. port) or "")
	local sni = not isEmpty(cfg.tls_sni) and ("#" .. cfg.tls_sni) or nil
	if t == "udp" then
		if isEmpty(host) then return nil, "missing server" end
		return dns_url_for_outbound("udp://" .. hostport, cfg.outbound)
	elseif t == "tcp" then
		if isEmpty(host) then return nil, "missing server" end
		return dns_url_for_outbound("tcp://" .. hostport, cfg.outbound)
	elseif t == "tls" then
		if isEmpty(host) then return nil, "missing server" end
		return "tls://" .. hostport .. (sni or "")
	elseif t == "https" or t == "h3" then
		if isEmpty(host) then return nil, "missing server" end
		if t == "h3" then
			warn("dns server '%s': h3 (DoH3) is unsupported -- degraded to https://.", tostring(cfg[".name"]))
		end
		local path = (type(cfg.path) == "string" and cfg.path ~= "") and cfg.path or "/dns-query"
		return "https://" .. hostport .. path .. (sni or "")
	elseif t == "quic" then
		if isEmpty(host) then return nil, "missing server" end
		warn("dns server '%s': quic (DoQ) is unsupported -- degraded to tls://.", tostring(cfg[".name"]))
		return "tls://" .. hostport .. (sni or "")
	elseif t == "local" or t == "system" or t == "system-dns" or t == "dhcp" then
		return wan_dns_url()
	elseif t == "rcode" and not isEmpty(cfg.rcode) then
		local rc = tostring(cfg.rcode):lower()
		if not MEOW_RCODES[rc] then
			return nil, "rcode '" .. tostring(cfg.rcode) .. "' is not a meow rcode (success/format_error/server_failure/name_error/not_implemented/refused)"
		end
		return "rcode://" .. rc
	else
		return nil, "dns server type '" .. tostring(t) .. "' unsupported"
	end
end

local function dns_pool_url(name, owner)
	if isEmpty(name) then return nil end
	if name == "default-dns" or name == "system-dns" then return wan_dns_url() end
	local sec = uci:get_all(UCICONFIG, name)
	if type(sec) ~= "table" or sec[".type"] ~= UCIDNSSERVER or sec.enabled ~= "1" then
		warn("%s: dns server '%s' is missing or disabled -- skipped.", owner, tostring(name))
		return nil
	end
	local url, err = dns_server_url(sec)
	if not url then
		warn("%s: dns server '%s': %s -- skipped.", owner, tostring(name), tostring(err))
	end
	return url
end

-- Non-custom mode upstreams: tls://https:// degrade to plain udp:// (the '#'
-- suffix is a proxy tag only on plain forms; on encrypted ones it is SNI).
local function plain_dns_url(v, proxy_tag)
	if isEmpty(v) then return nil end
	local u = tostring(v)
	local scheme, rest = u:match("^([a-z][a-z0-9+%.%-]*)://(.+)$")
	if scheme == "tls" or scheme == "https" then
		-- Encrypted upstreams carry the proxy as ?proxy=NAME (meow >= 0.26.1,
		-- issue #67); '#' stays reserved for the TLS SNI. Older kernels
		-- reject the parameter outright — `meow -t` catches that.
		if proxy_tag then
			u = u .. (u:find("?", 1, true) and "&" or "?") .. "proxy=" .. proxy_tag
		end
		return u
	elseif not scheme then
		-- bracket bare IPv6 literals so the URL parser sees host[:port]
		u = bracket_v6(u)
		u = "udp://" .. u
	elseif scheme ~= "udp" and scheme ~= "tcp" then
		warn("dns server '%s': unsupported scheme -- using wan DNS.", u)
		u = wan_dns_url()
	end
	if proxy_tag and not u:match("#") then u = u .. "#" .. proxy_tag end
	return u
end

---------------------------------------------------------------------------
-- Build the meow config skeleton (spec §4.2).
---------------------------------------------------------------------------
local config = {
	mode = "rule",
	["log-level"] = log_level,
	ipv6 = (ipv6_support == "1"),
	["mixed-port"] = mixed_port,
	["allow-lan"] = true,
	["bind-address"] = "*",
	["external-controller"] = "127.0.0.1:19290",
	["routing-mark"] = self_mark,
	strict = false,
	-- meow hard-fails `meow -t` when enable=true carries no sniff map
	-- (lib.rs: "sniffer.enable is true but sniffer.sniff map is absent or
	-- empty"); TLS/HTTP are the only protocols this build implements.
	sniffer = {
		enable = true,
		sniff = {
			TLS = { ports = { 443 } },
			HTTP = { ports = { 80 } },
		},
	},
}

---------------------------------------------------------------------------
-- Proxies/groups per routing mode (spec §4.3-§4.6).
---------------------------------------------------------------------------
local main_target = "main-out"   -- MATCH fallback target
local udp_target = "main-udp-out" -- NETWORK,udp target when dedicated

-- Emit a proxy/group for node section `sec` under adapter name `tag`;
-- returns the adapter name rules should point at (tag, or a builtin).
local function emit_as(tag, sec, owner)
	if type(sec) ~= "table" or sec[".type"] ~= UCINODE then
		warn("%s: node is missing -- %s falls back to direct.", owner, tag)
		push(proxies, { name = tag, type = "direct" })
		emitted[tag] = true
		return tag
	end
	local t = sec.type
	if t == "direct" then
		push(proxies, { name = tag, type = "direct" })
		emitted[tag] = true
		return tag
	elseif t == "block" then
		-- meow has no `reject` proxies[] type; route to the REJECT builtin.
		return "REJECT"
	elseif t == "dns" then
		warn("%s: dns pseudo node cannot be an outbound -- %s falls back to direct.", owner, tag)
		push(proxies, { name = tag, type = "direct" })
		emitted[tag] = true
		return tag
	elseif t == "urltest" or t == "selector" then
		if emit_node_group(sec[".name"], sec, tag) then return tag end
		warn("%s: %s node '%s' has no usable members -- %s falls back to direct.",
			owner, t, tostring(sec[".name"]), tag)
		push(proxies, { name = tag, type = "direct" })
		emitted[tag] = true
		return tag
	end
	if emit_node_proxy(sec[".name"], tag) then return tag end
	-- §4.6: main_* / references hitting quarantine -> warn + direct fallback.
	push(proxies, { name = tag, type = "direct" })
	emitted[tag] = true
	return tag
end

if routing_mode ~= "custom" then
	if main_node == "urltest" then
		local nodes = uget(UCIMAIN, "main_urltest_nodes") or {}
		if type(nodes) ~= "table" then nodes = { nodes } end
		if not emit_named_group("main-out", "url-test", nodes, {
			url = uget(UCIMAIN, "main_urltest_url"),
			interval = uget(UCIMAIN, "main_urltest_interval"),
			tolerance = uget(UCIMAIN, "main_urltest_tolerance"),
		}, "main_urltest_nodes") then
			warn("main_urltest_nodes has no usable members -- main-out falls back to direct.")
			push(proxies, { name = "main-out", type = "direct" })
			emitted["main-out"] = true
		end
	elseif not isEmpty(main_node) and main_node ~= "nil" then
		main_target = emit_as("main-out", uci:get_all(UCICONFIG, main_node) or {}, "main_node")
	else
		push(proxies, { name = "main-out", type = "direct" })
		emitted["main-out"] = true
	end

	if main_udp_node == "urltest" then
		local nodes = uget(UCIMAIN, "main_udp_urltest_nodes") or {}
		if type(nodes) ~= "table" then nodes = { nodes } end
		if not emit_named_group("main-udp-out", "url-test", nodes, {
			url = uget(UCIMAIN, "main_udp_urltest_url"),
			interval = uget(UCIMAIN, "main_udp_urltest_interval"),
			tolerance = uget(UCIMAIN, "main_udp_urltest_tolerance"),
		}, "main_udp_urltest_nodes") then
			warn("main_udp_urltest_nodes has no usable members -- main-udp-out falls back to direct.")
			push(proxies, { name = "main-udp-out", type = "direct" })
			emitted["main-udp-out"] = true
		end
	elseif dedicated_udp_node then
		udp_target = emit_as("main-udp-out", uci:get_all(UCICONFIG, main_udp_node) or {}, "main_udp_node")
	end
else
	-- custom: routing_node sections -> cfg-<rn>-out proxies/groups.
	uci:foreach(UCICONFIG, UCIROUTINGNODE, function(cfg)
		if cfg.enabled ~= "1" then return end
		local rn = cfg[".name"]
		local tag = "cfg-" .. rn .. "-out"
		if cfg.node == "urltest" or cfg.node == "selector" then
			local members = cfg.urltest_nodes or cfg.selector_nodes
			if type(members) ~= "table" then members = members and { members } or {} end
			if not isEmpty(cfg.outbound) then
				warn("routing_node '%s': outbound detour on a group is unsupported -- dropped.", rn)
			end
			if not emit_named_group(tag, (cfg.node == "selector") and "select" or "url-test",
				members, {
					url = cfg.urltest_url, interval = cfg.urltest_interval,
					tolerance = cfg.urltest_tolerance,
				}, "routing_node " .. rn) then
				warn("routing_node '%s' has no usable members -- falls back to direct.", rn)
				push(proxies, { name = tag, type = "direct" })
				emitted[tag] = true
			end
			return
		end
		if isEmpty(cfg.node) then
			warn("routing_node '%s' has no node -- skipped.", rn)
			return
		end
		local sec = uci:get_all(UCICONFIG, cfg.node)
		if type(sec) ~= "table" or sec[".type"] ~= UCINODE then
			warn("routing_node '%s' references missing node '%s' -- skipped.", rn, tostring(cfg.node))
			return
		end
		if not isEmpty(cfg.bind_interface) then
			warn("routing_node '%s': bind_interface has no meow equivalent -- dropped.", rn)
		end
		if sec.type == "block" then
			pseudo_targets[rn] = "REJECT"
			return
		end
		if sec.type == "direct" then
			push(proxies, { name = tag, type = "direct" })
			emitted[tag] = true
			return
		end
		local dialer
		if not isEmpty(cfg.outbound) and cfg.outbound ~= "nil" then
			dialer = resolve_outbound(cfg.outbound)
			if dialer == "DIRECT" or dialer == "REJECT" then dialer = nil end
		end
		if sec.type == "urltest" or sec.type == "selector" then
			if dialer then
				warn("routing_node '%s': outbound detour on a group is unsupported -- dropped.", rn)
				dialer = nil
			end
			if not emit_node_group(cfg.node, sec, tag) then
				warn("routing_node '%s' group '%s' has no usable members -- falls back to direct.", rn, tostring(cfg.node))
				push(proxies, { name = tag, type = "direct" })
				emitted[tag] = true
			end
			return
		end
		if sec.type == "dns" then
			warn("routing_node '%s': dns pseudo node cannot be an outbound -- falls back to direct.", rn)
			push(proxies, { name = tag, type = "direct" })
			emitted[tag] = true
			return
		end
		if dialer and sec.type == "hysteria2" then
			-- hysteria2 owns its QUIC socket: meow cannot thread an injected
			-- dialer through it and degrades to a DialerProxyAdapter wrapper
			-- that fails loudly on EVERY connection at runtime.
			warn("routing_node '%s': dialer detour on hysteria2 node '%s' is unsupported by meow -- dropped.",
				rn, tostring(cfg.node))
			dialer = nil
		end
		if not emit_node_proxy(cfg.node, tag, dialer) then
			-- Quarantined backing node: keep the tag resolvable as direct.
			push(proxies, { name = tag, type = "direct" })
			emitted[tag] = true
		end
	end)
end

-- Materialize cfg-<sect>-out for EVERY node so the API can ping each one.
-- Quarantined nodes still get skipped (init retries with materialize off on
-- meow -t failure, but a quarantined node never makes it that far).
if os.getenv("HP_MATERIALIZE_ALL_NODES") ~= "0" then
	uci:foreach(UCICONFIG, UCINODE, function(cfg)
		local tag = "cfg-" .. cfg[".name"] .. "-out"
		if emitted[tag] then return end
		local t = cfg.type
		if t == "urltest" or t == "selector" then
			emit_node_group(cfg[".name"], cfg)
			return
		end
		if t == "direct" or t == "block" or t == "dns" then return end
		emit_node_proxy(cfg[".name"], tag)
	end)
end

config.proxies = proxies
if #groups > 0 then
	config["proxy-groups"] = groups
end

---------------------------------------------------------------------------
-- rules + rule-providers (spec §4.7/§4.8/§4.9).
---------------------------------------------------------------------------
local rules = {}
local DL = direct_domain_list ~= nil
local PL = proxy_domain_list ~= nil

local function file_provider(path, behavior)
	return { type = "file", behavior = behavior or "domain", format = "text", path = path }
end

local function res_nonempty(name)
	local d = hp.readfile(hp.HP_DIR .. "/resources/" .. name)
	return d ~= nil and d:find("%S") ~= nil
end

if routing_mode ~= "custom" then
	if DL then
		rule_providers["direct-domain"] = file_provider("providers/direct_list.txt")
		push(rules, "RULE-SET,direct-domain,DIRECT")
	end
	if PL then
		-- bypass_mainland_china also references this from rules (below);
		-- other modes emit it for the dnsmasq/ipset side only (§4.7).
		rule_providers["proxy-domain"] = file_provider("providers/proxy_list.txt")
	end
	if routing_mode == "bypass_mainland_china" then
		rule_providers["china-domain"] = file_provider("providers/china_list.txt")
		-- gfw-domain feeds nameserver-policy only (below): unlisted traffic
		-- already reaches main-out via MATCH, so no rule references it.
		if res_nonempty("gfw_list.txt") then
			rule_providers["gfw-domain"] = file_provider("providers/gfw_list.txt")
		end
		-- proxy_list domains must precede china-domain: the CN DIRECT rule
		-- would otherwise swallow them (direct-domain stays first anyway).
		if PL then push(rules, "RULE-SET,proxy-domain," .. main_target) end
		push(rules, "RULE-SET,china-domain,DIRECT")
		-- dst_ip-only flows (redirect/tproxy daddr, IP literals, sniff
		-- misses) get their CN bypass here; no-resolve never pays a lookup.
		if res_nonempty("china_ip4.txt") then
			rule_providers["china-ip4"] = file_provider("providers/china_ip4.txt", "ipcidr")
			push(rules, "RULE-SET,china-ip4,DIRECT,no-resolve")
		end
		if ipv6_support == "1" and res_nonempty("china_ip6.txt") then
			rule_providers["china-ip6"] = file_provider("providers/china_ip6.txt", "ipcidr")
			push(rules, "RULE-SET,china-ip6,DIRECT,no-resolve")
		end
	elseif routing_mode == "gfwlist" then
		rule_providers["gfw-domain"] = file_provider("providers/gfw_list.txt")
		push(rules, "RULE-SET,gfw-domain," .. main_target)
	end
	if dedicated_udp_node then
		push(rules, "NETWORK,udp," .. udp_target)
	end
	push(rules, "MATCH," .. main_target)
else
	uci:foreach(UCICONFIG, UCIROUTINGRULE, function(cfg)
		if cfg.enabled ~= "1" then return end
		local lines = translate_routing_rule(cfg)
		for _, l in ipairs(lines or {}) do push(rules, l) end
	end)
	push(rules, "MATCH," .. resolve_outbound(default_outbound))
end
config.rules = rules

---------------------------------------------------------------------------
-- listeners (spec §6.3): external firewall owns steering -> firewall:false.
---------------------------------------------------------------------------
-- proxy_mode is normalized above: "tproxy"/"redirect_tproxy" carry the UDP
-- TPROXY arm, plain "redirect" does not.
local udp_listener = proxy_mode ~= "redirect"
	and ((routing_mode == "custom") or (main_udp_node and main_udp_node ~= "nil"))
config.listeners = {
	{
		name = "hp-tproxy",
		type = "tproxy",
		listen = "0.0.0.0",
		port = redirect_port,
		firewall = false,
		udp = udp_listener and true or false,
		["udp-timeout"] = udp_timeout,
	}
}
if ipv6_support == "1" then
	push(config.listeners, {
		name = "hp-tproxy6",
		type = "tproxy",
		listen = "::",
		port = v6_port,
		firewall = false,
		udp = false,
	})
end

---------------------------------------------------------------------------
-- DNS (spec §7.2-§7.4). dnsmasq stays in front; meow resolves upstream.
---------------------------------------------------------------------------
local dns = {
	enable = true,
	listen = "127.0.0.1:" .. dns_port,
	ipv6 = (ipv6_support == "1"),
	["enhanced-mode"] = "redir-host",
	["default-nameserver"] = { wan_dns_url() },
	["proxy-server-nameserver"] = { wan_dns_url() },
}

if routing_mode ~= "custom" then
	-- The #detour must name an EMITTED proxy/group: a block main_node makes
	-- emit_as return the REJECT builtin (nothing materialized as "main-out"),
	-- and a dangling #main-out hard-fails `meow -t`. REJECT cannot carry DNS
	-- queries anyway, so no tag is attached in that case.
	local main_detour = emitted[main_target] and main_target or nil
	if not main_detour then
		warn("main_node resolved to '%s' (no emitted proxy) -- dns detour tag dropped.", tostring(main_target))
	end
	-- Every upstream scheme can ride the proxy: plain forms take '#tag',
	-- DoT/DoH take '?proxy=tag' (meow >= 0.26.1).
	-- A proxied udp:// upstream is the weakest leg in the DNS path: the
	-- relay's plain-UDP forwarding drops packets under transit load, and
	-- each lost query surfaces client-side as a multi-second stall or
	-- NXDOMAIN (ERR_NAME_NOT_RESOLVED). Race a tcp:// twin on the same
	-- upstream -- TCP rides the strong splice path, so pool-first-answer
	-- keeps UDP speed when healthy and bounds the worst case otherwise.
	local function with_tcp_twin(pool, u)
		local host, tag = u:match("^udp://([^#]+)#(.+)$")
		if host and tag then
			pool[#pool + 1] = "tcp://" .. host .. "#" .. tag
		end
	end
	local bypass = (routing_mode == "bypass_mainland_china")
	-- bypass mode already routes CN rules at china_dns_server; use the same
	-- domestic resolver as the primary nameserver and demote dns_server
	-- (the foreign resolver) to a gated fallback riding the chain.
	local rs = plain_dns_url(bypass and china_dns_server or dns_server,
			(not bypass) and main_detour or nil)
		or (wan_dns_url() .. (main_detour and ("#" .. main_detour) or ""))
	dns.nameserver = { rs }
	with_tcp_twin(dns.nameserver, rs)
	local fb
	if bypass then
		fb = plain_dns_url(dns_server, main_detour)
			or (wan_dns_url() .. (main_detour and ("#" .. main_detour) or ""))
		if fb ~= rs then
			dns.fallback = { fb }
			with_tcp_twin(dns.fallback, fb)
			-- bogon gate (no GeoIP/mmdb): answers inside forged
			-- null/reserved ranges are replaced by the chained fallback's
			-- answer. Known-proxy domains never reach this gate -- the
			-- nameserver-policy below sends them straight to fb.
			dns["fallback-filter"] = {
				geoip = false,
				ipcidr = { "0.0.0.0/8", "127.0.0.0/8", "240.0.0.0/4",
					"::/128", "2001::/32" },
			}
		else
			fb = nil
		end
	end
	local cd = plain_dns_url(china_dns_server, nil) or (wan_dns_url())
	local policy = {}
	if routing_mode == "bypass_mainland_china" then
		policy["rule-set:china-domain"] = cd
		-- Known-bad domains (gfw list + user proxy list) go straight to the
		-- chained resolver: the domestic answer would be poisoned anyway,
		-- so skip the wasted primary query instead of fixing it up
		-- afterwards. Keys are emitted only for providers actually
		-- declared above -- a dangling rule-set ref fails `meow -t`.
		if fb then
			for _, name in ipairs({ "proxy-domain", "gfw-domain" }) do
				if rule_providers[name] then
					policy["rule-set:" .. name] = fb
				end
			end
		end
	end
	if DL then
		policy["rule-set:direct-domain"] = cd
	end
	if next(policy) then dns["nameserver-policy"] = policy end
else
	-- custom mode (§7.4): dns_server sections form the nameserver pool;
	-- dns_rule sections become nameserver-policy entries.
	local pool, seen = {}, {}
	uci:foreach(UCICONFIG, UCIDNSSERVER, function(cfg)
		if cfg.enabled ~= "1" then return end
		local url, err = dns_server_url(cfg)
		if not url then
			warn("dns server '%s': %s -- skipped.", tostring(cfg[".name"]), tostring(err))
			return
		end
		if not seen[url] then
			seen[url] = true
			push(pool, url)
		end
	end)
	local default_dns_url = dns_pool_url(uget(UCIROUTING, "default_outbound_dns")
		or uget(UCIDNS, "default_server"), "default dns")
	if not default_dns_url then default_dns_url = wan_dns_url() end
	if not seen[default_dns_url] then push(pool, default_dns_url) end
	dns.nameserver = pool

	local policy = {}
	uci:foreach(UCICONFIG, UCIDNSRULE, function(cfg)
		if cfg.enabled ~= "1" then return end
		local owner = "dns_rule " .. tostring(cfg[".name"])
		for k in pairs(SINGBOX_RULE_FIELDS) do
			if not isEmpty(cfg[k]) then
				warn("%s: sing-box-only field '%s' -- dropped.", owner, k)
			end
		end
		for _, k in ipairs({ "ip_cidr", "source_ip_cidr", "port", "port_range",
			"source_port", "source_port_range", "network", "protocol", "query_type",
			"domain_strategy", "client_subnet", "rewrite_ttl", "dns_disable_cache",
			"reject_method", "reject_no_drop", "predefined_rcode", "predefined_answer",
			"predefined_ns", "predefined_extra", "geosite" }) do
			if not isEmpty(cfg[k]) then
				warn("%s: field '%s' has no meow nameserver-policy equivalent -- dropped.", owner, k)
			end
		end
		if not isEmpty(cfg.action) and cfg.action ~= "route" then
			warn("%s: action '%s' is not 'route' -- skipped.", owner, tostring(cfg.action))
			return
		end
		local url = dns_pool_url(cfg.server, owner)
		if not url then
			if isEmpty(cfg.server) then
				warn("%s: no dns server configured -- skipped.", owner)
			end
			return
		end
		if not isEmpty(cfg.outbound) then
			url = dns_url_for_outbound(url, cfg.outbound)
		end
		local keys = {}
		for _, v in ipairs(str_list(cfg.domain) or {}) do push(keys, v) end
		for _, v in ipairs(str_list(cfg.domain_suffix) or {}) do push(keys, "+." .. v) end
		for _, v in ipairs(str_list(cfg.domain_keyword) or {}) do
			warn("%s: domain_keyword '%s' degrades to a plain domain key.", owner, v)
			push(keys, v)
		end
		for _, v in ipairs(str_list(cfg.domain_regex) or {}) do
			warn("%s: domain_regex '%s' degrades to a plain domain key.", owner, v)
			push(keys, v)
		end
		for _, v in ipairs(str_list(cfg.rule_set) or {}) do
			local pname, prov = provider_name_for(v)
			if pname then
				if prov.behavior ~= "domain" then
					warn("%s: provider '%s' behavior is %s -- nameserver-policy needs domain -- dropped.",
						owner, pname, prov.behavior)
				else
					push(keys, "rule-set:" .. pname)
				end
			end
		end
		for _, k in ipairs(keys) do policy[k] = url end
	end)
	if next(policy) then dns["nameserver-policy"] = policy end
end
config.dns = dns

-- Nothing in this config consumes geodata: rules use text rule-sets
-- (china-ip4/6), the DNS fallback gate is a static ipcidr list, and
-- GEOSITE rules are dropped upstream. Point every path at /dev/null so
-- meow's on-demand fetch never downloads the ~21MB bundle over the
-- proxied chain (or anywhere else).
config.geodata = {
	["mmdb-path"] = "/dev/null",
	["asn-path"] = "/dev/null",
	["geosite-path"] = "/dev/null",
}

-- ruleset providers may have been emitted during dns_rule processing.
if next(rule_providers) then
	config["rule-providers"] = rule_providers
end

---------------------------------------------------------------------------
-- Atomic writes: tmp + rename keeps the previous good file on failure.
---------------------------------------------------------------------------
local function atomic_write(path, content)
	local tmp = path .. ".tmp"
	if not hp.writefile(tmp, content) then
		os.remove(tmp)
		error("failed to write " .. tmp, 0)
	end
	local ok, err = os.rename(tmp, path)
	if not ok then
		os.remove(tmp)
		error("rename " .. tmp .. " -> " .. path .. " failed: " .. tostring(err), 0)
	end
end

-- unsupported-nodes.json is shared between three writers: this file owns
-- the role="client" partition (generate_server.lua owns role="server",
-- update_subscriptions.lua appends source="subscription"). Merge like
-- generate_server.lua's flush_unsupported: prior client records are
-- rewritten from live UCI on every run, other partitions pass through.
local function flush_unsupported()
	local existing = {}
	local raw = hp.readfile(UNSUPPORTED_FILE)
	if not isEmpty(raw) then
		local ok, j = pcall(hp.decode_json, raw)
		if ok and type(j) == "table" then existing = j end
	end
	local seen, merged = {}, {}
	for _, e in ipairs(existing) do
		if type(e) == "table" and e.role ~= "client" then
			local k = tostring(e.name) .. "|" .. tostring(e.type) .. "|" .. tostring(e.reason)
			if not seen[k] then merged[#merged + 1] = e; seen[k] = true end
		end
	end
	for _, e in ipairs(unsupported_nodes) do
		local k = tostring(e.name) .. "|" .. tostring(e.type) .. "|" .. tostring(e.reason)
		if not seen[k] then merged[#merged + 1] = e; seen[k] = true end
	end
	if #merged == 0 then
		-- Nothing quarantined anywhere: remove a stale file so
		-- `homeproxy nodes` / the API stop reporting ghosts.
		os.remove(UNSUPPORTED_FILE)
		return
	end
	atomic_write(UNSUPPORTED_FILE, hp.encode_json(merged))
end

hp.mkdir_p(hp.RUN_DIR)
flush_unsupported()
atomic_write(MEOW_FILE, hp.encode_json(config))
