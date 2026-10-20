-- SPDX-License-Identifier: GPL-2.0-only
-- Pure subscription parsing helpers for Lua 5.1 (meow-rs kernel).
-- The caller supplies runtime dependencies and feature flags so this module
-- remains independent from UCI, service control, and logging backends.
--
-- Parsed nodes are normalized UCI "node" tables. Before a node is returned
-- it passes the meow legality precheck (spec-meow-migration-A §4.4 rejection
-- table) implemented by M.validate_node -- the same function the generator
-- reuses for hand-written UCI nodes. parse_uri returns:
--   cfg                        on success
--   nil, reason, kind          on rejection/failure. kind is one of
--                              "unsupported-type"   (protocol has no meow
--                                                    equivalent: hysteria,
--                                                    tuic, wireguard, ssr,
--                                                    ssh, shadowtls, ...)
--                              "unsupported-scheme" (share-link scheme this
--                                                    parser cannot read)
--                              "unsupported-field"  (parsed ok but §4.4
--                                                    rejects a field value)
--                              "malformed"          (unparseable/junk input)

local M = {}

local function is_empty(hp, v) return hp.isEmpty(v) end

local function uridecode_component(s)
	if not s then return nil end
	return (s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end

local function aslist(hp, v)
	if is_empty(hp, v) then return nil end
	-- Only accept array-like tables: a JSON object (e.g. alpn:{...}) would
	-- leak into generated config verbatim.
	if type(v) == "table" then return (v[1] ~= nil) and v or nil end
	local t = {}
	for part in tostring(v):gmatch("[^,]+") do t[#t + 1] = part end
	return #t > 0 and t or nil
end

-- Coerce a JSON scalar to string; tables/functions become nil so malformed
-- provider data can never crash string functions downstream.
local function jstr(v)
	if type(v) == "string" then return v end
	if type(v) == "number" then return tostring(v) end
	return nil
end

-- Consistent boolean flag parsing (M8): real-world links serialise booleans
-- as "1", "true", or true.  Use this everywhere instead of inconsistent per-
-- scheme checks.
local function flag(v) return v == "1" or v == "true" or v == true or v == 1 end

---------------------------------------------------------------------------
-- meow v0.24.0 (`full` build) capability tables (spec §0.3 / §4.4).
-- These lists are the single source of truth for the subscription-side
-- precheck AND the generator-side quarantine (U3 reuses M.validate_node).
---------------------------------------------------------------------------

-- UCI node type -> meow proxies[] type (meow emits it, generator maps it).
M.SUPPORTED_TYPES = {
	shadowsocks = "ss",
	vmess = "vmess",
	vless = "vless",
	trojan = "trojan",
	hysteria2 = "hysteria2",
	snell = "snell",
	anytls = "anytls",
	socks = "socks5",
	http = "http",
}

-- Types the old kernel accepted but meow cannot emit at all: a hard error,
-- never silently mapped (spec §4.4 last rows).
M.UNSUPPORTED_TYPES = {
	hysteria = true,        -- hysteria v1: meow implements hysteria2 only
	tuic = true,
	wireguard = true,
	ssh = true,
	shadowtls = true,
	shadowsocksr = true,
	trusttunnel = true,
}

-- Pseudo node types: valid UCI sections but never materialized as proxies.
local PSEUDO_TYPES = { urltest = true, selector = true, direct = true, block = true, dns = true }

-- Share-link schemes naming a hard-unsupported protocol. These get an
-- explicit rejection reason (counted + logged) instead of falling through
-- to the generic "unknown scheme" path, per spec §9.1/AC-14.
local UNSUPPORTED_SCHEMES = {
	hysteria = "hysteria (v1)",
	tuic = "tuic",
	wireguard = "wireguard", wg = "wireguard",
	ssr = "shadowsocksr", shadowsocksr = "shadowsocksr",
	ssh = "ssh",
	shadowtls = "shadowtls", ["shadow-tls"] = "shadowtls",
	trusttunnel = "trusttunnel",
}

-- AEAD cipher set for ss outbounds. Verified against the reference v0.24.0
-- build: xchacha20-ietf-poly1305, aes-192-gcm and the ccm variants are NOT
-- compiled there and fail `meow -t`; stream ciphers parse but are excluded
-- anyway per spec §4.4 ("encrypt_method not in the AEAD set" -> quarantine).
M.SS_AEAD_METHODS = {
	["aes-128-gcm"] = true,
	["aes-256-gcm"] = true,
	["chacha20-ietf-poly1305"] = true,
	["2022-blake3-aes-128-gcm"] = true,
	["2022-blake3-aes-256-gcm"] = true,
	["2022-blake3-chacha20-poly1305"] = true,
}

-- In-process SIP003 plugin names (spec §0.3). Any other name becomes an
-- external plugin subprocess, which the deployed `--no-external-plugins`
-- command line rejects -- so such nodes are dropped here instead.
M.SS_BUILTIN_PLUGINS = {
	obfs = true, ["simple-obfs"] = true, ["v2ray-plugin"] = true,
	["gost-plugin"] = true, ["shadow-tls"] = true, restls = true,
	jls = true, ["ech-tls-tunnel"] = true, kcptun = true,
}

-- client-fingerprint values meow accepts (spec §4.4).
M.MEOW_UTLS = {
	chrome = true, firefox = true, safari = true, ios = true,
	android = true, edge = true, random = true, randomized = true,
}

-- transport value sets per meow type (spec §4.4; UCI "transport" field, nil
-- means tcp/plain).
local VLESS_TRANSPORTS = { tcp = true, ws = true, grpc = true, h2 = true, httpupgrade = true, xhttp = true }
local VMESS_TRANSPORTS = { tcp = true, ws = true }   -- meow vmess: tcp/ws only
-- meow rejects cipher 'zero' outright (security gap); keep it out of the set.
local VMESS_SECURITY = { auto = true, ["aes-128-gcm"] = true, ["chacha20-poly1305"] = true, none = true }
local SNELL_VERSIONS = { ["3"] = true, ["4"] = true, ["5"] = true, ["6"] = true, v3 = true, v4 = true, v5 = true, v6 = true }
local SMUX_PROTOCOLS = { smux = true, yamux = true, h2mux = true, muxcool = true }

-- Node type -> meow feature flag that gates it (probed per §9.3; absent or
-- true means available -- only an explicit false drops the node).
local FEATURE_BY_TYPE = {
	hysteria2 = "with_quic",
	shadowsocks = "with_ss",
	trojan = "with_trojan",
	vmess = "with_vmess",
	snell = "with_snell",
	anytls = "with_anytls",
}

local function apply_ws_early_data(cfg)
	if not cfg.ws_path then return end
	local path, ed = cfg.ws_path:match("^(.-)%?ed=(.+)$")
	if path and ed then
		cfg.ws_path = path
		cfg.websocket_early_data = ed
		cfg.websocket_early_data_header = "Sec-WebSocket-Protocol"
	end
end

-- Strict base64/base64url check + decoded byte length. meow's 2022-blake3
-- methods require the password to be a base64 key of exactly the cipher's
-- key length; `meow -t` hard-fails otherwise, so catch it here.
local function b64_key_len(hp, s)
	if type(s) ~= "string" or not s:match("^[A-Za-z0-9%+%/_%-]+=?=?$") then return nil end
	local d = hp.decodeBase64Str(s)
	return d and #d or nil
end

-- One meow `ports` hopping segment (Q6 syntax): a single decimal port or a
-- "start-end" range, bounds-checked (M14: only ',' separates segments; a
-- malformed set fails `meow -t`, so it is rejected by the precheck).
local function hop_port_seg(s)
	local a, b = s:match("^(%d+)%-(%d+)$")
	if a then
		a, b = tonumber(a), tonumber(b)
		return a >= 1 and a <= b and b <= 65535
	end
	if not s:match("^%d+$") then return false end
	local n = tonumber(s)
	return n >= 1 and n <= 65535
end

---------------------------------------------------------------------------
-- §4.4 legality precheck on a normalized UCI node table.
-- Returns true, or false + human-readable reason. May normalize cfg in place
-- (reality nodes without an explicit fingerprint get "chrome" -- spec §4.4).
-- Shared between the subscription path, add_nodes.lua, and the generator.
---------------------------------------------------------------------------
function M.validate_node(hp, cfg, features)
	if type(cfg) ~= "table" then return false, "not a node table" end
	local t = cfg.type
	if type(t) ~= "string" or t == "" then return false, "node missing type" end
	if UNSUPPORTED_SCHEMES[t] or M.UNSUPPORTED_TYPES[t] then
		return false, string.format("%s nodes are not supported by meow", UNSUPPORTED_SCHEMES[t] or t)
	end
	if PSEUDO_TYPES[t] then
		return false, string.format("%s is a pseudo outbound, not a proxy node", t)
	end
	if not M.SUPPORTED_TYPES[t] then
		return false, string.format("unknown node type '%s'", tostring(t))
	end
	local fk = FEATURE_BY_TYPE[t]
	if fk and features and features[fk] == false then
		return false, string.format("%s support is missing from this meow build", t)
	end

	if t == "shadowsocks" then
		if is_empty(hp, cfg.shadowsocks_encrypt_method) or is_empty(hp, cfg.password) then
			return false, "shadowsocks node missing encrypt_method or password"
		end
		if not M.SS_AEAD_METHODS[cfg.shadowsocks_encrypt_method] then
			return false, string.format("shadowsocks method '%s' is not an AEAD cipher meow accepts",
				tostring(cfg.shadowsocks_encrypt_method))
		end
		if cfg.shadowsocks_encrypt_method:sub(1, 12) == "2022-blake3-" then
			local need = (cfg.shadowsocks_encrypt_method == "2022-blake3-aes-128-gcm") and 16 or 32
			if b64_key_len(hp, cfg.password) ~= need then
				return false, string.format("shadowsocks %s requires a base64 key of %d bytes",
					cfg.shadowsocks_encrypt_method, need)
			end
		end
		if not is_empty(hp, cfg.shadowsocks_plugin) and not M.SS_BUILTIN_PLUGINS[cfg.shadowsocks_plugin] then
			return false, string.format("shadowsocks plugin '%s' is not a meow built-in (external SIP003 plugins are disabled)",
				tostring(cfg.shadowsocks_plugin))
		end
	elseif t == "vless" then
		if is_empty(hp, cfg.uuid) then return false, "vless node missing uuid" end
		if not is_empty(hp, cfg.vless_flow) and cfg.vless_flow ~= "xtls-rprx-vision" then
			return false, string.format("vless flow '%s' is not supported by meow (only xtls-rprx-vision)",
				tostring(cfg.vless_flow))
		end
		if not is_empty(hp, cfg.transport) and not VLESS_TRANSPORTS[cfg.transport] then
			return false, string.format("vless transport '%s' is not supported by meow", tostring(cfg.transport))
		end
		if cfg.tls_reality == "1" then
			if cfg.tls ~= "1" then
				return false, "vless reality requires tls"
			end
			if is_empty(hp, cfg.tls_reality_public_key) then
				return false, "vless reality node missing public key"
			end
			if is_empty(hp, cfg.tls_utls) then
				-- meow hard-errors on reality-opts without client-fingerprint;
				-- spec §4.4 fills "chrome" when the link carried none.
				if features and features.with_utls == false then
					return false, "vless reality requires client-fingerprint but this meow build lacks uTLS"
				end
				cfg.tls_utls = "chrome"
			end
		end
	elseif t == "vmess" then
		if is_empty(hp, cfg.uuid) then return false, "vmess node missing uuid" end
		if not is_empty(hp, cfg.transport) and not VMESS_TRANSPORTS[cfg.transport] then
			return false, string.format("vmess transport '%s' is not supported by meow (tcp/ws only)",
				tostring(cfg.transport))
		end
		if not is_empty(hp, cfg.vmess_encrypt) and not VMESS_SECURITY[cfg.vmess_encrypt] then
			return false, string.format("vmess security '%s' is not supported by meow", tostring(cfg.vmess_encrypt))
		end
	elseif t == "trojan" then
		if is_empty(hp, cfg.password) then return false, "trojan node missing password" end
		-- meow trojan is bare TCP+TLS: transport keys are silently ignored at
		-- parse, so a ws/grpc node would lose its camouflage without warning.
		if not is_empty(hp, cfg.transport) or not is_empty(hp, cfg.ws_host)
			or not is_empty(hp, cfg.grpc_servicename) or not is_empty(hp, cfg.http_host)
			or not is_empty(hp, cfg.httpupgrade_host) then
			return false, "trojan transports (ws/grpc/http/quic) are not supported by meow"
		end
	elseif t == "hysteria2" then
		if is_empty(hp, cfg.password) then return false, "hysteria2 node missing password" end
		if not is_empty(hp, cfg.hysteria_obfs_type) then
			if cfg.hysteria_obfs_type ~= "salamander" then
				return false, string.format("hysteria2 obfs '%s' is not supported by meow (salamander only)",
					tostring(cfg.hysteria_obfs_type))
			end
			if is_empty(hp, cfg.hysteria_obfs_password) then
				return false, "hysteria2 salamander obfs requires a password"
			end
		end
		-- meow `ports` port-hopping set (Q6 syntax): ','-separated segments
		-- only, each "443" or "1000-2000" with 1<=start<=end<=65535 (M14).
		-- A malformed value fails `meow -t`, so precheck it.
		if not is_empty(hp, cfg.hysteria_hopping_port) then
			local v = cfg.hysteria_hopping_port
			if type(v) == "table" then
				for _, p in ipairs(v) do
					if not hop_port_seg(tostring(p)) then
						return false, "hysteria2 ports list contains an invalid port"
					end
				end
			else
				local sv, ok = tostring(v), false
				for seg in sv:gmatch("[^,]+") do
					if not hop_port_seg(seg) then
						return false, string.format("hysteria2 ports '%s' is not a valid port set", sv)
					end
					ok = true
				end
				if not ok then
					return false, string.format("hysteria2 ports '%s' is not a valid port set", sv)
				end
			end
		end
	elseif t == "anytls" then
		if is_empty(hp, cfg.password) then return false, "anytls node missing password" end
		if cfg.tls_reality == "1" then
			return false, "anytls over REALITY is not supported by meow"
		end
	elseif t == "snell" then
		if is_empty(hp, cfg.snell_psk) and is_empty(hp, cfg.psk) then
			return false, "snell node missing psk"
		end
		local v = cfg.snell_version or cfg.version
		if not is_empty(hp, v) and not SNELL_VERSIONS[tostring(v)] then
			return false, string.format("snell version '%s' is not supported by meow (3-6)", tostring(v))
		end
		local om = cfg.snell_obfs_mode or cfg.obfs_mode
		if not is_empty(hp, om) and om ~= "http" and om ~= "tls" then
			return false, string.format("snell obfs mode '%s' is not supported (http/tls)", tostring(om))
		end
	elseif t == "socks" then
		if cfg.socks_version == "4" then
			return false, "meow supports socks5 only (socks4/socks4a link)"
		end
		-- meow hard-errors on an orphaned credential (Class A): both or neither.
		if (cfg.username == nil) ~= (cfg.password == nil) then
			return false, "socks node must set both 'username' and 'password', or neither"
		end
	elseif t == "http" then
		if (cfg.username == nil) ~= (cfg.password == nil) then
			return false, "http node must set both 'username' and 'password', or neither"
		end
	end

	-- client-fingerprint legality wherever it is set (vless/vmess primarily).
	if not is_empty(hp, cfg.tls_utls) then
		if features and features.with_utls == false then
			return false, "client-fingerprint set but this meow build lacks uTLS"
		end
		if not M.MEOW_UTLS[cfg.tls_utls] then
			return false, string.format("invalid client-fingerprint '%s'", tostring(cfg.tls_utls))
		end
	end
	-- multiplex -> meow smux: protocol must be a known value when given.
	if cfg.multiplex == "1" and not is_empty(hp, cfg.multiplex_protocol) then
		if not SMUX_PROTOCOLS[cfg.multiplex_protocol] then
			return false, string.format("multiplex protocol '%s' is not a meow smux protocol",
				tostring(cfg.multiplex_protocol))
		end
		-- Same gate as the generator's build_smux: meow parses muxcool on
		-- vless/vmess only (L26).
		if cfg.multiplex_protocol == "muxcool" and t ~= "vless" and t ~= "vmess" then
			return false, "multiplex protocol 'muxcool' is VLESS/VMess-only on meow"
		end
	end
	return true
end

local function parse_share_url(hp, scheme, rest)
	local url = hp.parseURL("http://" .. rest)
	if not url then return nil end
	-- Stop at '/' so authority matches what parseURL sees (H6: URIs with a
	-- path before the query would otherwise fail port detection and fall back
	-- to the scheme default, connecting to the wrong port).
	local authority = rest:match("^([^?#/]*)") or ""
	local has_port = authority:match("%]:%d+$") or authority:match("[^:]:%d+$")
	if not has_port then
		local defaults = {
			http = "80", https = "443", socks = "1080", socks4 = "1080",
			socks4a = "1080", socks5 = "1080", socks5h = "1080",
			anytls = "443", hysteria2 = "443", hy2 = "443",
			trojan = "443", vless = "443", snell = "443"
		}
		-- parseURL sees a synthetic http authority. SIP002 still requires an
		-- explicit port, so ss intentionally gets no implicit default here.
		url.port = defaults[scheme]
	end
	return url
end

local function normalize_node(hp, cfg)
	if type(cfg) ~= "table" or is_empty(hp, cfg.address) or is_empty(hp, cfg.port) then
		return nil, "node missing server address or port"
	end
	cfg.address = tostring(cfg.address):gsub("[%[%]]", "")
	local valid_host = hp.validation("ip4addr", cfg.address)
		or hp.validation("ip6addr", cfg.address)
		or hp.validation("hostname", cfg.address)
	if not valid_host or not hp.validation("port", tostring(cfg.port)) then
		return nil, "invalid server address or port"
	end
	if is_empty(hp, cfg.label) then
		local addr = hp.validation("ip6addr", cfg.address) and ("[" .. cfg.address .. "]") or cfg.address
		cfg.label = addr .. ":" .. tostring(cfg.port)
	end
	return cfg
end

local function parse_ss(hp, rest)
	local body, frag = rest, nil
	local hashpos = rest:find("#", 1, true)
	if hashpos then body, frag = rest:sub(1, hashpos - 1), rest:sub(hashpos + 1) end
	-- Shadowrocket whole-body form. Decode only an unambiguous Base64 body.
	if body and not body:find("@", 1, true) and body:match("^[A-Za-z0-9%+%/_%=%-]+$") then
		local dec = hp.decodeBase64Str(body)
		if dec and dec:find("@", 1, true) then
			local dh = dec:find("#", 1, true)
			if dh then
				body = dec:sub(1, dh - 1)
				if not frag then frag = dec:sub(dh + 1) end
			else
				body = dec
			end
		end
	end
	local ssuserinfo, hostpart = body:match("^(.*)@([^@]*)$")
	if not ssuserinfo then return nil, "malformed ss link (missing userinfo)" end
	local ssurl = parse_share_url(hp, "ss", hostpart)
	if not ssurl then return nil, "malformed ss link (bad host:port)" end
	local ssp = ssurl.searchParams or {}
	local method, pass = ssuserinfo:match("^([^:]+):(.*)$")
	if method then
		pass = uridecode_component(pass)
	else
		local d = hp.decodeBase64Str(uridecode_component(ssuserinfo))
		if d then method, pass = d:match("^([^:]+):(.*)$") end
	end
	local ssplugin, sspluginopts
	if ssp.plugin and ssp.plugin ~= "" then
		local pname, popts = ssp.plugin:match("^([^;]+);?(.*)$")
		-- meow's in-process simple-obfs names are "obfs"/"simple-obfs"; the
		-- legacy "obfs-local" name maps onto the "obfs" builtin.
		if pname == "simple-obfs" or pname == "obfs-local" then pname = "obfs" end
		ssplugin = pname
		sspluginopts = not is_empty(hp, popts) and popts or nil
	end
	if not method or not ssurl.hostname or not ssurl.port then
		return nil, "malformed ss link (missing method/host/port)"
	end
	local sslabel = frag and hp.urldecode(frag) or nil
	return { label = sslabel, type = "shadowsocks", address = ssurl.hostname,
		port = ssurl.port, shadowsocks_encrypt_method = method, password = pass,
		shadowsocks_plugin = ssplugin, shadowsocks_plugin_opts = sspluginopts }
end

local function parse_uri_raw(hp, opts, uri)
	local features = opts.features or {}
	local packet_encoding = opts.packet_encoding or "xudp"
	if type(uri) == "table" then
		if uri.nodetype ~= "sip008" then return nil end
		-- Coerce every field: a malformed SIP008 server object (remarks as a
		-- number, etc.) must not crash string functions or leak non-strings
		-- into the generated config.
		local sip008_plugin = jstr(uri.plugin)
		-- Same normalization as parse_ss: legacy names map onto the "obfs"
		-- builtin so SIP008 and share-link inputs converge.
		if sip008_plugin == "simple-obfs" or sip008_plugin == "obfs-local" then
			sip008_plugin = "obfs"
		end
		return { label = jstr(uri.remarks), type = "shadowsocks", address = jstr(uri.server),
			port = uri.server_port and tostring(uri.server_port),
			shadowsocks_encrypt_method = jstr(uri.method), password = jstr(uri.password),
			shadowsocks_plugin = sip008_plugin, shadowsocks_plugin_opts = jstr(uri.plugin_opts) }
	end
	if type(uri) ~= "string" then return nil end
	uri = uri:gsub("^%s+", ""):gsub("%s+$", "")
	local scheme, rest = uri:match("^(%w[%w+.-]*)://(.*)$")
	if not scheme then return nil end -- not URI-shaped: junk line, stay silent
	scheme = scheme:lower()
	-- Hard-unsupported protocols: explicit rejection reason (counted +
	-- logged upstream) rather than a silent drop.
	local uname = UNSUPPORTED_SCHEMES[scheme]
	if uname then
		return nil, string.format("%s nodes are not supported by meow", uname), "unsupported-type", uname
	end
	if scheme == "ss" then
		local cfg, err = parse_ss(hp, rest)
		if not cfg then return nil, err, "malformed", "shadowsocks" end
		return cfg
	end
	if scheme == "vmess" then
		if rest:find("&", 1, true) then
			return nil, "unsupported vmess format", "malformed", "vmess"
		end
		-- Strip fragment/query before base64 decode (M7): characters in #tag
		-- that happen to be base64-valid would corrupt the trailing JSON.
		local b64 = rest:match("^([^?#]*)") or rest
		local raw = hp.decodeBase64Str(b64)
		if is_empty(hp, raw) then
			return nil, "unsupported vmess format", "malformed", "vmess"
		end
		local ok, j = pcall(hp.decode_json, raw)
		-- v2rayN exports "v" as a JSON number; some providers use "2".
		if not ok or type(j) ~= "table" or (j.v ~= "2" and j.v ~= 2) or is_empty(hp, j.add)
			or is_empty(hp, j.port) or is_empty(hp, j.id) then
			return nil, "unsupported vmess format", "malformed", "vmess"
		end
		local net = jstr(j.net) or "tcp"
		local cfg = { label = jstr(j.ps) and hp.urldecode(jstr(j.ps)) or nil, type = "vmess", address = jstr(j.add),
			port = tostring(j.port), uuid = jstr(j.id), vmess_alterid = tostring(tonumber(j.aid) or 0),
			vmess_encrypt = jstr(j.scy) or "auto", vmess_global_padding = "1",
			transport = (net ~= "tcp") and net or nil,
			tls = (j.tls == "tls" or flag(j.tls)) and "1" or "0",
			-- Insecure markers used by exporters (M9): allowInsecure and
			-- skip-cert-verify mean "skip verify" directly; verify_cert is
			-- the inverted form (false/0 = skip verification).
			tls_insecure = (flag(j.allowInsecure) or flag(j["skip-cert-verify"])
				or j.verify_cert == false or j.verify_cert == "false"
				or j.verify_cert == "0" or j.verify_cert == 0) and "1" or "0",
			tls_sni = jstr(j.sni) or jstr(j.host), tls_alpn = aslist(hp, j.alpn),
			tls_utls = (features.with_utls ~= false and not is_empty(hp, j.fp)) and jstr(j.fp) or nil,
			packet_encoding = packet_encoding }
		if net == "h2" or (net == "tcp" and j.type == "http") then
			cfg.transport, cfg.http_host, cfg.http_path = "http", aslist(hp, j.host), jstr(j.path)
		elseif net == "grpc" then cfg.grpc_servicename = jstr(j.path)
		elseif net == "httpupgrade" then cfg.httpupgrade_host, cfg.http_path = jstr(j.host), jstr(j.path)
		elseif net == "ws" then cfg.ws_host, cfg.ws_path = jstr(j.host), jstr(j.path) or "/"; apply_ws_early_data(cfg) end
		-- Transport legality is decided by validate_node (§4.4: meow vmess
		-- accepts tcp/ws only -- quic/kcp/grpc/http/httpupgrade all reject).
		return cfg
	end
	local url = parse_share_url(hp, scheme, rest)
	if not url then
		return nil, string.format("malformed %s link (bad host:port)", scheme), "malformed", scheme
	end
	local p, label = url.searchParams or {}, url.hash and hp.urldecode(url.hash) or nil
	if scheme == "anytls" then
		return { label = label, type = "anytls", address = url.hostname, port = url.port,
			password = uridecode_component(url.username), tls = "1", tls_sni = p.sni,
			tls_alpn = aslist(hp, p.alpn), tls_insecure = flag(p.insecure) and "1" or "0",
			tls_reality = (p.security == "reality") and "1" or "0",
			tls_reality_public_key = p.pbk, tls_reality_short_id = p.sid,
			tls_utls = (features.with_utls ~= false and not is_empty(hp, p.fp)) and p.fp or nil }
	elseif scheme == "http" or scheme == "https" then
		return { label = label, type = "http", address = url.hostname, port = url.port,
			username = url.username and uridecode_component(url.username) or nil,
			password = url.password and uridecode_component(url.password) or nil,
			tls = (scheme == "https") and "1" or "0",
			tls_insecure = (flag(p.allowInsecure) or flag(p.insecure)) and "1" or "0" }
	elseif scheme == "socks" or scheme == "socks4" or scheme == "socks4a" or scheme == "socks5" or scheme == "socks5h" then
		return { label = label, type = "socks", socks_version = scheme:match("4") and "4" or "5",
			address = url.hostname, port = url.port, username = url.username and uridecode_component(url.username) or nil,
			password = url.password and uridecode_component(url.password) or nil }
	elseif scheme == "trojan" then
		-- meow trojan has no transports: parse them anyway so validate_node
		-- rejects the node with a precise reason instead of silently
		-- stripping the camouflage (§4.4).
		local cfg = { label = label, type = "trojan", address = url.hostname, port = url.port,
			password = uridecode_component(url.username), tls = "1", tls_sni = p.sni,
			tls_insecure = (flag(p.allowInsecure) or flag(p.insecure)) and "1" or "0",
			tls_alpn = aslist(hp, p.alpn), transport = (p.type and p.type ~= "tcp") and p.type or nil }
		if p.type == "grpc" then cfg.grpc_servicename = p.serviceName
		elseif p.type == "ws" then cfg.ws_host, cfg.ws_path = p.host, p.path or "/"; apply_ws_early_data(cfg)
		elseif p.type == "http" then cfg.http_host, cfg.http_path = aslist(hp, p.host), p.path
		elseif p.type == "httpupgrade" then cfg.httpupgrade_host, cfg.http_path = p.host, p.path end
		return cfg
	elseif scheme == "hysteria2" or scheme == "hy2" then
		-- Port hopping: the community `mport` key (Clash Verge Rev) and
		-- mihomo's `ports` alias both carry the hop set (M12).
		local hop = p.mport or p.ports
		local port = url.port
		if not is_empty(hp, hop) then
			-- mport links put the dial port at the head of the hop set and
			-- commonly omit :port from the authority (parse_share_url then
			-- invented the 443 default): normalize port from the hop head,
			-- with the authority port as the fallback (M12).
			port = tostring(hop):match("^(%d+)") or port
		end
		return { label = label, type = "hysteria2", address = url.hostname, port = port,
			password = url.username and uridecode_component(url.username .. (url.password and (":" .. url.password) or "")) or nil,
			hysteria_obfs_type = p.obfs, hysteria_obfs_password = p["obfs-password"], tls = "1",
			hysteria_hopping_port = hop,
			tls_sni = p.sni, tls_insecure = flag(p.insecure) and "1" or "0", tls_alpn = aslist(hp, p.alpn) }
	elseif scheme == "vless" then
		local sec, has_tls = p.security, (p.security == "tls" or p.security == "xtls" or p.security == "reality")
		local cfg = { label = label, type = "vless", address = url.hostname, port = url.port, uuid = uridecode_component(url.username),
			transport = (p.type and p.type ~= "tcp") and p.type or nil, tls = has_tls and "1" or "0", tls_sni = p.sni,
			tls_insecure = (flag(p.allowInsecure) or flag(p.insecure)) and "1" or "0",
			tls_alpn = aslist(hp, p.alpn), tls_reality = (sec == "reality") and "1" or "0",
			tls_reality_public_key = p.pbk, tls_reality_short_id = p.sid,
			tls_utls = (features.with_utls ~= false and not is_empty(hp, p.fp)) and p.fp or nil,
			-- security=xtls in a share link IS flow xtls-rprx-vision (M13);
			-- silently dropping it changed both the transport and TLS shape.
			vless_flow = (sec == "xtls") and "xtls-rprx-vision"
				or ((sec == "tls" or sec == "reality") and p.flow or nil),
			packet_encoding = packet_encoding }
		if p.type == "grpc" then cfg.grpc_servicename = p.serviceName
		elseif p.type == "h2" then
			-- The h2 arm was missing entirely (M13): feed the generator's
			-- h2-opts source fields so the node keeps its camouflage.
			cfg.http_host, cfg.http_path = aslist(hp, p.host), p.path
		elseif p.type == "http" or (p.type == "tcp" and p.headerType == "http") then
			-- headerType=http camouflage: the transport must be set to http or
			-- the host/path fields would be silently dropped by the generator.
			-- meow rejects "http" as a vless network -> validate_node drops it.
			cfg.transport, cfg.http_host, cfg.http_path = "http", aslist(hp, p.host), p.path
		elseif p.type == "xhttp" then
			-- meow accepts the transport but exposes no xhttp-opts UCI
			-- surface: host/path/mode degrade to meow defaults. Warn instead
			-- of silently degrading (M13).
			if opts.log then opts.log(string.format(
				"vless xhttp node %s: link xhttp parameters degrade to meow defaults.",
				tostring(label or url.hostname))) end
		elseif p.type == "httpupgrade" then cfg.httpupgrade_host, cfg.http_path = p.host, p.path
		elseif p.type == "ws" then cfg.ws_host, cfg.ws_path = p.host, p.path or "/"; apply_ws_early_data(cfg) end
		return cfg
	end
	return nil, string.format("unsupported subscription scheme '%s'", scheme), "unsupported-scheme", scheme
end

function M.parse_uri(hp, opts, uri)
	opts = opts or {}
	local cfg, err, kind, hint = parse_uri_raw(hp, opts, uri)
	if not cfg then return nil, err, kind, hint end
	local ncfg, nerr = normalize_node(hp, cfg)
	if not ncfg then
		return nil, nerr or "invalid node", "malformed", cfg.type
	end
	local ok, verr = M.validate_node(hp, ncfg, opts.features)
	if not ok then
		return nil, verr, "unsupported-field", ncfg.type
	end
	return ncfg
end

function M.decode_subscription_body(hp, res)
	local function looks_like(s)
		if not s then return false end
		for line in s:gmatch("[^\r\n]+") do
			if line:match("^%s*[%a][%w+%.%-]*://") then return true end
		end
		return false
	end
	local plain = hp.trim(res)
	if is_empty(hp, plain) or looks_like(plain) then return plain end
	local decoded = hp.decodeBase64Str(plain)
	return looks_like(decoded) and decoded or plain
end

function M.filter_check(hp, name, mode, keywords)
	if is_empty(hp, name) or mode == "disabled" then return false end
	if type(keywords) ~= "table" or #keywords == 0 then return false end
	local matched = false
	for _, kw in ipairs(keywords) do
		for term in tostring(kw):gmatch("[^|]+") do
			if name:find(term, 1, true) then matched = true; break end
		end
		if matched then break end
	end
	if mode == "whitelist" then return not matched end
	return matched
end

return M
