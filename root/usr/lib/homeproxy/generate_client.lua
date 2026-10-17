#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy client config generator (Lua port of generate_client.uc).
-- Reads /etc/config/homeproxy via the uci Lua binding and emits the
-- sing-box client JSON to /var/run/homeproxy/sing-box-c.json.

package.path = (os.getenv("HP_LUAPATH") or "/usr/lib/homeproxy") .. "/?.lua;" .. package.path

local hp   = require("homeproxy")
local uci  = require("uci").cursor(os.getenv("HP_CONFDIR") or "/etc/config")

local UCICONFIG = "homeproxy"
uci:load(UCICONFIG)

-- Remove any stale output up front: an error()/os.exit mid-generation must
-- not leave a previous JSON that init.d's existence check would then pass.
os.remove(hp.RUN_DIR .. "/sing-box-c.json")

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

local function uget(sec, opt) return uci:get(UCICONFIG, sec, opt) end
local function isEmpty(v) return hp.isEmpty(v) end
local function strToBool(v) return hp.strToBool(v) end
local function strToInt(v) return hp.strToInt(v) end
local function strToTime(v) return hp.strToTime(v) end
local function push(t, v) t[#t + 1] = v end
local function map(arr, fn)
    if not arr then return nil end
    if type(arr) ~= "table" then arr = { arr } end
    local out = {}
    -- Skip nil results: writing fn(v) at index i leaves a sparse table that
    -- clean() then encodes as a JSON *object* where sing-box needs an array.
    for _, v in ipairs(arr) do
        local r = fn(v)
        if r ~= nil then out[#out + 1] = r end
    end
    return out
end
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

local function get_wan_dns()
    -- Reject loopback/unspecified resolvers: they point back at the local
    -- dnsmasq, which forwards right into sing-box -- a resolution loop.
    -- A UCI "dns" list is a table; take its first entry.
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

local routing_mode = uget(UCIMAIN, "routing_mode") or "bypass_mainland_china"

local wan_dns = get_wan_dns()
if isEmpty(wan_dns) then
    wan_dns = (routing_mode == "proxy_mainland_china" or routing_mode == "global")
        and "8.8.8.8" or "223.5.5.5"
end

local dns_port = uget(UCIINFRA, "dns_port") or "5333"
local ntp_server = uget(UCIINFRA, "ntp_server") or "time.apple.com"
local ipv6_support = uget(UCIMAIN, "ipv6_support") or "0"

local main_node, main_udp_node, dedicated_udp_node, default_outbound, default_outbound_dns,
      domain_strategy, dns_server, dns_server_proto, china_dns_server, dns_default_strategy,
      dns_default_server, dns_disable_cache, dns_disable_cache_expire, dns_independent_cache,
      dns_client_subnet, cache_file_store_rdrc, cache_file_rdrc_timeout,
      direct_domain_list, proxy_domain_list

if routing_mode ~= "custom" then
    main_node = uget(UCIMAIN, "main_node") or "nil"
    main_udp_node = uget(UCIMAIN, "main_udp_node") or "nil"

    -- A main_node/main_udp_node pointing at a deleted section would emit
    -- route.final="main-out" / a udp rule with no such outbound -> sing-box
    -- check fails and the whole service refuses to start. Fall back instead.
    local function node_exists(name)
        local s = not isEmpty(name) and uci:get_all(UCICONFIG, name) or nil
        return type(s) == "table" and s[".type"] == "node"
    end
    if main_node ~= "urltest" and not isEmpty(main_node) and not node_exists(main_node) then
        io.stderr:write("homeproxy: WARNING: main_node '" .. tostring(main_node)
            .. "' does not exist -- falling back to direct.\n")
        main_node = "nil"
    end

    -- main_udp_node="urltest" names an independent group even when main_node
    -- is also "urltest" -- the plain ~= comparison would treat them as one
    -- node and never route UDP to main-udp-out.
    dedicated_udp_node = not isEmpty(main_udp_node)
        and main_udp_node ~= "same"
        and (main_udp_node == "urltest" or main_udp_node ~= main_node)
    if dedicated_udp_node and main_udp_node ~= "urltest" and not node_exists(main_udp_node) then
        io.stderr:write("homeproxy: WARNING: main_udp_node '" .. tostring(main_udp_node)
            .. "' does not exist -- UDP falls back to the main node.\n")
        main_udp_node = "same"
        dedicated_udp_node = false
    end

    dns_server = uget(UCIMAIN, "dns_server")
    -- Bare "wan"/unset means the ISP resolver -- plain UDP; DoH would fail.
    -- An explicit bare IP keeps the deliberate DoH upgrade (see main-dns).
    dns_server_proto = "https"
    if isEmpty(dns_server) or dns_server == "wan" then
        dns_server = wan_dns
        dns_server_proto = "udp"
    end

    if routing_mode == "bypass_mainland_china" then
        china_dns_server = uget(UCIMAIN, "china_dns_server")
        if isEmpty(china_dns_server) or type(china_dns_server) ~= "string" or china_dns_server == "wan" then
            china_dns_server = wan_dns
        end
    end
    dns_default_strategy = (ipv6_support ~= "1") and "ipv4_only" or nil

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
    dns_default_strategy  = uget(UCIDNS, "default_strategy") or uget(UCIDNS, "dns_strategy")
    dns_default_server     = uget(UCIDNS, "default_server")
    -- default_server must resolve to an *enabled* dns_server section (or a
    -- builtin tag); a dangling or disabled name becomes a cfg-*-dns tag that
    -- is never emitted, and sing-box rejects the config.
    if not isEmpty(dns_default_server)
        and dns_default_server ~= "default-dns" and dns_default_server ~= "system-dns" then
        local sec = uci:get_all(UCICONFIG, dns_default_server)
        if not sec or sec.enabled ~= "1" then
            io.stderr:write("homeproxy: WARNING: dns.default_server '" .. tostring(dns_default_server)
                .. "' is not an enabled dns_server section -- falling back to system-dns.\n")
            dns_default_server = "system-dns"
        end
    end
    dns_disable_cache      = uget(UCIDNS, "disable_cache")
    dns_disable_cache_expire = uget(UCIDNS, "disable_cache_expire")
    dns_independent_cache  = uget(UCIDNS, "independent_cache")
    dns_client_subnet      = uget(UCIDNS, "client_subnet")
    cache_file_store_rdrc  = uget(UCIDNS, "cache_file_store_rdrc")
    cache_file_rdrc_timeout = uget(UCIDNS, "cache_file_rdrc_timeout")

    default_outbound       = uget(UCIROUTING, "default_outbound") or "nil"
    default_outbound_dns   = uget(UCIROUTING, "default_outbound_dns") or "default-dns"
    domain_strategy        = uget(UCIROUTING, "domain_strategy")
end

local proxy_mode = uget(UCIMAIN, "proxy_mode") or "redirect_tproxy"
local default_interface = uget(UCICONTROL, "bind_interface")
local mixed_port = uget(UCIINFRA, "mixed_port") or "5330"

local self_mark, redirect_port, tproxy_port, tun_name,
      tun_addr4, tun_addr6, tun_mtu, tcpip_stack,
      endpoint_independent_nat, udp_timeout

if routing_mode == "custom" then
    udp_timeout = uget(UCIROUTING, "udp_timeout")
else
    udp_timeout = uget(UCIINFRA, "udp_timeout")
end

-- self_mark must exist in EVERY mode, not just redirect: all outbounds carry
-- it as routing_mark so sing-box egress escapes the firewall's own OUTPUT
-- steering. Without it, tproxy/tun-only modes loop traffic back into sing-box.
self_mark = uget(UCIINFRA, "self_mark") or "100"
if not tostring(self_mark):match("^%d+$") then
    io.stderr:write("homeproxy: WARNING: self_mark '" .. tostring(self_mark)
        .. "' is not numeric -- using 100.\n")
    self_mark = "100"
end
if proxy_mode:find("redirect") then
    redirect_port = uget(UCIINFRA, "redirect_port") or "5331"
end
if proxy_mode:find("tproxy") then
    tproxy_port = uget(UCIINFRA, "tproxy_port") or "5332"
end
if proxy_mode:find("tun") then
    tun_name = uget(UCIINFRA, "tun_name") or "singtun0"
    tun_addr4 = uget(UCIINFRA, "tun_addr4") or "172.19.0.1/30"
    tun_addr6 = uget(UCIINFRA, "tun_addr6") or "fdfe:dcba:9876::1/126"
    tun_mtu = uget(UCIINFRA, "tun_mtu") or "9000"
    tcpip_stack = "system"
    if routing_mode == "custom" then
        tcpip_stack = uget(UCIROUTING, "tcpip_stack") or "system"
        endpoint_independent_nat = uget(UCIROUTING, "endpoint_independent_nat")
    end
end

local log_level = uget(UCIMAIN, "log_level") or "warn"

-- config helpers
local function parse_port(strport)
    if type(strport) ~= "table" or isEmpty(strport) then return nil end
    return map(strport, function(i)
        local n = strToInt(i)
        return (n and n >= 0 and n <= 65535) and n or nil
    end)
end

local function parse_dnsserver(server_addr, default_protocol)
    if isEmpty(server_addr) then return nil end
    if not tostring(server_addr):find("://") then
        server_addr = (default_protocol or "udp") .. "://"
            .. (hp.validation("ip6addr", server_addr) and ("[" .. server_addr .. "]") or server_addr)
    end
    server_addr = hp.parseURL(server_addr)
    if not server_addr then return nil end
    return {
        type = server_addr.protocol,
        server = server_addr.hostname,
        server_port = strToInt(server_addr.port),
        path = (server_addr.pathname ~= "/") and server_addr.pathname or nil,
    }
end

local function parse_dnsquery(strquery)
    if type(strquery) ~= "table" or isEmpty(strquery) then return nil end
    local out = {}
    for _, i in ipairs(strquery) do
        local n = tonumber(i)
        out[#out + 1] = n or i
    end
    return out
end

local function generate_endpoint(node)
    if type(node) ~= "table" or isEmpty(node) then return nil end
    return {
        type = node.type,
        tag = "cfg-" .. node[".name"] .. "-out",
        address = node.wireguard_local_address,
        mtu = strToInt(node.wireguard_mtu),
        private_key = node.wireguard_private_key,
        peers = (node.type == "wireguard") and {
            {
                address = node.address,
                port = strToInt(node.port),
                allowed_ips = { "0.0.0.0/0", "::/0" },
                persistent_keepalive_interval = strToInt(node.wireguard_persistent_keepalive_interval),
                public_key = node.wireguard_peer_public_key,
                pre_shared_key = node.wireguard_pre_shared_key,
                reserved = parse_port(node.wireguard_reserved),
            }
        } or nil,
        system = (node.type == "wireguard") and false or nil,
        -- DialerOptions field: without it the wg handshake egresses unmarked
        -- and the OUTPUT steering hook recaptures it -> handshake loop.
        routing_mark = strToInt(self_mark),
        tcp_fast_open = strToBool(node.tcp_fast_open),
        tcp_multi_path = strToBool(node.tcp_multi_path),
        udp_fragment = strToBool(node.udp_fragment),
    }
end

local function generate_outbound(node)
    if type(node) ~= "table" or isEmpty(node) then return nil end
    return {
        type = node.type,
        tag = "cfg-" .. node[".name"] .. "-out",
        routing_mark = strToInt(self_mark),
        server = node.address,
        server_port = strToInt(node.port),
        server_ports = node.hysteria_hopping_port,
        username = (node.type ~= "ssh") and node.username or nil,
        user = (node.type == "ssh") and node.username or nil,
        password = node.password,
        override_address = node.override_address,
        override_port = strToInt(node.override_port),
        proxy_protocol = strToInt(node.proxy_protocol),
        idle_session_check_interval = strToTime(node.anytls_idle_session_check_interval),
        idle_session_timeout = strToTime(node.anytls_idle_session_timeout),
        min_idle_session = strToInt(node.anytls_min_idle_session),
        hop_interval = strToTime(node.hysteria_hop_interval),
        up_mbps = strToInt(node.hysteria_up_mbps),
        down_mbps = strToInt(node.hysteria_down_mbps),
        obfs = node.hysteria_obfs_type and {
            type = node.hysteria_obfs_type,
            password = node.hysteria_obfs_password,
        } or node.hysteria_obfs_password,
        auth = (node.hysteria_auth_type == "base64") and node.hysteria_auth_payload or nil,
        auth_str = (node.hysteria_auth_type == "string") and node.hysteria_auth_payload or nil,
        recv_window_conn = strToInt(node.hysteria_recv_window_conn),
        recv_window = strToInt(node.hysteria_revc_window),
        disable_mtu_discovery = strToBool(node.hysteria_disable_mtu_discovery),
        method = node.shadowsocks_encrypt_method,
        plugin = node.shadowsocks_plugin,
        plugin_opts = node.shadowsocks_plugin_opts,
        version = (node.type == "shadowtls") and strToInt(node.shadowtls_version)
            or ((node.type == "socks") and node.socks_version or nil),
        client_version = node.ssh_client_version,
        host_key = node.ssh_host_key,
        host_key_algorithms = node.ssh_host_key_algo,
        private_key = node.ssh_priv_key,
        private_key_passphrase = node.ssh_priv_key_pp,
        uuid = node.uuid,
        congestion_control = node.tuic_congestion_control,
        udp_relay_mode = node.tuic_udp_relay_mode,
        udp_over_stream = strToBool(node.tuic_udp_over_stream),
        zero_rtt_handshake = strToBool(node.tuic_enable_zero_rtt),
        heartbeat = strToTime(node.tuic_heartbeat),
        flow = node.vless_flow,
        alter_id = strToInt(node.vmess_alterid),
        security = node.vmess_encrypt,
        global_padding = strToBool(node.vmess_global_padding),
        authenticated_length = strToBool(node.vmess_authenticated_length),
        packet_encoding = node.packet_encoding,
        multiplex = (node.multiplex == "1") and {
            enabled = true,
            protocol = node.multiplex_protocol,
            max_connections = strToInt(node.multiplex_max_connections),
            min_streams = strToInt(node.multiplex_min_streams),
            max_streams = strToInt(node.multiplex_max_streams),
            padding = strToBool(node.multiplex_padding),
            brutal = (node.multiplex_brutal == "1") and {
                enabled = true,
                up_mbps = strToInt(node.multiplex_brutal_up),
                down_mbps = strToInt(node.multiplex_brutal_down),
            } or nil,
        } or nil,
        tls = (node.tls == "1") and {
            enabled = true,
            server_name = node.tls_sni,
            insecure = strToBool(node.tls_insecure),
            alpn = node.tls_alpn,
            min_version = node.tls_min_version,
            max_version = node.tls_max_version,
            cipher_suites = node.tls_cipher_suites,
            certificate_path = node.tls_cert_path,
            ech = (node.tls_ech == "1") and {
                enabled = true,
                config = node.tls_ech_config,
                config_path = node.tls_ech_config_path,
            } or nil,
            utls = not isEmpty(node.tls_utls) and {
                enabled = true,
                fingerprint = node.tls_utls,
            } or nil,
            reality = (node.tls_reality == "1") and {
                enabled = true,
                public_key = node.tls_reality_public_key,
                short_id = node.tls_reality_short_id,
            } or nil,
        } or nil,
        transport = not isEmpty(node.transport) and {
            type = node.transport,
            host = node.http_host or node.httpupgrade_host,
            path = node.http_path or node.ws_path,
            headers = node.ws_host and { Host = node.ws_host } or nil,
            method = node.http_method,
            max_early_data = strToInt(node.websocket_early_data),
            early_data_header_name = node.websocket_early_data_header,
            service_name = node.grpc_servicename,
            idle_timeout = strToTime(node.http_idle_timeout),
            ping_timeout = strToTime(node.http_ping_timeout),
            permit_without_stream = strToBool(node.grpc_permit_without_stream),
        } or nil,
        udp_over_tcp = (node.udp_over_tcp == "1") and {
            enabled = true,
            version = strToInt(node.udp_over_tcp_version),
        } or nil,
        tcp_fast_open = strToBool(node.tcp_fast_open),
        tcp_multi_path = strToBool(node.tcp_multi_path),
        udp_fragment = strToBool(node.udp_fragment),
    }
end

local function get_outbound(cfg)
    if isEmpty(cfg) then return nil end
    if type(cfg) == "table" then
        if contains(cfg, "any-out") then return "any" end
        return map(cfg, function(i) return get_outbound(i) end)
    else
        if cfg == "block-out" or cfg == "direct-out" then return cfg end
        -- cfg names a routing_node section.  The outbound it produces is
        -- tagged with the routing_node's own name, not the underlying
        -- node's: two routing_nodes may share one node while carrying
        -- different bind_interface/detour, so node-name tags would collide.
        local rn = uci:get_all(UCICONFIG, cfg)
        if type(rn) ~= "table" or rn[".type"] ~= UCIROUTINGNODE or isEmpty(rn.node) then
            error(cfg .. " is not a valid routing node, please check your configuration.")
        end
        return "cfg-" .. cfg .. "-out"
    end
end

local function get_resolver(cfg)
    if isEmpty(cfg) then return nil end
    if cfg == "default-dns" or cfg == "system-dns" then return cfg end
    return "cfg-" .. cfg .. "-dns"
end

local function get_ruleset(cfg)
    if isEmpty(cfg) then return nil end
    if type(cfg) ~= "table" then cfg = { cfg } end
    return map(cfg, function(i) return isEmpty(i) and nil or ("cfg-" .. i .. "-rule") end)
end

local function get_first(t)
    local first
    uci:foreach(UCICONFIG, t, function(s) first = s[".name"]; return false end)
    return first
end

-- build config
local config = {}
config.log = {
    disabled = false,
    level = log_level,
    output = hp.RUN_DIR .. "/sing-box-c.log",
    timestamp = true,
}
if not isEmpty(ntp_server) and ntp_server ~= "nil" then
    config.ntp = {
        enabled = true,
        server = ntp_server,
        detour = "direct-out",
        domain_resolver = "default-dns",
    }
end

-- DNS
config.dns = {
    servers = {
        { tag = "default-dns", type = "udp", server = wan_dns,
          detour = "direct-out" },
        { tag = "system-dns", type = "local",
          detour = "direct-out" },
    },
    rules = {},
    strategy = dns_default_strategy,
    disable_cache = strToBool(dns_disable_cache),
    disable_expire = strToBool(dns_disable_cache_expire),
    independent_cache = strToBool(dns_independent_cache),
    client_subnet = dns_client_subnet,
}

if not isEmpty(main_node) then
    local main_dns = {
        tag = "main-dns",
        domain_resolver = { server = "default-dns",
            strategy = (ipv6_support ~= "1") and "ipv4_only" or nil },
        detour = "main-out",
    }
    -- DoH (HTTPS) instead of plain TCP: HTTP/2 multiplexes queries over a
    -- single tunnel connection with builtired reconnection, eliminating the
    -- "read response: EOF" errors when the proxy link's TCP connection is
    -- closed by any layer (anytls idle reaping, server NAT, carrier).
    local dns_parsed = parse_dnsserver(dns_server, dns_server_proto)
    if not dns_parsed then
        -- An unparseable dns_server would emit a server entry without
        -- type/server and fail sing-box check; degrade to the WAN resolver
        -- so the service still starts.
        io.stderr:write("homeproxy: WARNING: dns_server '" .. tostring(dns_server)
            .. "' is not parseable -- falling back to udp://" .. tostring(wan_dns) .. ".\n")
        dns_parsed = parse_dnsserver(wan_dns, "udp")
    end
    for k, v in pairs(dns_parsed or {}) do main_dns[k] = v end
    push(config.dns.servers, main_dns)
    config.dns.final = "main-dns"

    if direct_domain_list and #direct_domain_list > 0 then
        push(config.dns.rules, {
            rule_set = "direct-domain", action = "route",
            server = (routing_mode == "bypass_mainland_china") and "china-dns" or "default-dns",
        })
    end
    if routing_mode == "gfwlist" or (proxy_domain_list and #proxy_domain_list > 0) then
        push(config.dns.rules, {
            rule_set = (routing_mode ~= "gfwlist") and "proxy-domain" or nil,
            query_type = { 64, 65 }, action = "reject",
        })
    end
    if routing_mode == "bypass_mainland_china" then
        local c_dns = {
            tag = "china-dns",
            domain_resolver = { server = "default-dns", strategy = "prefer_ipv6" },
            detour = "direct-out",
        }
        local c_dns_parsed = parse_dnsserver(china_dns_server)
        if not c_dns_parsed then
            io.stderr:write("homeproxy: WARNING: china_dns_server '" .. tostring(china_dns_server)
                .. "' is not parseable -- falling back to udp://" .. tostring(wan_dns) .. ".\n")
            c_dns_parsed = parse_dnsserver(wan_dns, "udp")
        end
        for k, v in pairs(c_dns_parsed or {}) do c_dns[k] = v end
        push(config.dns.servers, c_dns)
        if proxy_domain_list and #proxy_domain_list > 0 then
            push(config.dns.rules, { rule_set = "proxy-domain", action = "route", server = "main-dns" })
        end
        push(config.dns.rules, { rule_set = "geosite-cn", action = "route", server = "china-dns", strategy = "prefer_ipv6" })
        push(config.dns.rules, {
            type = "logical", mode = "and",
            rules = { { rule_set = "geosite-noncn", invert = true }, { rule_set = "geoip-cn" } },
            action = "route", server = "china-dns", strategy = "prefer_ipv6",
        })
    end
elseif not isEmpty(default_outbound) then
    uci:foreach(UCICONFIG, UCIDNSSERVER, function(cfg)
        if cfg.enabled ~= "1" then return end
        local outbound = get_outbound(cfg.outbound)
        if outbound == "direct-out" and isEmpty(self_mark) then outbound = nil end
        push(config.dns.servers, {
            tag = "cfg-" .. cfg[".name"] .. "-dns",
            type = cfg.type, server = cfg.server, server_port = strToInt(cfg.server_port),
            path = cfg.path, headers = cfg.headers,
            tls = cfg.tls_sni and { enabled = true, server_name = cfg.tls_sni } or nil,
            domain_resolver = (cfg.address_resolver or cfg.address_strategy) and {
                server = get_resolver(cfg.address_resolver or dns_default_server),
                strategy = cfg.address_strategy,
            } or nil,
            detour = outbound,
        })
    end)
    uci:foreach(UCICONFIG, UCIDNSRULE, function(cfg)
        if cfg.enabled ~= "1" then return end
        push(config.dns.rules, {
            ip_version = strToInt(cfg.ip_version), query_type = parse_dnsquery(cfg.query_type),
            network = cfg.network, protocol = cfg.protocol,
            domain = cfg.domain, domain_suffix = cfg.domain_suffix,
            domain_keyword = cfg.domain_keyword, domain_regex = cfg.domain_regex,
            port = parse_port(cfg.port), port_range = cfg.port_range,
            source_ip_cidr = cfg.source_ip_cidr, source_ip_is_private = strToBool(cfg.source_ip_is_private),
            ip_cidr = cfg.ip_cidr, ip_is_private = strToBool(cfg.ip_is_private),
            source_port = parse_port(cfg.source_port), source_port_range = cfg.source_port_range,
            process_name = cfg.process_name, process_path = cfg.process_path,
            process_path_regex = cfg.process_path_regex, user = cfg.user,
            rule_set = get_ruleset(cfg.rule_set),
            rule_set_ip_cidr_match_source = strToBool(cfg.rule_set_ip_cidr_match_source),
            rule_set_ip_cidr_accept_empty = strToBool(cfg.rule_set_ip_cidr_accept_empty),
            invert = strToBool(cfg.invert), outbound = get_outbound(cfg.outbound),
            action = cfg.action, server = get_resolver(cfg.server), strategy = cfg.domain_strategy,
            disable_cache = strToBool(cfg.dns_disable_cache), rewrite_ttl = strToInt(cfg.rewrite_ttl),
            client_subnet = cfg.client_subnet, method = cfg.reject_method,
            no_drop = strToBool(cfg.reject_no_drop), rcode = cfg.predefined_rcode,
            answer = cfg.predefined_answer, ns = cfg.predefined_ns, extra = cfg.predefined_extra,
        })
    end)
    config.dns.final = get_resolver(dns_default_server)
end

-- Inbounds
config.inbounds = {
    { type = "direct", tag = "dns-in", listen = "::", listen_port = tonumber(dns_port) },
    { type = "mixed", tag = "mixed-in", listen = "::", listen_port = tonumber(mixed_port),
      udp_timeout = strToTime(udp_timeout), set_system_proxy = false },
}
if proxy_mode:find("redirect") then
    push(config.inbounds, { type = "redirect", tag = "redirect-in", listen = "::",
        listen_port = tonumber(redirect_port) })
end
if tproxy_port then
    -- "tcp,udp": in a tproxy-only mode (no redirect inbound) the firewall
    -- TPROXYs TCP here as well; in redirect_tproxy TCP goes to redirect-in
    -- and the tcp side of this listener simply stays unused.
    push(config.inbounds, { type = "tproxy", tag = "tproxy-in", listen = "::",
        listen_port = tonumber(tproxy_port), network = { "tcp", "udp" },
        udp_timeout = strToTime(udp_timeout) })
end
if proxy_mode:find("tun") then
    push(config.inbounds, { type = "tun", tag = "tun-in", interface_name = tun_name,
        address = (ipv6_support == "1") and { tun_addr4, tun_addr6 } or { tun_addr4 },
        mtu = strToInt(tun_mtu), auto_route = false,
        endpoint_independent_nat = strToBool(endpoint_independent_nat),
        udp_timeout = strToTime(udp_timeout), stack = tcpip_stack })
end

-- Outbounds
config.endpoints = {}
config.outbounds = {
    { type = "direct", tag = "direct-out", routing_mark = strToInt(self_mark) },
    { type = "block", tag = "block-out" },
}
local function add_endpoint(node_cfg, tag)
    local ep = generate_endpoint(node_cfg)
    if ep and tag then ep.tag = tag end
    if ep then push(config.endpoints, ep) end
end
local function add_outbound(node_cfg, tag)
    local ob = generate_outbound(node_cfg)
    if ob and tag then ob.tag = tag end
    if ob then push(config.outbounds, ob) end
end

-- urltest member lists name node SECTIONS; a member that no longer exists
-- would emit a dangling cfg-*-out reference that sing-box check rejects.
local function filter_node_list(list, owner)
    return filter(list or {}, function(name)
        local sec = uci:get_all(UCICONFIG, name)
        if not sec or sec[".type"] ~= UCINODE then
            io.stderr:write("homeproxy: WARNING: " .. tostring(owner)
                .. " references missing node " .. tostring(name) .. " -- dropped.\n")
            return false
        end
        return true
    end)
end

if not isEmpty(main_node) then
    local urltest_nodes = {}
    if main_node == "urltest" then
        local nodes = uget(UCIMAIN, "main_urltest_nodes") or {}
        if type(nodes) ~= "table" then nodes = { nodes } end
        nodes = filter_node_list(nodes, "main_urltest_nodes")
        -- Guard against empty urltest node list (H16): clean() drops an empty
        -- outbounds array, producing a config sing-box rejects ("outbounds
        -- required").  Fall back to direct-out so the config remains valid.
        if #nodes == 0 then
            io.stderr:write("homeproxy: WARNING: main_urltest_nodes is empty -- falling back to direct outbound.\n")
            push(config.outbounds, { type = "direct", tag = "main-out",
                routing_mark = strToInt(self_mark) })
        else
            local interval = uget(UCIMAIN, "main_urltest_interval")
            local interval_n = strToInt(interval)
            push(config.outbounds, {
                type = "urltest", tag = "main-out",
                outbounds = map(nodes, function(k) return "cfg-" .. k .. "-out" end),
                interval = strToTime(interval), tolerance = strToInt(uget(UCIMAIN, "main_urltest_tolerance")),
                idle_timeout = (interval_n and interval_n > 1800)
                    and (interval_n * 2 .. "s") or nil,
            })
        end
        urltest_nodes = nodes
    else
        local ncfg = uci:get_all(UCICONFIG, main_node) or {}
        if ncfg.type == "wireguard" then add_endpoint(ncfg, "main-out")
        else add_outbound(ncfg, "main-out") end
    end

    if main_udp_node == "urltest" then
        local nodes = uget(UCIMAIN, "main_udp_urltest_nodes") or {}
        if type(nodes) ~= "table" then nodes = { nodes } end
        nodes = filter_node_list(nodes, "main_udp_urltest_nodes")
        if #nodes == 0 then
            -- Same guard as main-out: an empty urltest outbounds array is
            -- cleaned away, leaving a broken reference from the udp rule.
            io.stderr:write("homeproxy: WARNING: main_udp_urltest_nodes is empty -- UDP falls back to direct.\n")
            push(config.outbounds, { type = "direct", tag = "main-udp-out",
                routing_mark = strToInt(self_mark) })
            nodes = nil
        end
        local interval = uget(UCIMAIN, "main_udp_urltest_interval")
        local interval_n = strToInt(interval)
        if nodes then
        push(config.outbounds, {
            type = "urltest", tag = "main-udp-out",
            outbounds = map(nodes, function(k) return "cfg-" .. k .. "-out" end),
            interval = strToTime(interval), tolerance = strToInt(uget(UCIMAIN, "main_udp_urltest_tolerance")),
            idle_timeout = (interval_n and interval_n > 1800)
                and (interval_n * 2 .. "s") or nil,
        })
            for _, l in ipairs(filter(nodes, function(l) return not contains(urltest_nodes, l) end)) do
                urltest_nodes[#urltest_nodes + 1] = l
            end
        end
    elseif dedicated_udp_node then
        local ncfg = uci:get_all(UCICONFIG, main_udp_node) or {}
        if ncfg.type == "wireguard" then add_endpoint(ncfg, "main-udp-out")
        else add_outbound(ncfg, "main-udp-out") end
    end

    for _, i in ipairs(urltest_nodes) do
        local ncfg = uci:get_all(UCICONFIG, i) or {}
        if ncfg.type == "wireguard" then add_endpoint(ncfg, "cfg-" .. i .. "-out")
        else add_outbound(ncfg, "cfg-" .. i .. "-out") end
    end
elseif not isEmpty(default_outbound) then
    local urltest_nodes, routing_nodes = {}, {}
    uci:foreach(UCICONFIG, UCIROUTINGNODE, function(cfg)
        if cfg.enabled ~= "1" then return end
        if cfg.node == "urltest" then
            local ut_nodes = cfg.urltest_nodes
            if type(ut_nodes) ~= "table" then ut_nodes = ut_nodes and { ut_nodes } or {} end
            ut_nodes = filter_node_list(ut_nodes, "routing_node " .. tostring(cfg[".name"]))
            if #ut_nodes == 0 then
                io.stderr:write("homeproxy: WARNING: routing_node " .. tostring(cfg[".name"])
                    .. " has an empty urltest_nodes list -- skipped.\n")
                return
            end
            push(config.outbounds, {
                type = "urltest", tag = "cfg-" .. cfg[".name"] .. "-out",
                outbounds = map(ut_nodes, function(k) return "cfg-" .. k .. "-out" end),
                url = cfg.urltest_url, interval = strToTime(cfg.urltest_interval),
                tolerance = strToInt(cfg.urltest_tolerance),
                idle_timeout = strToTime(cfg.urltest_idle_timeout),
                interrupt_exist_connections = strToBool(cfg.urltest_interrupt_exist_connections),
            })
            for _, l in ipairs(filter(ut_nodes, function(l) return not contains(urltest_nodes, l) end)) do
                urltest_nodes[#urltest_nodes + 1] = l
            end
        else
            -- A missing node must NOT fall through: add_* would push nothing
            -- and the detour/bind_interface edits below would hit whatever
            -- outbound happens to be last in the array.
            -- cfg.node nil -> get_all returns the whole package (truthy);
            -- a nonexistent/non-node name yields nil or a foreign section.
            local ob = not isEmpty(cfg.node) and uci:get_all(UCICONFIG, cfg.node) or nil
            if type(ob) ~= "table" or ob[".type"] ~= "node" then
                io.stderr:write("homeproxy: WARNING: routing_node " .. tostring(cfg[".name"])
                    .. " references missing node " .. tostring(cfg.node) .. " -- skipped.\n")
                return
            end
            -- Tag with the routing_node's own name so two routing_nodes
            -- sharing one node still emit distinct entries (get_outbound
            -- resolves references the same way).
            local rn_tag = "cfg-" .. cfg[".name"] .. "-out"
            if ob.type == "wireguard" then
                local n = #config.endpoints
                add_endpoint(ob, rn_tag)
                if #config.endpoints == n then
                    io.stderr:write("homeproxy: WARNING: routing_node " .. tostring(cfg[".name"])
                        .. " node " .. tostring(cfg.node) .. " generated no endpoint -- skipped.\n")
                    return
                end
                local last = config.endpoints[#config.endpoints]
                last.bind_interface = cfg.bind_interface
                last.detour = get_outbound(cfg.outbound)
                if cfg.domain_resolver then
                    last.domain_resolver = { server = get_resolver(cfg.domain_resolver), strategy = cfg.domain_strategy }
                end
            else
                local n = #config.outbounds
                add_outbound(ob, rn_tag)
                if #config.outbounds == n then
                    io.stderr:write("homeproxy: WARNING: routing_node " .. tostring(cfg[".name"])
                        .. " node " .. tostring(cfg.node) .. " generated no outbound -- skipped.\n")
                    return
                end
                local last = config.outbounds[#config.outbounds]
                last.bind_interface = cfg.bind_interface
                last.detour = get_outbound(cfg.outbound)
                if cfg.domain_resolver then
                    last.domain_resolver = { server = get_resolver(cfg.domain_resolver), strategy = cfg.domain_strategy }
                end
            end
            -- Track emitted tags: a node used by a routing_node is still
            -- materialized under its own cfg-<node>-out tag when a urltest
            -- group references it.
            routing_nodes[#routing_nodes + 1] = rn_tag
        end
    end)
    for _, i in ipairs(filter(urltest_nodes, function(l) return not contains(routing_nodes, "cfg-" .. l .. "-out") end)) do
        local ncfg = uci:get_all(UCICONFIG, i) or {}
        if ncfg.type == "wireguard" then add_endpoint(ncfg) else add_outbound(ncfg) end
    end
end

-- Routing rules
config.route = {
    rules = { { inbound = "dns-in", action = "hijack-dns" }, { action = "sniff" } },
    rule_set = {},
    auto_detect_interface = isEmpty(default_interface) and true or nil,
    default_interface = default_interface,
}

if not isEmpty(main_node) then
    config.route.default_domain_resolver = {
        action = "route",
        server = (routing_mode == "bypass_mainland_china") and "china-dns" or "default-dns",
        strategy = (ipv6_support ~= "1") and "prefer_ipv4" or nil,
    }
    if direct_domain_list and #direct_domain_list > 0 then
        push(config.route.rules, { rule_set = "direct-domain", action = "route", outbound = "direct-out" })
    end
    if dedicated_udp_node then
        push(config.route.rules, { network = "udp", action = "route", outbound = "main-udp-out" })
    end
    config.route.final = "main-out"

    if direct_domain_list and #direct_domain_list > 0 then
        push(config.route.rule_set, { type = "inline", tag = "direct-domain",
            rules = { { domain_suffix = direct_domain_list } } })
    end
    if proxy_domain_list and #proxy_domain_list > 0 then
        push(config.route.rule_set, { type = "inline", tag = "proxy-domain",
            rules = { { domain_suffix = proxy_domain_list } } })
    end
    if routing_mode == "bypass_mainland_china" then
        -- Prefer pre-downloaded local rule sets: a remote fetch goes through
        -- the proxy node (download_detour=main-out), whose REALITY/TLS
        -- handshake fails while the RTC-less clock is still stale at boot --
        -- a chicken-and-egg deadlock that FATALs sing-box at init. A file
        -- passing the 3-byte "SRS" magic check is used as type=local; absent
        -- or invalid files fall back to the upstream remote source.
        for _, rs in ipairs({
            { tag = "geoip-cn",
              url = "https://fastly.jsdelivr.net/gh/1715173329/IPCIDR-CHINA@rule-set/cn.srs" },
            { tag = "geosite-cn",
              url = "https://fastly.jsdelivr.net/gh/1715173329/sing-geosite@rule-set-unstable/geosite-geolocation-cn.srs" },
            { tag = "geosite-noncn",
              url = "https://fastly.jsdelivr.net/gh/1715173329/sing-geosite@rule-set-unstable/geosite-geolocation-!cn.srs" },
        }) do
            local rs_path = hp.HP_DIR .. "/ruleset/" .. rs.tag .. ".srs"
            local rs_ok
            local rf = io.open(rs_path, "rb")
            if rf then
                rs_ok = (rf:read(3) == "SRS")
                rf:close()
            end
            if rs_ok then
                push(config.route.rule_set, { type = "local", tag = rs.tag,
                    format = "binary", path = rs_path })
            else
                push(config.route.rule_set, { type = "remote", tag = rs.tag,
                    format = "binary", url = rs.url, download_detour = "main-out" })
            end
        end
    end
elseif not isEmpty(default_outbound) then
    config.route.default_domain_resolver = { action = "resolve", server = get_resolver(default_outbound_dns) }
    if domain_strategy then
        push(config.route.rules, { action = "resolve", strategy = domain_strategy })
    end
    uci:foreach(UCICONFIG, UCIROUTINGRULE, function(cfg)
        if cfg.enabled ~= "1" then return end
        push(config.route.rules, {
            ip_version = strToInt(cfg.ip_version), protocol = cfg.protocol, network = cfg.network,
            domain = cfg.domain, domain_suffix = cfg.domain_suffix,
            domain_keyword = cfg.domain_keyword, domain_regex = cfg.domain_regex,
            source_ip_cidr = cfg.source_ip_cidr, source_ip_is_private = strToBool(cfg.source_ip_is_private),
            ip_cidr = cfg.ip_cidr, ip_is_private = strToBool(cfg.ip_is_private),
            source_port = parse_port(cfg.source_port), source_port_range = cfg.source_port_range,
            port = parse_port(cfg.port), port_range = cfg.port_range,
            process_name = cfg.process_name, process_path = cfg.process_path,
            process_path_regex = cfg.process_path_regex, user = cfg.user,
            rule_set = get_ruleset(cfg.rule_set),
            rule_set_ip_cidr_match_source = strToBool(cfg.rule_set_ip_cidr_match_source),
            invert = strToBool(cfg.invert), action = cfg.action, outbound = get_outbound(cfg.outbound),
            override_address = cfg.override_address, override_port = strToInt(cfg.override_port),
            udp_disable_domain_unmapping = strToBool(cfg.udp_disable_domain_unmapping),
            udp_connect = strToBool(cfg.udp_connect), udp_timeout = strToTime(cfg.udp_timeout),
            tls_fragment = strToBool(cfg.tls_fragment),
            tls_fragment_fallback_delay = strToTime(cfg.tls_fragment_fallback_delay),
            tls_record_fragment = strToBool(cfg.tls_record_fragment),
        })
    end)
    config.route.final = get_outbound(default_outbound)
    uci:foreach(UCICONFIG, UCIRULESET, function(cfg)
        if cfg.enabled ~= "1" then return end
        push(config.route.rule_set, {
            type = cfg.type, tag = "cfg-" .. cfg[".name"] .. "-rule", format = cfg.format,
            path = cfg.path, url = cfg.url, download_detour = get_outbound(cfg.outbound),
            update_interval = cfg.update_interval,
        })
    end)
else
    -- Neither a main node nor a default_outbound: sing-box still requires a
    -- route.final, so fall back to direct rather than emitting broken JSON.
    config.route.final = "direct-out"
end

-- Materialize an outbound for EVERY node (cfg-<sect>-out) so the Clash API
-- can run a per-node reachability/delay test from the web UI. Outbounds not
-- referenced by any route are inert (no routing/port-forward impact). The
-- active node keeps its "main-out" alias; this adds the cfg-<sect>-out form
-- the UI keys on. Gated by HP_MATERIALIZE_ALL_NODES (default on; init.d
-- retries with =0 if a bad unused node fails sing-box check, so a malformed
-- node never blocks startup -- ping-all is just unavailable for that run).
if os.getenv("HP_MATERIALIZE_ALL_NODES") ~= "0" then
    local function has_outbound(tag)
        for _, o in ipairs(config.outbounds) do if o.tag == tag then return true end end
        for _, e in ipairs(config.endpoints) do if e.tag == tag then return true end end
        return false
    end
    uci:foreach(UCICONFIG, UCINODE, function(cfg)
        local tag = "cfg-" .. cfg[".name"] .. "-out"
        if has_outbound(tag) then return end
        -- Group/pseudo types have no single-server outbound form; skipping
        -- them keeps one stray node from failing `sing-box check`.
        if cfg.type == "urltest" or cfg.type == "selector" or cfg.type == "direct"
            or cfg.type == "block" or cfg.type == "dns" then return end
        if cfg.type == "wireguard" then add_endpoint(cfg, tag)
        else add_outbound(cfg, tag) end
    end)
end

-- Clash API (loopback only, no secret) so the web UI can run per-node
-- delay tests via GET /proxies/<tag>/delay. Used by the ping_nodes endpoint.
config.experimental = {
    clash_api = { external_controller = "127.0.0.1:19290" },
}
if routing_mode == "bypass_mainland_china" or routing_mode == "custom" then
    config.experimental.cache_file = {
        enabled = true, path = hp.RUN_DIR .. "/cache.db",
        store_rdrc = strToBool(cache_file_store_rdrc),
        rdrc_timeout = strToTime(cache_file_rdrc_timeout),
    }
end

hp.mkdir_p(hp.RUN_DIR)
if not hp.writefile(hp.RUN_DIR .. "/sing-box-c.json", hp.encode_json(config)) then
    io.stderr:write("homeproxy: ERROR: failed to write " .. hp.RUN_DIR .. "/sing-box-c.json\n")
    os.exit(1)
end
