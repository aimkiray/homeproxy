#!/usr/bin/lua
-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy config migration / defaults (Lua port, simplified for MiWiFi).
-- Idempotent: ensures sane defaults and removes deprecated options. Safe to
-- run repeatedly. Expects the shipped default /etc/config/homeproxy baseline.

package.path = (os.getenv("HP_LUAPATH") or "/usr/lib/homeproxy") .. "/?.lua;" .. package.path

local hp  = require("homeproxy")
local uci = require("uci").cursor(os.getenv("HP_CONFDIR") or "/etc/config")

local CFG = "homeproxy"
uci:load(CFG)

local function isEmpty(v) return hp.isEmpty(v) end
local function changed() return uci:changes(CFG) ~= nil and next(uci:changes(CFG)) ~= nil end

-- Migration warnings go to stderr (init.d/CLI redirect it to homeproxy.log)
-- and to homeproxy.log directly so they are observable either way.
local function logwarn(msg)
    io.stderr:write("homeproxy: " .. msg .. "\n")
    hp.log(msg, "MIGRATE")
end

-- Pre-meow (sing-box era) marker: the old migrator force-ensured
-- infra.tproxy_port and the tun_* set on every config it touched, so their
-- presence proves config.proxy_mode still uses the OLD vocabulary in which
-- "tproxy" meant TCP+UDP TPROXY. Post-migration "tproxy" (UDP-only arm, spec
-- 3.4) is a legal new value and must survive re-runs -- hence this gate.
local function has_opt(sec, opt) return uci:get(CFG, sec, opt) ~= nil end
local legacy_infra =
    has_opt("infra", "tproxy_port") or has_opt("infra", "tun_name")
    or has_opt("infra", "tun_addr4") or has_opt("infra", "tun_addr6")
    or has_opt("infra", "tun_mtu") or has_opt("infra", "tun_table")
    or has_opt("infra", "tun_mark")

-- ensure a scalar default on an existing named section
local function ensure(sec, opt, default)
    if isEmpty(uci:get(CFG, sec, opt)) then
        uci:set(CFG, sec, opt, default)
    end
end

-- ensure infra defaults
if uci:get_all(CFG, "infra") then
    ensure("infra", "mixed_port", "5330")
    ensure("infra", "redirect_port", "5331")
    ensure("infra", "dns_port", "5333")
    ensure("infra", "v6_port", "5334")
    ensure("infra", "self_mark", "100")
    ensure("infra", "tproxy_mark", "101")
    ensure("infra", "table_mark", "100")
    ensure("infra", "ntp_server", "nil")
    -- udp_timeout feeds listeners[].udp-timeout (integer seconds). Accept
    -- the same set the generator's secs() accepts: bare seconds or an
    -- Ns/Nm/Nh/Nd suffix, with optional surrounding whitespace; normalize
    -- to integer seconds 1..86400.
    ensure("infra", "udp_timeout", "60")
    do
        local raw = uci:get(CFG, "infra", "udp_timeout")
        local secs
        if type(raw) == "string" then
            local n, unit = raw:match("^%s*(%d+)%s*([smhd]?)%s*$")
            if n then
                secs = tonumber(n)
                if unit == "m" then secs = secs * 60
                elseif unit == "h" then secs = secs * 3600
                elseif unit == "d" then secs = secs * 86400 end
            end
        end
        if not secs or secs < 1 or secs > 86400 then
            logwarn("infra.udp_timeout='" .. tostring(raw) .. "' is invalid; reset to 60")
            uci:set(CFG, "infra", "udp_timeout", "60")
        elseif tostring(secs) ~= raw then
            uci:set(CFG, "infra", "udp_timeout", tostring(secs))
        end
    end

    -- meow: infra.tproxy_port is removed -- the single tproxy listener serves
    -- TCP REDIRECT and UDP TPROXY on redirect_port (spec 3.3).
    local tp = uci:get(CFG, "infra", "tproxy_port")
    if tp ~= nil then
        local rp = uci:get(CFG, "infra", "redirect_port")
        if type(rp) ~= "string" or rp == "" then rp = "5331" end
        if not isEmpty(tp) and tp ~= rp then
            logwarn("infra.tproxy_port=" .. tostring(tp) ..
                " discarded; UDP TPROXY now shares redirect_port (" .. tostring(rp) .. ")")
        end
        uci:delete(CFG, "infra", "tproxy_port")
    end

    -- meow: the TUN arm is gone (spec 3.5). Record the old tun_name once for
    -- stop-time device cleanup (init.d/firewall.sh consume + delete the
    -- file), then drop every tun_* option.
    local tun_opts = { "tun_name", "tun_addr4", "tun_addr6", "tun_mtu", "tun_table", "tun_mark" }
    local saw_tun = false
    for _, o in ipairs(tun_opts) do
        if uci:get(CFG, "infra", o) ~= nil then saw_tun = true break end
    end
    if saw_tun then
        local tfile = hp.RUN_DIR .. "/legacy-tun-name"
        if not hp.readfile(tfile) then
            local tname = uci:get(CFG, "infra", "tun_name")
            if isEmpty(tname) then tname = "singtun0" end
            -- Two space-separated fields: name + tun_mark. The cleanup
            -- readers (init.d/firewall.sh) need the real fwmark to drain
            -- the old tun ip-rules; a missing second field (file written
            -- by an older build) is read as the historical default 102.
            local tmark = uci:get(CFG, "infra", "tun_mark")
            if isEmpty(tmark) then tmark = "102" end
            hp.mkdir_p(hp.RUN_DIR)
            hp.writefile(tfile, tname .. " " .. tmark .. "\n")
        end
        for _, o in ipairs(tun_opts) do uci:delete(CFG, "infra", o) end
        logwarn("infra.tun_* options removed (TUN is no longer supported); " ..
            "legacy tun name saved to " .. tfile)
    end

    -- deprecated
    if not isEmpty(uci:get(CFG, "infra", "tun_gso")) then uci:delete(CFG, "infra", "tun_gso") end
    if not isEmpty(uci:get(CFG, "infra", "china_dns_port")) then uci:delete(CFG, "infra", "china_dns_port") end
    -- sniff_override never had an effect in this port (no consumer).
    if not isEmpty(uci:get(CFG, "infra", "sniff_override")) then uci:delete(CFG, "infra", "sniff_override") end
end
if not isEmpty(uci:get(CFG, "routing", "sniff_override")) then
    uci:delete(CFG, "routing", "sniff_override")
end

-- ensure main config defaults
if uci:get_all(CFG, "config") then
    ensure("config", "routing_mode", "bypass_mainland_china")
    ensure("config", "proxy_mode", "redirect_tproxy")
    ensure("config", "ipv6_support", "1")
    ensure("config", "log_level", "warn")
    -- spec 3.4 rewrite table (idempotent): the TUN modes are gone, so they
    -- and any unknown value fall back to redirect_tproxy, the strongest
    -- surviving combination. Old "tproxy" (TCP+UDP TPROXY) also maps there,
    -- but only while pre-meow infra markers still exist -- a "tproxy" set
    -- after migration means the NEW UDP-only arm and must not be touched.
    local pm = uci:get(CFG, "config", "proxy_mode")
    if pm == "tproxy" and legacy_infra then
        uci:set(CFG, "config", "proxy_mode", "redirect_tproxy")
        logwarn("config.proxy_mode=tproxy (legacy TCP+UDP TPROXY meaning) " ..
            "rewritten to redirect_tproxy")
    elseif pm ~= "redirect" and pm ~= "redirect_tproxy" and pm ~= "tproxy" then
        uci:set(CFG, "config", "proxy_mode", "redirect_tproxy")
        logwarn("config.proxy_mode=" .. tostring(pm) ..
            " is not supported (TUN modes removed); rewritten to redirect_tproxy")
    end
    if uci:get(CFG, "config", "routing_port") == "all" then
        uci:delete(CFG, "config", "routing_port")
    end
    -- china_dns_server must be a single server
    local cds = uci:get(CFG, "config", "china_dns_server")
    if type(cds) == "table" then
        uci:set(CFG, "config", "china_dns_server", cds[1])
    elseif type(cds) == "string" and cds:find(",") then
        uci:set(CFG, "config", "china_dns_server", cds:match("^([^,]+)"))
    elseif cds == "wan_114" then
        uci:set(CFG, "config", "china_dns_server", "114.114.114.114")
    end
end

-- server defaults
uci:foreach(CFG, "server", function(s)
    if isEmpty(uci:get(CFG, s[".name"], "log_level")) then
        uci:set(CFG, s[".name"], "log_level", "warn")
    end
    if not isEmpty(s.sniff_override) then uci:delete(CFG, s[".name"], "sniff_override") end
    if not isEmpty(s.domain_strategy) then uci:delete(CFG, s[".name"], "domain_strategy") end
end)

-- node deprecated options
uci:foreach(CFG, "node", function(s)
    if not isEmpty(s.tls_ech_tls_disable_drs) then uci:delete(CFG, s[".name"], "tls_ech_tls_disable_drs") end
    if not isEmpty(s.tls_ech_enable_pqss) then uci:delete(CFG, s[".name"], "tls_ech_enable_pqss") end
    if not isEmpty(s.wireguard_gso) then uci:delete(CFG, s[".name"], "wireguard_gso") end
end)

-- Normalize subscription node section names to md5(grouphash|label) (F6).
-- Older builds hashed the bare label, which collides across subscriptions;
-- an even older scheme embedded a NUL that the md5 pipeline truncated.
-- Rename sections in place and repoint every reference so the user's chosen
-- main node survives the upgrade.
do
    local renames = {}
    uci:foreach(CFG, "node", function(s)
        local gh, lbl = s.grouphash, s.label
        if isEmpty(gh) or isEmpty(lbl) then return end
        local want = hp.md5(tostring(gh) .. "|" .. tostring(lbl))
        if not want or s[".name"] == want then return end
        if uci:get_all(CFG, want) then return end  -- target exists; leave it
        renames[s[".name"]] = want
    end)
    if next(renames) ~= nil then
        for old, new in pairs(renames) do
            local sec = uci:get_all(CFG, old)
            if sec then
                uci:set(CFG, new, "node")
                for k, v in pairs(sec) do
                    if k:sub(1, 1) ~= "." then uci:set(CFG, new, k, v) end
                end
                uci:delete(CFG, old)
            end
        end
        for _, opt in ipairs({ "main_node", "main_udp_node" }) do
            local v = uci:get(CFG, "config", opt)
            if v and renames[v] then uci:set(CFG, "config", opt, renames[v]) end
        end
        for _, opt in ipairs({ "main_urltest_nodes", "main_udp_urltest_nodes" }) do
            local l = uci:get(CFG, "config", opt)
            if type(l) == "table" then
                local ch = false
                for i, v in ipairs(l) do
                    if renames[v] then l[i] = renames[v]; ch = true end
                end
                if ch then uci:set(CFG, "config", opt, l) end
            end
        end
        uci:foreach(CFG, "routing_node", function(s)
            if s.node and renames[s.node] then
                uci:set(CFG, s[".name"], "node", renames[s.node])
            end
            local l = s.urltest_nodes
            if type(l) == "table" then
                local ch = false
                for i, v in ipairs(l) do
                    if renames[v] then l[i] = renames[v]; ch = true end
                end
                if ch then uci:set(CFG, s[".name"], "urltest_nodes", l) end
            end
        end)
        -- Repoint one option on one section: scalar values are rewritten
        -- when they name a renamed node; list values are rewritten per
        -- element (uci:set with a table rewrites the whole list).
        local function repoint(sec, opt, v)
            if type(v) == "table" then
                local ch = false
                for i, m in ipairs(v) do
                    if renames[m] then v[i] = renames[m]; ch = true end
                end
                if ch then uci:set(CFG, sec, opt, v) end
            elseif type(v) == "string" and renames[v] then
                uci:set(CFG, sec, opt, renames[v])
            end
        end
        -- Group-type node sections carry their member lists directly
        -- (generate_client emit_node_group reads urltest_nodes /
        -- selector_nodes off the node section itself).
        uci:foreach(CFG, "node", function(s)
            repoint(s[".name"], "urltest_nodes", s.urltest_nodes)
            repoint(s[".name"], "selector_nodes", s.selector_nodes)
        end)
        -- routing_node group members may also live in selector_nodes
        -- (generator: cfg.urltest_nodes or cfg.selector_nodes), and its
        -- outbound names a node for dialer detour (generate_client.lua:1042).
        uci:foreach(CFG, "routing_node", function(s)
            repoint(s[".name"], "selector_nodes", s.selector_nodes)
            repoint(s[".name"], "outbound", s.outbound)
        end)
        -- Scalar outbound references that resolve_outbound() maps through
        -- node section names.
        for _, st in ipairs({ "routing_rule", "dns_server", "dns_rule", "ruleset" }) do
            uci:foreach(CFG, st, function(s)
                repoint(s[".name"], "outbound", s.outbound)
            end)
        end
        repoint("routing", "default_outbound",
            uci:get(CFG, "routing", "default_outbound"))
    end
end

-- experimental section was removed. The old sections are anonymous
-- (`config experimental` -> cfgXXXX names), which uci:get_all("experimental")
-- cannot reach -- it only matches a section literally NAMED "experimental".
-- Iterate by type and delete every match; collect names first because
-- deleting inside uci:foreach mutates the list being walked.
do
    local doomed = {}
    uci:foreach(CFG, "experimental", function(s) doomed[#doomed + 1] = s[".name"] end)
    for _, n in ipairs(doomed) do uci:delete(CFG, n) end
end

if changed() then
    if not uci:commit(CFG) then
        io.stderr:write("homeproxy: migration commit failed\n")
        os.exit(1)
    end
end
