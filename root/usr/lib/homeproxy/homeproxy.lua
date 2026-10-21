-- SPDX-License-Identifier: GPL-2.0-only
-- HomeProxy helper library (Lua port of the ucode `homeproxy` module).
-- Designed for OpenWrt/MiWiFi devices without ucode: pure Lua 5.1 +
-- luci.json + the uci Lua binding. No external shell helpers required for
-- core logic (base64/md5/URL parsing implemented in Lua).

local _M = {}

_M.HP_DIR  = "/etc/homeproxy"
_M.RUN_DIR = "/var/run/homeproxy"

-- Seed math.random so temp-file names are not predictable (H3).
-- Lua 5.1's default srand is fixed, producing the same sequence every run.
math.randomseed(os.time())

-- ---------------------------------------------------------------------------
-- Filesystem helpers
-- ---------------------------------------------------------------------------
function _M.readfile(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end

function _M.writefile(path, content)
    local f = io.open(path, "wb")
    if not f then return false end
    local ok = f:write(content or "")
    if not ok then f:close(); return false end
    ok = f:close()
    if not ok then return false end
    return true
end

function _M.appendfile(path, content)
    local f = io.open(path, "ab")
    if not f then return false end
    local ok = f:write(content or "")
    if not ok then f:close(); return false end
    ok = f:close()
    if not ok then return false end
    return true
end

function _M.mkdir_p(path)
    os.execute(string.format("mkdir -p %s", _M.shellQuote(path)))
end

-- ---------------------------------------------------------------------------
-- String helpers
-- ---------------------------------------------------------------------------
function _M.trim(s)
    if type(s) ~= "string" then return nil end
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

function _M.isEmpty(res)
    if res == nil or res == false then return true end
    if res == "nil" then return true end
    if res == "" then return true end
    if type(res) == "table" then return next(res) == nil end
    return false
end

function _M.shellQuote(s)
    s = tostring(s or "")
    return "'" .. s:gsub("'", "'\\''") .. "'"
end

function _M.strToBool(str)
    return (str == "1") or nil
end

function _M.strToInt(str)
    if _M.isEmpty(str) then return nil end
    local n = tonumber(tostring(str))
    -- Integer only: a float like "80.5" would otherwise be emitted verbatim
    -- into port/mtu fields that sing-box requires to be integers.
    if not n or n ~= math.floor(n) then return nil end
    return n
end

-- The upstream ucode implementation appends "s" so numeric seconds become
-- sing-box duration strings ("300" -> "300s").  Check if the input already
-- has a valid sing-box duration unit to avoid double-suffixing (M15).
-- sing-box accepts: <number>s, <number>m, <number>h, <number>d, <number>ms
function _M.strToTime(str)
    if _M.isEmpty(str) then return nil end
    local s = tostring(str)
    -- Already has a valid sing-box duration suffix?  Go-style durations can
    -- be composite ("1h30m", "5m3ms").  Lua patterns cannot repeat a capture,
    -- so consume "<num><unit>" pieces from the front; "ms" must be tried
    -- first so its trailing "s" is not taken as a seconds unit.
    local rest = s
    while rest ~= "" do
        local n = rest:gsub("^%d+%.?%d*ms", "", 1):gsub("^%d+%.?%d*[smhd]", "", 1)
        if n == rest then break end
        rest = n
    end
    if rest == "" then return s end
    -- Bare value must be a (possibly fractional) number of seconds; appending
    -- "s" to anything else would produce an invalid duration that only fails
    -- deep inside sing-box check.
    if not s:match("^%d+%.?%d*$") then return nil end
    return s .. "s"
end

function _M.split(s, pat)
    if not s then return {} end
    pat = pat or "%s"
    local t = {}
    local first = 1
    local a, b = s:find(pat, first)
    while a do
        t[#t + 1] = s:sub(first, a - 1)
        first = b + 1
        a, b = s:find(pat, first)
    end
    t[#t + 1] = s:sub(first)
    return t
end

-- ---------------------------------------------------------------------------
-- Validation (replaces /sbin/validate_data which may be absent on MiWiFi)
-- ---------------------------------------------------------------------------
local function is_ip4(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    for _, v in ipairs({a, b, c, d}) do
        local n = tonumber(v)
        if not n or n < 0 or n > 255 then return false end
    end
    return true
end

local function is_ip6(s)
    if s == "" then return false end
    if s:find("[^0-9a-fA-F:.]") then return false end
    if s:sub(1, 1) == ":" and s:sub(2, 2) ~= ":" then return false end
    if s:sub(-1, -1) == ":" and s:sub(-2, -2) ~= ":" then return false end
    if s:find(":::", 1, true) then return false end
    local _, doubles = s:gsub("::", "")
    if doubles > 1 then return false end
    local seen_double = doubles > 0
    local groups = 0
    -- IPv4-embedded tail ("::ffff:192.0.2.1"): a dotted-quad is only valid
    -- as the last group and counts as two 16-bit groups.
    if s:find(".", 1, true) then
        local v4 = s:match(":(%d+%.%d+%.%d+%.%d+)$")
        if not v4 or not is_ip4(v4) then return false end
        s = s:sub(1, #s - #v4 - 1)
        groups = 2
    end
    for part in s:gmatch("[^:]+") do
        if #part > 4 then return false end
        groups = groups + 1
    end
    -- A double colon represents at least one omitted group.
    if (seen_double and groups > 7) or (not seen_double and groups ~= 8) then return false end
    return true
end

local function is_hostname(s)
    if s == "" or #s > 253 then return false end
    -- Reject empty labels: leading/trailing dot or "a..b" (gmatch("[^.]+")
    -- would silently skip them).
    if s:sub(1, 1) == "." or s:sub(-1) == "." or s:find("..", 1, true) then
        return false
    end
    -- Single-label hostname (no dots): same label rules as multi-label
    -- (RFC 1123 permits interior hyphens, e.g. "my-router").
    if not s:match("%.") then
        if #s > 63 then return false end
        return s:match("^[a-zA-Z0-9_][a-zA-Z0-9_%-]*[a-zA-Z0-9_]$") ~= nil
            or s:match("^[a-zA-Z0-9_]$") ~= nil
    end
    -- Multi-label: validate each label.  Allow underscores for backward
    -- compatibility (SRV/TXT records use them; RFC 1123 forbids them but
    -- real-world proxy configs may contain them).
    for label in s:gmatch("[^.]+") do
        if #label == 0 or #label > 63 then return false end
        -- Label must not start or end with hyphen; alnum + hyphen + underscore.
        if not label:match("^[a-zA-Z0-9_][a-zA-Z0-9_%-]*[a-zA-Z0-9_]$") then
            -- Allow single-char labels (just alnum/underscore).
            if not label:match("^[a-zA-Z0-9_]$") then return false end
        end
    end
    -- Must contain at least one non-numeric label (avoid pure-numeric "123.456").
    return s:match("[^0-9%.]") ~= nil
end

function _M.validation(datatype, data)
    if not datatype or not data or data == "" then return nil end
    if datatype == "ip4addr" then return is_ip4(data)
    elseif datatype == "ip6addr" then return is_ip6(data)
    elseif datatype == "ipaddr"  then return is_ip4(data) or is_ip6(data)
    elseif datatype == "hostname" then return is_hostname(data)
    elseif datatype == "port" then
        -- Strict decimal integer: tonumber() alone accepts "80.5", "0x50",
        -- "1e3", none of which are valid ports.
        if not tostring(data):match("^%d+$") then return false end
        local n = tonumber(data)
        return n > 0 and n < 65536
    end
    return true
end

-- Lua dual of the shell bool_on() / init.d config_get_bool truth table
-- (firewall.sh, CLI, install.sh): only {1,yes,on,true,enabled} count as
-- true; every other spelling -- including nil, "0"/"no"/"off" and
-- garbage values -- is false.
local UCI_TRUE_WORDS = { ["1"] = true, yes = true, on = true, ["true"] = true, enabled = true }
function _M.uci_true(v)
	return UCI_TRUE_WORDS[tostring(v)] == true
end

-- ---------------------------------------------------------------------------
-- Base64 (pure Lua, standard + URL-safe input)
-- ---------------------------------------------------------------------------
local b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local b64idx = {}
for i = 1, #b64 do b64idx[b64:sub(i, i):byte()] = i - 1 end

function _M.decodeBase64Str(str)
    if _M.isEmpty(str) then return nil end
    str = _M.trim(str):gsub("_", "/"):gsub("-", "+")
    local pad = #str % 4
    if pad > 0 then str = str .. string.rep("=", 4 - pad) end
    local out, val, bits = {}, 0, 0
    for i = 1, #str do
        local c = str:byte(i)
        if c == 61 then break end -- '='
        local v = b64idx[c]
        if v then
            val = val * 64 + v
            bits = bits + 6
            if bits >= 8 then
                bits = bits - 8
                local byte = math.floor(val / 2^bits) % 256
                if math.tointeger then byte = math.tointeger(byte) end
                out[#out + 1] = string.char(byte)
                val = val % 2^bits   -- keep residual bits, keep val bounded
            end
        end
    end
    return table.concat(out)
end

-- ---------------------------------------------------------------------------
-- md5 (shell out to busybox md5sum; small and reliable)
-- ---------------------------------------------------------------------------
-- Subscription updates hash the same labels/configurations more than once.
-- Keep a process-local cache: this script is short-lived, so it is bounded by
-- one update run and does not create persistent state on the router.
local md5_cache = {}
function _M.md5(s)
    if s == nil then return nil end
    s = tostring(s)
    if md5_cache[s] then return md5_cache[s] end
    local h = io.popen("printf %s " .. _M.shellQuote(s) .. " | md5sum 2>/dev/null")
    local line = h and h:read("*l") or nil
    if h then h:close() end
    local r = line and line:match("^([^%s]+)") or nil
    r = _M.trim(r)
    if r then md5_cache[s] = r end
    return r
end

-- ---------------------------------------------------------------------------
-- URL encoding (for subscription labels/params)
-- ---------------------------------------------------------------------------
function _M.urldecode(s)
    if not s then return nil end
    -- Keep upstream/form semantics for query strings and labels.  Protocol
    -- userinfo that needs URI-component semantics is decoded locally by the
    -- subscription parser.
    s = s:gsub("+", " ")
    s = s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
    return s
end

function _M.urlencode(s)
    if s == nil then return nil end
    s = tostring(s)
    return (s:gsub("([^%w%-_.~])", function(c)
        return string.format("%%%02X", c:byte())
    end))
end

-- ---------------------------------------------------------------------------
-- URL parser (port of the ucode parseURL)
-- ---------------------------------------------------------------------------
function _M.parseURL(url)
    if type(url) ~= "string" then return nil end
    local services = { http = "80", https = "443" }
    local o = { href = url }

    -- fragment
    url = url:gsub("#(.+)$", function(v) o.hash = v; return "" end)
    -- scheme
    url = url:gsub("^([%w][%w%+%.%-]*):", function(v) o.protocol = v; return "" end)
    -- query
    url = url:gsub("%?(.+)$", function(v)
        o.search = v
        o.searchParams = {}
        for k, val in v:gmatch("([^&=]+)=?([^&]*)") do
            o.searchParams[_M.urldecode(k)] = _M.urldecode(val)
        end
        return ""
    end)
    -- authority
    url = url:gsub("^//([^/]*)", function(v)
        v = v:gsub("^([^@]+)@", function(u) o.userinfo = u; return "" end)
        v = v:gsub(":(%d+)$", function(p)
            -- Strip a numeric port only when the remainder cannot itself be
            -- an IPv6 literal: "https://2001:db8::1/" must not lose ":1".
            local rest = v:sub(1, #v - #p - 1)
            if rest:find("[", 1, true) or not rest:find(":", 1, true) then
                o.port = p
                return ""
            end
            return ":" .. p
        end)
        local bare = v:gsub("[%[%]]", "")
        if _M.validation("ip4addr", v) or _M.validation("hostname", v) then
            o.hostname = v
        elseif _M.validation("ip6addr", bare) then
            o.hostname = bare
        end
        return ""
    end)

    o.pathname = (url ~= "" and url) or "/"
    if not o.protocol or not o.hostname then return nil end

    if o.userinfo then
        o.userinfo = o.userinfo:gsub(":(.+)$", function(v) o.password = v; return "" end)
        -- Userinfo is opaque protocol data; scheme-specific parsers decide
        -- whether it is plaintext or base64.  Do not reject valid URI
        -- sub-delimiters such as '=' and '/' here.
        o.username = o.userinfo
        o.userinfo = nil
    end

    if o.port and not _M.validation("port", o.port) then return nil end
    if not o.port then o.port = services[o.protocol] end
    o.host = o.hostname .. (o.port and (":" .. o.port) or "")
    o.origin = o.protocol .. "://" .. o.host
    return o
end

-- ---------------------------------------------------------------------------
-- JSON: luci.json drops nil keys; we additionally drop "" / empty containers
-- to match the upstream removeBlankAttrs behaviour.
-- ---------------------------------------------------------------------------
-- luci.json (luci-lib-json, pure Lua: encode/decode) is preferred; fall back
-- to luci.jsonc (luci-lib-jsonc C binding: parse/stringify) which the ipk
-- declares as the dependency.
local json
do
	local ok, mod = pcall(require, "luci.json")
	if not ok or type(mod) ~= "table" then
		local ok2, jc = pcall(require, "luci.jsonc")
		if ok2 and type(jc) == "table" then
			json = {
				encode = function(t) return jc.stringify(t) end,
				decode = function(s)
					local v = jc.parse(s)
					return v
				end,
			}
		end
	else
		json = mod
	end
end
if not json then
	error("no JSON module available (need luci.json or luci.jsonc)")
end

local function clean(res)
    local t = type(res)
    if t == "table" then
        local out = {}
        local isarray = true
        local n = 0
        for k in pairs(res) do
            if type(k) ~= "number" then isarray = false end
            n = n + 1
        end
        if n == 0 then return nil end
        if isarray then
            -- Verify keys are exactly {1, 2, ..., n} (M2): non-sequential
            -- numeric keys (e.g. {[0]=... or {[1]=..,[3]=..}) would silently
            -- lose data if we just iterated 1..n.
            for i = 1, n do
                if res[i] == nil then isarray = false; break end
            end
        end
        if isarray then
            for i = 1, n do
                local v = clean(res[i])
                if v ~= nil then out[#out + 1] = v end
            end
            if #out == 0 then return nil end
            return out
        else
            for k, v in pairs(res) do
                v = clean(v)
                if v ~= nil then out[k] = v end
            end
            if next(out) == nil then return nil end
            return out
        end
    elseif res == nil or res == "" then
        return nil
    else
        return res
    end
end

function _M.encode_json(t)
    return json.encode(clean(t) or {}) .. "\n"
end

function _M.decode_json(s)
    return json.decode(s)
end

-- ---------------------------------------------------------------------------
-- Command execution / logging / HTTP fetch
-- ---------------------------------------------------------------------------
function _M.getTime()
    return os.date("%Y-%m-%d %H:%M:%S")
end

function _M.executeCommand(...)
    local args = { ... }
    local cmd = table.concat(args, " ")
    local out, err = {}, {}
    local tmp_o = "/tmp/.hp_out_" .. tostring(math.random(100000, 999999))
    local tmp_e = "/tmp/.hp_err_" .. tostring(math.random(100000, 999999))
    local code = os.execute(cmd .. " >" .. tmp_o .. " 2>" .. tmp_e)
    local fo = io.open(tmp_o, "rb"); if fo then out = fo:read("*a") or "" fo:close() end
    local fe = io.open(tmp_e, "rb"); if fe then err = fe:read("*a") or "" fe:close() end
    os.remove(tmp_o); os.remove(tmp_e)
    return { command = cmd, stdout = out, stderr = err, exitcode = code }
end

local function have_cmd(bin)
    -- Lua 5.1 os.execute() returns the exit status (0 on success); on some
    -- builds it may return true -- accept both.
    local rc = os.execute("command -v " .. bin .. " >/dev/null 2>&1")
    return rc == 0 or rc == true
end

function _M.wGET(url, ua)
    if not url or type(url) ~= "string" then return nil end
    ua = ua or "Wget/1.21 (HomeProxy, like v2rayN)"
    local qua = _M.shellQuote(ua)
    local qurl = _M.shellQuote(url)
    -- A nonzero exit MUST yield nil: a truncated body would otherwise be
    -- parsed as a partial node list and good nodes deleted as stale (C4).
    local function try(cmd)
        local r = _M.executeCommand(cmd)
        if r.exitcode == 0 and not _M.isEmpty(r.stdout) then
            return _M.trim(r.stdout)
        end
        return nil
    end
    -- Stock MiWiFi busybox wget cannot fetch HTTPS; prefer curl for https
    -- URLs (any curl in PATH, not just /usr/bin) and fall back to wget,
    -- which still handles plain http and https on non-busybox builds.
    if url:match("^https://") and have_cmd("curl") then
        local body = try("curl -fsSL -m 20 --max-filesize 16777216 -A " .. qua .. " " .. qurl)
        if body then return body end
    end
    if have_cmd("wget") then
        return try("wget -qO- --user-agent " .. qua .. " --timeout=10 " .. qurl)
    end
    return try("curl -fsSL -m 20 --max-filesize 16777216 -A " .. qua .. " " .. qurl)
end

local _log_dir_created = false
function _M.log(msg, tag)
    if not _log_dir_created then
        _M.mkdir_p(_M.RUN_DIR)
        _log_dir_created = true
    end
    _M.appendfile(_M.RUN_DIR .. "/homeproxy.log",
        string.format("%s [%s] %s\n", _M.getTime(), tag or "DAEMON", msg))
end

return _M
