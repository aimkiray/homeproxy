-- SPDX-License-Identifier: GPL-2.0-only
-- Minimal LAN NTP responder for firewall.sh's homeproxy_ntp arm.
-- LAN clients NTP to foreign servers whose UDP path is usually dead (GFW
-- drop or -- on Qualcomm ECM builds -- the UDP-TPROXY attach being stripped
-- on the bridge pass-up path). nat REDIRECT lands their query here instead
-- and we answer from the router's vendor-synced clock; conntrack rewrites
-- the reply source back to the queried server, so the client sees a normal
-- response. arg[1] = refid IPv4 (router LAN addr) when known.
local socket = require("socket")

local udp = assert(socket.udp())
udp:setoption("reuseaddr", true)
assert(udp:setsockname("*", 123))
udp:settimeout(nil) -- truly block in receivefrom; settimeout(0) is NON-blocking
-- (busy EAGAIN re-loop = ~100% CPU on the router core). nil = wait forever.

local EPOCH = 2208988800 -- NTP epoch offset (seconds 1900 -> 1970)

-- refid: stratum>1 responders carry an IPv4 upstream reference; we have
-- none, so self-identify with the LAN address when one was passed in.
local ref = "INIT"
do
	local a, b, c, d = tostring(arg and arg[1] or ""):match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	if a then ref = string.char(a % 256, b % 256, c % 256, d % 256) end
end

local function ntp_ts()
	local now = os.time() + EPOCH
	local frac = math.floor((socket.gettime() % 1) * 4294967296)
	local hi = math.floor(now / 65536)
	local lo = now % 65536
	return string.char(
		math.floor(hi / 256) % 256, hi % 256,
		math.floor(lo / 256) % 256, lo % 256,
		math.floor(frac / 16777216) % 256, math.floor(frac / 65536) % 256,
		math.floor(frac / 256) % 256, frac % 256)
end

while true do
	local pkt, ip, port = udp:receivefrom()
	-- Only answer client-mode (3) requests that carry a full 48-byte
	-- transmit field; anything else (server pkts, short probes) is ignored.
	if pkt and #pkt >= 48 and pkt:byte(1) % 8 == 3 then
		local vn = math.floor(pkt:byte(1) / 8) % 8
		local ts = ntp_ts()
		local rep = string.char(vn * 8 + 4, 3, pkt:byte(3), 0xEC)
			.. "\0\0\0\0" .. "\0\0\0\32"
			.. ref
			.. ts .. pkt:sub(41, 48) .. ts .. ts
		pcall(udp.sendto, udp, rep, ip, port)
	end
end
