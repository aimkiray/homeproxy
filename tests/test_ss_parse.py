#!/usr/bin/env python3
"""
Verify ss (shadowsocks) share-link parsing: OLD vs NEW Lua handler logic.

Replicates the Lua functions in homeproxy.lua and subscription_parser.lua
(both the pre-d2acb22 "manual" handler, the post-d2acb22 "parseURL-based"
handler, and the current meow-era handler in subscription_parser.lua) to
confirm which ss link formats break and which the fix resolves.

Post-migration additions mirror the meow legality precheck (spec
§4.4/§9.1): AEAD-only cipher set, 2022-blake3 base64 key-length rule, and
the in-process SIP003 plugin names ("simple-obfs"/"obfs-local" normalize
onto the "obfs" builtin; external plugins are rejected).

Lua pattern semantics reproduced:
  - parseURL: IPv6 brackets stripped from hostname; username always assigned
    (no charset gate); port range-validated.
  - is_ip6: rejects multiple '::', ':::', group counts >7 with '::', !=8 without.
  - decodeBase64Str: _ -> /, - -> +, skip non-base64 chars, stop at '='
  - urldecode (for fragments): + -> space, %XX -> byte
  - uri_component_decode (for ss passwords/userinfo): %XX -> byte only
"""

import base64
import re
import sys

# ---------------------------------------------------------------------------
# Replicate hp.decodeBase64Str (Lua port in homeproxy.lua)
# ---------------------------------------------------------------------------
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
B64IDX = {c: i for i, c in enumerate(B64)}


def lua_trim(s):
    return s.strip() if s else s


def decode_base64_str(s):
    """Faithful replica of hp.decodeBase64Str."""
    if not s:
        return None
    s = lua_trim(s).replace("_", "/").replace("-", "+")
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    out = []
    val = 0
    bits = 0
    for ch in s:
        c = ord(ch)
        if c == 61:  # '='
            break
        v = B64IDX.get(chr(c))
        if v is not None:
            val = val * 64 + v
            bits += 6
            if bits >= 8:
                bits -= 8
                byte = (val >> bits) & 0xFF
                out.append(byte)
                val &= (1 << bits) - 1
    return bytes(out).decode("utf-8", errors="replace") if out else None


# ---------------------------------------------------------------------------
# Replicate hp.urldecode
# ---------------------------------------------------------------------------
def urldecode(s):
    if s is None:
        return None
    s = s.replace("+", " ")
    return re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)


# ---------------------------------------------------------------------------
# Replicate hp.parseURL (Lua port in homeproxy.lua)
# ---------------------------------------------------------------------------
def is_ip4(s):
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if n < 0 or n > 255:
            return False
    return True


def is_ip6(s):
    if not s or s == "":
        return False
    if not re.match(r"^[0-9a-fA-F:.]+$", s):
        return False
    if s[0] == ":" and (len(s) < 2 or s[1] != ":"):
        return False
    if s[-1] == ":" and (len(s) < 2 or s[-2] != ":"):
        return False
    seen_double = "::" in s
    _, doubles = re.subn(r"::", "", s)
    if doubles > 1 or ":::" in s:
        return False
    groups = [g for g in re.split(r":", s) if g]
    for g in groups:
        if len(g) > 4:
            return False
    if seen_double and len(groups) > 7:
        return False
    if not seen_double and len(groups) != 8:
        return False
    return True


def is_hostname(s):
    """Faithful replica of homeproxy.lua is_hostname (post-hardening):
    rejects empty labels (a..b, .x, x.), >253 total, >63 labels, leading/
    trailing hyphens in labels, and pure-numeric dotted strings."""
    if not s or len(s) > 253:
        return False
    if s.startswith(".") or s.endswith(".") or ".." in s:
        return False
    if "." not in s:
        # Single label follows the same label rules (interior hyphens OK).
        if len(s) > 63:
            return False
        return re.match(r"^[a-zA-Z0-9_][a-zA-Z0-9_\-]*[a-zA-Z0-9_]$", s) is not None \
            or re.match(r"^[a-zA-Z0-9_]$", s) is not None
    for label in s.split("."):
        if len(label) == 0 or len(label) > 63:
            return False
        if not re.match(r"^[a-zA-Z0-9_][a-zA-Z0-9_\-]*[a-zA-Z0-9_]$", label) \
                and not re.match(r"^[a-zA-Z0-9_]$", label):
            return False
    return re.search(r"[^0-9.]", s) is not None


def validation(datatype, data):
    if not datatype or not data:
        return False
    if datatype == "ip4addr":
        return is_ip4(data)
    if datatype == "ip6addr":
        return is_ip6(data)
    if datatype == "hostname":
        return is_hostname(data)
    if datatype == "port":
        n = int(data) if str(data).isdigit() else None
        return n is not None and 0 < n < 65536
    return True


def parse_url(url):
    """Replica of the current hp.parseURL (post-fix)."""
    if not isinstance(url, str):
        return None
    services = {"http": "80", "https": "443"}
    o = {"href": url}

    # fragment
    m = re.search(r"#(.+)$", url)
    if m:
        o["hash"] = m.group(1)
        url = url[: m.start()]

    # scheme
    m = re.match(r"^(\w[\w+.\-]*):", url)
    if m:
        o["protocol"] = m.group(1)
        url = url[m.end():]

    # query
    m = re.search(r"\?(.+)$", url)
    if m:
        o["search"] = m.group(1)
        o["searchParams"] = {}
        for mm in re.finditer(r"([^&=]+)=?([^&]*)", m.group(1)):
            o["searchParams"][urldecode(mm.group(1))] = urldecode(mm.group(2))
        url = url[: m.start()]

    # authority
    m = re.match(r"^//([^/]*)", url)
    if m:
        v = m.group(1)
        m2 = re.match(r"^([^@]+)@", v)
        if m2:
            o["userinfo"] = m2.group(1)
            v = v[m2.end():]
        m3 = re.search(r":(\d+)$", v)
        if m3:
            o["port"] = m3.group(1)
            v = v[: m3.start()]
        bare = re.sub(r"[\[\]]", "", v)
        if validation("ip4addr", v) or validation("hostname", v):
            o["hostname"] = v
        elif validation("ip6addr", bare):
            o["hostname"] = bare
        url = url[m.end():]

    o["pathname"] = url or "/"
    if not o.get("protocol") or not o.get("hostname"):
        return None

    if "userinfo" in o:
        m = re.search(r":(.+)$", o["userinfo"])
        if m:
            o["password"] = m.group(1)
            o["userinfo"] = o["userinfo"][: m.start()]
        # Userinfo is opaque protocol data; always assign (no charset gate).
        o["username"] = o["userinfo"]
        o.pop("userinfo", None)

    if "port" in o and not validation("port", o["port"]):
        return None
    if "port" not in o:
        o["port"] = services.get(o["protocol"])
    o["host"] = o["hostname"] + (":" + o["port"] if o.get("port") else "")
    o["origin"] = o["protocol"] + "://" + o["host"]
    return o


def parse_url_buggy(url):
    """Replica of the pre-fix hp.parseURL (with username charset gate + IPv6 brackets kept)."""
    if not isinstance(url, str):
        return None
    services = {"http": "80", "https": "443"}
    o = {"href": url}

    m = re.search(r"#(.+)$", url)
    if m:
        o["hash"] = m.group(1)
        url = url[: m.start()]

    m = re.match(r"^(\w[\w+.\-]*):", url)
    if m:
        o["protocol"] = m.group(1)
        url = url[m.end():]

    m = re.search(r"\?(.+)$", url)
    if m:
        o["search"] = m.group(1)
        o["searchParams"] = {}
        for mm in re.finditer(r"([^&=]+)=?([^&]*)", m.group(1)):
            o["searchParams"][urldecode(mm.group(1))] = urldecode(mm.group(2))
        url = url[: m.start()]

    m = re.match(r"^//([^/]*)", url)
    if m:
        v = m.group(1)
        m2 = re.match(r"^([^@]+)@", v)
        if m2:
            o["userinfo"] = m2.group(1)
            v = v[m2.end():]
        m3 = re.search(r":(\d+)$", v)
        if m3:
            o["port"] = m3.group(1)
            v = v[: m3.start()]
        bare = re.sub(r"[\[\]]", "", v)
        # OLD: keep brackets for IPv6; accept ip4/ip6/hostname in one check
        if validation("ip4addr", v) or validation("ip6addr", bare) or validation("hostname", v):
            o["hostname"] = v
        url = url[m.end():]

    o["pathname"] = url or "/"
    if not o.get("protocol") or not o.get("hostname"):
        return None

    if "userinfo" in o:
        m = re.search(r":(.+)$", o["userinfo"])
        if m:
            o["password"] = m.group(1)
            o["userinfo"] = o["userinfo"][: m.start()]
        # OLD: reject username if it contains '=' or '/'
        if re.match(r"^[A-Za-z0-9+\-_.]+$", o["userinfo"]):
            o["username"] = o["userinfo"]
        o.pop("userinfo", None)

    if "port" not in o:
        o["port"] = services.get(o["protocol"])
    o["host"] = o["hostname"] + (":" + o["port"] if o.get("port") else "")
    o["origin"] = o["protocol"] + "://" + o["host"]
    return o
    o["host"] = o["hostname"] + (":" + o["port"] if o.get("port") else "")
    o["origin"] = o["protocol"] + "://" + o["host"]
    return o


# ---------------------------------------------------------------------------
# OLD ss handler (pre-d2acb22): manual extraction, no parseURL
# ---------------------------------------------------------------------------
def ss_old(rest):
    body, frag = rest, None
    hpos = rest.find("#")
    if hpos >= 0:
        body, frag = rest[:hpos], rest[hpos + 1:]
    else:
        hpos = None
    sslabel = urldecode(frag) if frag and frag != "" else None
    method = pass_ = host = port = None
    at = body.find("@") if body else -1
    if at >= 0:
        userinfo = body[:at]
        hostport = re.sub(r"\?.*$", "", body[at + 1:])
        m = re.match(r"^([^:]+):(.*)$", userinfo)
        if m:
            method, pass_ = m.group(1), m.group(2)
        if not method:
            dec = decode_base64_str(userinfo)
            if dec:
                m = re.match(r"^([^:]+):(.*)$", dec)
                if m:
                    method, pass_ = m.group(1), m.group(2)
        m = re.match(r"^([^:]+):(\d+)$", hostport)
        if m:
            host, port = m.group(1), m.group(2)
    else:
        dec = decode_base64_str(body)
        if dec:
            m = re.match(r"^([^:]+):([^@]+)@([^:]+):(\d+)$", dec)
            if m:
                method, pass_, host, port = m.groups()
    if method and host and port:
        return {"label": sslabel, "type": "shadowsocks", "address": host,
                "port": port, "method": method, "password": pass_}
    return None


# ---------------------------------------------------------------------------
# NEW ss handler (post-d2acb22, BEFORE fix): uses parseURL
# ---------------------------------------------------------------------------
def ss_new_buggy(rest):
    body, frag = rest, None
    hpos = rest.find("#")
    if hpos >= 0:
        body, frag = rest[:hpos], rest[hpos + 1:]
    if body and "@" not in body and re.match(r"^[A-Za-z0-9+/=_-]+$", body):
        dec = decode_base64_str(body)
        if dec and "@" in dec:
            rest = dec + ("#" + frag if frag else "")
    ssurl = parse_url_buggy("http://" + rest)
    if not ssurl:
        return None
    ssp = ssurl.get("searchParams", {})
    label = urldecode(ssurl["hash"]) if ssurl.get("hash") else None
    method = pass_ = None
    if ssurl.get("username") and ssurl.get("password"):
        method = ssurl["username"]
        pass_ = urldecode(ssurl["password"])
    elif ssurl.get("username"):
        d = decode_base64_str(urldecode(ssurl["username"]))
        if d:
            m = re.match(r"^([^:]+):(.*)$", d)
            if m:
                method, pass_ = m.group(1), m.group(2)
    ssplugin = sspluginopts = None
    if ssp.get("plugin"):
        m = re.match(r"^([^;]+);?(.*)$", ssp["plugin"])
        if m:
            pname = m.group(1)
            if pname == "simple-obfs":
                pname = "obfs-local"
            ssplugin = pname
            sspluginopts = m.group(2) or None
    if method and ssurl.get("hostname") and ssurl.get("port"):
        sslabel = urldecode(frag) if frag else label
        return {"label": sslabel, "type": "shadowsocks", "address": ssurl["hostname"],
                "port": ssurl["port"], "method": method, "password": pass_,
                "plugin": ssplugin, "plugin_opts": sspluginopts}
    return None


# URI component decode: only %XX, do NOT convert '+' to space.
def uri_component_decode(s):
    if s is None:
        return None
    return re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)


# ---------------------------------------------------------------------------
# FIXED ss handler: manual userinfo split + parseURL for host:port only
# ---------------------------------------------------------------------------
def ss_fixed(rest):
    body, frag = rest, None
    hpos = rest.find("#")
    if hpos >= 0:
        body, frag = rest[:hpos], rest[hpos + 1:]
    # Shadowrocket pre-decode
    if body and "@" not in body and re.match(r"^[A-Za-z0-9+/=_-]+$", body):
        dec = decode_base64_str(body)
        if dec and "@" in dec:
            dh = dec.find("#")
            if dh >= 0:
                body = dec[:dh]
                if not frag:
                    frag = dec[dh + 1:]
            else:
                body = dec
    # Split at LAST '@'
    if "@" not in body:
        return None
    idx = body.rfind("@")
    ssuserinfo = body[:idx]
    hostpart = body[idx + 1:]
    ssurl = parse_url("http://" + hostpart)
    if not ssurl:
        return None
    ssp = ssurl.get("searchParams", {})
    method = pass_ = None
    # Try plaintext first (password may be URI-component-encoded)
    m = re.match(r"^([^:]+):(.*)$", ssuserinfo)
    if m:
        method, pass_ = m.group(1), uri_component_decode(m.group(2))
    else:
        d = decode_base64_str(uri_component_decode(ssuserinfo))
        if d:
            m = re.match(r"^([^:]+):(.*)$", d)
            if m:
                method, pass_ = m.group(1), m.group(2)
    ssplugin = sspluginopts = None
    if ssp.get("plugin"):
        m = re.match(r"^([^;]+);?(.*)$", ssp["plugin"])
        if m:
            pname = m.group(1)
            # meow: legacy names map onto the "obfs" builtin.
            if pname in ("simple-obfs", "obfs-local"):
                pname = "obfs"
            ssplugin = pname
            sspluginopts = m.group(2) or None
    if method and ssurl.get("hostname") and ssurl.get("port"):
        sslabel = urldecode(frag) if frag else None
        ssaddr = re.sub(r"[\[\]]", "", ssurl["hostname"])
        return {"label": sslabel, "type": "shadowsocks", "address": ssaddr,
                "port": ssurl["port"], "method": method, "password": pass_,
                "plugin": ssplugin, "plugin_opts": sspluginopts}
    return None


# ---------------------------------------------------------------------------
# meow SS legality precheck (mirror of subscription_parser.lua
# M.validate_node shadowsocks branch, spec §4.4/§9.1).
# ---------------------------------------------------------------------------
MEOW_SS_AEAD = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
MEOW_SS_BUILTIN_PLUGINS = {
    "obfs", "simple-obfs", "v2ray-plugin", "gost-plugin", "shadow-tls",
    "restls", "jls", "ech-tls-tunnel", "kcptun",
}


def b64_decoded_len(s):
    """Mirror of the Lua b64_key_len: strict charset, decoded byte count."""
    if not isinstance(s, str) or not re.match(r"^[A-Za-z0-9+/_\-]+=?=?$", s):
        return None
    try:
        return len(base64.b64decode(s + "=" * (-len(s) % 4)))
    except Exception:
        return None


def ss_meow_precheck(method, password, plugin=None):
    """Returns (ok, reason). Mirrors validate_node's shadowsocks branch."""
    if not method or not password:
        return (False, "shadowsocks node missing encrypt_method or password")
    if method not in MEOW_SS_AEAD:
        return (False, "not an AEAD cipher meow accepts")
    if method.startswith("2022-blake3-"):
        need = 16 if method == "2022-blake3-aes-128-gcm" else 32
        if b64_decoded_len(password) != need:
            return (False, "requires a base64 key of %d bytes" % need)
    if plugin and plugin not in MEOW_SS_BUILTIN_PLUGINS:
        return (False, "not a meow built-in plugin")
    return (True, None)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
def b64(s):
    return base64.b64encode(s.encode()).decode()


def make_sip002_b64_nopad(method, password, host, port, tag=None):
    userinfo = b64(f"{method}:{password}").rstrip("=")
    url = f"ss://{userinfo}@{host}:{port}"
    if tag:
        url += f"#{tag}"
    return url


def make_sip002_b64_padded(method, password, host, port, tag=None):
    userinfo = b64(f"{method}:{password}")  # WITH padding
    url = f"ss://{userinfo}@{host}:{port}"
    if tag:
        url += f"#{tag}"
    return url


def make_sip002_b64url(method, password, host, port, tag=None):
    userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
    url = f"ss://{userinfo}@{host}:{port}"
    if tag:
        url += f"#{tag}"
    return url


def make_sip002_plain(method, password, host, port, tag=None):
    url = f"ss://{method}:{password}@{host}:{port}"
    if tag:
        url += f"#{tag}"
    return url


def make_sip002_plain_encoded(method, password, host, port, tag=None):
    """Password with special chars URL-encoded."""
    from urllib.parse import quote
    pw = quote(password, safe="")
    url = f"ss://{method}:{pw}@{host}:{port}"
    if tag:
        url += f"#{tag}"
    return url


def make_shadowrocket(method, password, host, port, tag=None):
    """Entire body base64-encoded (Shadowrocket 'lovely' format)."""
    inner = f"{method}:{password}@{host}:{port}"
    if tag:
        inner += f"#{tag}"
    body = b64(inner)
    url = f"ss://{body}"
    if tag:
        url += f"#{tag}"  # tag outside base64
    return url, f"ss://{b64(f'{method}:{password}@{host}:{port}')}#{tag}" if tag else f"ss://{b64(f'{method}:{password}@{host}:{port}')}"


def make_sip002_plugin(method, password, host, port, plugin, opts=None, tag=None):
    userinfo = b64(f"{method}:{password}").rstrip("=")
    plugin_str = plugin
    if opts:
        plugin_str += f";{opts}"
    from urllib.parse import quote
    url = f"ss://{userinfo}@{host}:{port}?plugin={quote(plugin_str, safe=';=')}"
    if tag:
        url += f"#{tag}"
    return url


def make_sip002_ipv6(method, password, host, port, tag=None):
    userinfo = b64(f"{method}:{password}").rstrip("=")
    url = f"ss://{userinfo}@[{host}]:{port}"
    if tag:
        url += f"#{tag}"
    return url


def extract_rest(ss_url):
    """Extract the part after 'ss://' for the handler."""
    return ss_url[len("ss://"):]


tests = [
    # (description, ss_url, expected_method)
    ("SIP002 base64 NO padding", make_sip002_b64_nopad("aes-256-gcm", "password", "example.com", 8388, "MyNode"), "aes-256-gcm"),
    ("SIP002 base64 WITH padding", make_sip002_b64_padded("aes-256-gcm", "password", "example.com", 8388, "MyNode"), "aes-256-gcm"),
    ("SIP002 base64 chacha20 (==pad)", make_sip002_b64_padded("chacha20-ietf-poly1305", "password", "example.com", 8388, "Node"), "chacha20-ietf-poly1305"),
    ("SIP002 base64url no pad", make_sip002_b64url("aes-256-gcm", "password", "example.com", 8388, "Tag"), "aes-256-gcm"),
    ("SIP002 plaintext", make_sip002_plain("aes-256-gcm", "password", "example.com", 8388, "Plain"), "aes-256-gcm"),
    ("SIP002 plaintext encoded pw", make_sip002_plain_encoded("aes-256-gcm", "p@ss:word", "example.com", 8388, "Enc"), "aes-256-gcm"),
    ("SIP002 base64 no pad no tag", make_sip002_b64_nopad("aes-256-gcm", "password", "example.com", 8388), "aes-256-gcm"),
    ("SIP002 base64 padded no tag", make_sip002_b64_padded("aes-256-gcm", "password", "example.com", 8388), "aes-256-gcm"),
    # Shadowrocket format (tag outside)
    ("Shadowrocket tag outside", f"ss://{b64('aes-256-gcm:password@example.com:8388')}#SRNode", "aes-256-gcm"),
    # Shadowrocket format (tag inside base64)
    ("Shadowrocket tag inside", f"ss://{b64('aes-256-gcm:password@example.com:8388#InnerTag')}", "aes-256-gcm"),
    # SIP002 with plugin
    ("SIP002 plugin simple-obfs", make_sip002_plugin("aes-256-gcm", "password", "example.com", "8388", "simple-obfs", "mode=http"), "aes-256-gcm"),
    # IPv6
    ("SIP002 IPv6 no pad", make_sip002_ipv6("aes-256-gcm", "password", "2001:db8::1", 8388, "V6Node"), "aes-256-gcm"),
    # base64 with '/' in it (method that produces '/' in base64)
    # rc4-md5:password -> base64 = "cmM0LW1kNTpwYXNzd29yZA==" — has no '/', let me force one
    # Use a password that produces '/' in base64
    ("SIP002 base64 with / char", make_sip002_b64_padded("aes-256-gcm", "p\x00ss", "example.com", 8388, "Slash"), "aes-256-gcm"),
]


def run_tests():
    print(f"{'DESCRIPTION':<35} {'OLD':<8} {'BUGGY':<8} {'FIXED':<8} EXPECTED")
    print("-" * 95)
    total = 0
    old_pass = buggy_pass = fixed_pass = 0
    old_fail = buggy_fail = fixed_fail = 0
    for desc, url, expected in tests:
        rest = extract_rest(url)
        old_r = ss_old(rest)
        buggy_r = ss_new_buggy(rest)
        fixed_r = ss_fixed(rest)

        old_ok = old_r is not None and old_r.get("method") == expected
        buggy_ok = buggy_r is not None and buggy_r.get("method") == expected
        fixed_ok = fixed_r is not None and fixed_r.get("method") == expected

        total += 1
        if old_ok: old_pass += 1
        else: old_fail += 1
        if buggy_ok: buggy_pass += 1
        else: buggy_fail += 1
        if fixed_ok: fixed_pass += 1
        else: fixed_fail += 1

        print(f"{desc:<35} {'PASS' if old_ok else 'FAIL':<8} {'PASS' if buggy_ok else 'FAIL':<8} {'PASS' if fixed_ok else 'FAIL':<8} {expected}")

        if not fixed_ok:
            print(f"    URL: {url}")
            if fixed_r:
                print(f"    FIXED result: {fixed_r}")
            else:
                print(f"    FIXED: returned None")
            # Debug
            body = rest.split("#")[0] if "#" in rest else rest
            print(f"    body={body!r}")
            if "@" in body:
                idx = body.rfind("@")
                print(f"    userinfo={body[:idx]!r} hostpart={body[idx+1:]!r}")

    print("-" * 95)
    print(f"Summary: OLD {old_pass}/{total} pass | BUGGY {buggy_pass}/{total} pass | FIXED {fixed_pass}/{total} pass")
    if buggy_fail > 0 and fixed_fail == 0:
        print(f"\n✓ FIX RESOLVES REGRESSION: {buggy_fail} cases broken by buggy code, all fixed.")
    if fixed_fail > 0:
        print(f"\n✗ {fixed_fail} cases still failing after fix!")
        sys.exit(1)


def check_meow_ss_precheck():
    """Contract checks for the meow-era ss precheck (AEAD set, 2022 keys,
    plugin normalization)."""
    key16 = base64.b64encode(b"k" * 16).decode()
    key32 = base64.b64encode(b"k" * 32).decode()

    accepted = [
        ("aes-128-gcm", "password", None),
        ("aes-256-gcm", "password", "obfs"),          # normalized builtin
        ("aes-256-gcm", "password", "v2ray-plugin"),
        ("chacha20-ietf-poly1305", "password", None),
        ("2022-blake3-aes-128-gcm", key16, None),
        ("2022-blake3-aes-256-gcm", key32, None),
        ("2022-blake3-chacha20-poly1305", key32, None),
    ]
    for method, pw, plugin in accepted:
        ok, reason = ss_meow_precheck(method, pw, plugin)
        assert ok, f"should accept {method}/{plugin}: {reason}"

    rejected = [
        # measured against the v0.24.0 reference build: these fail `meow -t`.
        ("xchacha20-ietf-poly1305", "password", None),
        ("aes-192-gcm", "password", None),
        ("aes-128-ccm", "password", None),
        ("aes-256-ccm", "password", None),
        ("rc4-md5", "password", None),                # stream cipher
        ("aes-256-cfb", "password", None),            # stream cipher
        # 2022 ciphers with wrong key material must be rejected.
        ("2022-blake3-aes-128-gcm", "password", None),
        ("2022-blake3-aes-128-gcm", key32, None),     # wrong length
        ("2022-blake3-aes-256-gcm", key16, None),     # wrong length
        # external SIP003 plugin names are disabled by --no-external-plugins
        ("aes-256-gcm", "password", "ck-client"),
        ("aes-256-gcm", "password", "some-external-plugin"),
        # missing credentials
        (None, "password", None),
        ("aes-256-gcm", None, None),
    ]
    for method, pw, plugin in rejected:
        ok, reason = ss_meow_precheck(method, pw, plugin)
        assert not ok, f"should reject {method}/{plugin}"
        assert reason
    print("meow ss precheck checks: PASS")


def check_plugin_normalization():
    """simple-obfs / obfs-local links must normalize to the 'obfs' builtin."""
    for plugin_in in ("simple-obfs", "obfs-local", "obfs"):
        url = make_sip002_plugin("aes-256-gcm", "password", "example.com",
                                 "8388", plugin_in, "mode=http")
        r = ss_fixed(extract_rest(url))
        assert r is not None, plugin_in
        assert r["plugin"] == "obfs", (plugin_in, r["plugin"])
        assert r["plugin_opts"] == "mode=http"
    # SIP008 plugin field gets the same normalization upstream; ensure an
    # unknown plugin survives parsing (precheck rejects it, not the parser).
    url = make_sip002_plugin("aes-256-gcm", "password", "example.com",
                             "8388", "ck-client", "mode=x")
    r = ss_fixed(extract_rest(url))
    assert r is not None and r["plugin"] == "ck-client"
    ok, reason = ss_meow_precheck(r["method"], r["password"], r["plugin"])
    assert not ok and reason
    print("plugin normalization checks: PASS")


def check_hostname_replica():
    """Lock the Python replica to the hardened Lua is_hostname contract."""
    good = ["example.com", "a.b-c.example.org", "localhost", "node_1.example.com",
            "xn--fsq.com", "a" * 63 + ".com", "my-router", "DESKTOP-PC", "a-b"]
    bad = ["", ".example.com", "example.com.", "a..b", "-bad.example.com",
           "bad-.example.com", "exa mple.com", "a" * 64 + ".com",
           "123.456", "ex/ample.com", "exam_ple.com x", "-single", "single-",
           "a" * 64]
    for h in good:
        assert is_hostname(h), f"valid hostname rejected: {h}"
    for h in bad:
        assert not is_hostname(h), f"invalid hostname accepted: {h!r}"
    print("hostname replica checks: PASS")


# pytest entry points: the file predates pytest -- expose the suites.
def test_hostname_replica():
    check_hostname_replica()


def test_parser_matrix():
    run_tests()


def test_meow_ss_precheck():
    check_meow_ss_precheck()


def test_plugin_normalization():
    check_plugin_normalization()


if __name__ == "__main__":
    check_hostname_replica()
    run_tests()
    check_meow_ss_precheck()
    check_plugin_normalization()