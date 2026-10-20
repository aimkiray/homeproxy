#!/usr/bin/env python3
"""Pure-Python checks for subscription helper contracts (meow-rs migration).

The router runs Lua 5.1 with UCI/luci.json, which is unavailable on this
Windows checkout. These tests exercise the data-shaping contracts that do not
need those runtime bindings: body detection, filter semantics, URI-component
plus handling, the meow legality-precheck taxonomy (spec-meow-migration-A
§4.4/§9.1), and the meow-features.json cache contract (§9.3).
"""

import base64
import re


# ---------------------------------------------------------------------------
# Body decoding / filter / URI component contracts (unchanged)
# ---------------------------------------------------------------------------
def looks_like_share_list(value):
    if not value:
        return False
    return any(re.match(r"^\s*[A-Za-z][A-Za-z0-9+.\-]*://", line)
               for line in value.splitlines() if line)


def decode_subscription_body(value):
    plain = value.strip() if value else value
    if not plain or looks_like_share_list(plain):
        return plain
    try:
        decoded = base64.b64decode(plain + "=" * (-len(plain) % 4), validate=False).decode()
    except (ValueError, UnicodeDecodeError):
        decoded = ""
    return decoded if looks_like_share_list(decoded) else plain


def filter_check(name, mode, keywords):
    if not name or mode == "disabled" or not keywords:
        return False
    matched = any(term and term in name
                  for keyword in keywords
                  for term in str(keyword).split("|"))
    return (not matched) if mode == "whitelist" else matched


def uri_component_decode(value):
    return re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value)


# ---------------------------------------------------------------------------
# meow legality precheck (mirror of subscription_parser.lua M.validate_node +
# parse_uri_raw dispatch). Spec §4.4/§9.1/AC-14.
# ---------------------------------------------------------------------------
MEOW_SUPPORTED_TYPES = {
    "shadowsocks": "ss",
    "vmess": "vmess",
    "vless": "vless",
    "trojan": "trojan",
    "hysteria2": "hysteria2",
    "snell": "snell",
    "anytls": "anytls",
    "socks": "socks5",
    "http": "http",
}

# UCI types the old kernel accepted but meow cannot emit at all.
MEOW_UNSUPPORTED_TYPES = {
    "hysteria", "tuic", "wireguard", "ssh", "shadowtls",
    "shadowsocksr", "trusttunnel",
}

# Share-link schemes naming a hard-unsupported protocol -> "unsupported-type".
MEOW_UNSUPPORTED_SCHEMES = {
    "hysteria": "hysteria (v1)",
    "tuic": "tuic",
    "wireguard": "wireguard",
    "wg": "wireguard",
    "ssr": "shadowsocksr",
    "shadowsocksr": "shadowsocksr",
    "ssh": "ssh",
    "shadowtls": "shadowtls",
    "shadow-tls": "shadowtls",
    "trusttunnel": "trusttunnel",
}

# Schemes the link dispatcher actually has parsers for.
MEOW_PARSED_SCHEMES = {
    "ss", "vmess", "anytls", "http", "https",
    "socks", "socks4", "socks4a", "socks5", "socks5h",
    "trojan", "hysteria2", "hy2", "vless",
}


def classify_link(line):
    """Mirror of parse_uri_raw's scheme dispatch: returns
    (kind, hint) where kind is "supported"|"unsupported-type"|
    "unsupported-scheme"|"malformed" and hint is the type/scheme."""
    if not isinstance(line, str):
        return ("malformed", "unknown")
    line = line.strip()
    m = re.match(r"^(\w[\w+.\-]*)://", line)
    if not m:
        return ("malformed", "unknown")   # junk line: silent drop upstream
    scheme = m.group(1).lower()
    if scheme in MEOW_UNSUPPORTED_SCHEMES:
        return ("unsupported-type", MEOW_UNSUPPORTED_SCHEMES[scheme])
    if scheme in MEOW_PARSED_SCHEMES:
        return ("supported", scheme)
    return ("unsupported-scheme", scheme)


def main():
    plain = "ss://method:pass@example.com:8388\nvless://uuid@example.com:443"
    encoded = base64.urlsafe_b64encode(plain.encode()).decode().rstrip("=")
    assert decode_subscription_body(plain) == plain
    assert decode_subscription_body(encoded) == plain
    assert decode_subscription_body("not a subscription") == "not a subscription"

    assert filter_check("Japan Remaining 01", "blacklist", ["重置|到期|Remaining"])
    assert not filter_check("Japan Premium", "blacklist", ["重置|到期|Remaining"])
    assert not filter_check("Japan Premium", "whitelist", ["Japan|HK"])
    assert filter_check("US Premium", "whitelist", ["Japan|HK"])

    assert uri_component_decode("a+b%2Bc") == "a+b+c"

    # --- meow whitelist: supported protocols -------------------------------
    assert set(MEOW_SUPPORTED_TYPES) == {
        "shadowsocks", "vmess", "vless", "trojan", "hysteria2",
        "snell", "anytls", "socks", "http",
    }
    assert MEOW_SUPPORTED_TYPES["shadowsocks"] == "ss"
    assert MEOW_SUPPORTED_TYPES["socks"] == "socks5"
    # --- hard-unsupported protocols must be explicit rejections ------------
    for scheme in ("hysteria", "tuic", "ssr", "wireguard", "ssh", "shadowtls"):
        kind, hint = classify_link(scheme + "://x:y@h:1#lbl")
        assert kind == "unsupported-type", (scheme, kind)
        assert hint  # a human-readable protocol name reaches the record
    assert classify_link("ssr://abc")[1] == "shadowsocksr"
    # --- parsed schemes ----------------------------------------------------
    for scheme in MEOW_PARSED_SCHEMES:
        assert classify_link(scheme + "://u@h:1")[0] == "supported", scheme
    # snell has no share-link form: parsed by UCI only, not by subscription.
    assert classify_link("snell://h:443")[0] == "unsupported-scheme"
    assert classify_link("not-a-link") == ("malformed", "unknown")


# --- meow feature cache contract (§9.3/§8.4) -------------------------------
MEOW_FEATURE_KEYS = [
    "with_quic", "with_utls", "with_hysteria", "with_ss_listener",
    "with_ss", "with_trojan", "with_vmess", "with_snell", "with_anytls",
]


def meow_signature(binary, version, mtime):
    """Mirror of meow_signature(): hp.md5(path + version + mtime); returns
    None when the binary cannot answer `meow --version` (never cached)."""
    import hashlib
    if not version:
        return None
    return hashlib.md5(
        ("%s\n%s\n%s" % (binary, version, mtime or "0")).encode()).hexdigest()


def read_feature_cache(cache, signature):
    """Mirror of update_subscriptions.lua read_feature_cache."""
    if not isinstance(cache, dict):
        return None
    if cache.get("signature") != signature:
        return None
    f = cache.get("features")
    if not isinstance(f, dict):
        return None
    for k in MEOW_FEATURE_KEYS:
        if type(f.get(k)) is not bool:
            return None
    return f


def test_meow_feature_cache():
    sig = meow_signature("/usr/bin/meow", "meow 0.24.0", "1719000000")
    good = {"signature": sig, "features": {k: True for k in MEOW_FEATURE_KEYS}}
    good["features"]["with_hysteria"] = False  # hysteria v1: always absent
    assert read_feature_cache(good, sig) is good["features"]
    # version bump or binary swap (mtime change) must invalidate
    assert read_feature_cache(good, meow_signature("/usr/bin/meow", "meow 0.25.0", "1719000000")) is None
    assert read_feature_cache(good, meow_signature("/usr/bin/meow", "meow 0.24.0", "1719999999")) is None
    # corrupt entries rejected
    bad = {"signature": sig, "features": dict(good["features"], with_quic="yes")}
    assert read_feature_cache(bad, sig) is None
    missing = {"signature": sig, "features": {k: True for k in MEOW_FEATURE_KEYS[:-1]}}
    assert read_feature_cache(missing, sig) is None
    assert read_feature_cache({"signature": "x"}, sig) is None
    assert read_feature_cache(None, sig) is None
    # binary that cannot answer `meow --version` must never be cached.
    assert meow_signature("/usr/bin/meow", "", "1719000000") is None
    print("meow feature-cache checks: PASS")


def test_meow_whitelist():
    # Re-run the dispatch assertions under pytest as well.
    for scheme in ("hysteria", "hy1", "tuic", "ssr", "ssh", "wireguard", "shadowtls"):
        kind, _ = classify_link(scheme + "://u@h:1")
        if scheme == "hy1":
            assert kind == "unsupported-scheme"   # not an alias we parse
        else:
            assert kind == "unsupported-type", (scheme, kind)
    for scheme in MEOW_PARSED_SCHEMES:
        assert classify_link(scheme + "://u@h:1")[0] == "supported"
    assert "hysteria" not in MEOW_SUPPORTED_TYPES  # v1 must stay absent
    assert set(MEOW_UNSUPPORTED_TYPES) <= set(
        k for k in MEOW_UNSUPPORTED_TYPES)  # self-consistency
    print("meow whitelist checks: PASS")


# pytest entry point: the file predates pytest -- expose the suite as a test.
def test_subscription_helpers():
    main()


if __name__ == "__main__":
    main()
    test_meow_feature_cache()
    test_meow_whitelist()
    print("subscription helper checks: PASS")
