"""Convert a Surge profile into a strict external policy-path proxy list.

A policy-path resource only needs proxy declarations. A built-in DIRECT/REJECT
policy, traffic rule or policy group must never appear as an airport node.
"""

from __future__ import annotations

import re

# The supported outbound families for Surge policy-path, aligned to the
# aggregator's Surge artifact validation. Unsupported protocols are omitted.
PROXY_TYPES = frozenset({
    "ss", "ssr", "vmess", "trojan", "http", "https", "socks5",
    "socks5-tls", "snell", "tuic", "tuic-v5", "hysteria2", "wireguard",
    "vless", "anytls", "masque", "ssh", "h2-connect", "trust-tunnel",
})
SECTION_RE = re.compile(r"^\[([^\]]+)\]$")
POLICY_RE = re.compile(r"^([^=\r\n]+?)\s*=\s*([a-zA-Z][a-zA-Z0-9-]*)\s*,\s*(\S.*)$")


def proxy_lines_only(profile: str) -> str:
    """Return a bare policy list that Surge can import via policy-path.

    Supports both full Surge profiles and bare proxy declaration lists.
    Raises instead of publishing an empty or malformed resource.
    """
    if not isinstance(profile, str) or not profile.strip():
        raise ValueError("empty Surge conversion")
    sections = [m.group(1).strip().lower() for line in profile.splitlines()
                if (m := SECTION_RE.fullmatch(line.strip()))]
    with_sections = bool(sections)
    if with_sections and "proxy" not in sections:
        raise ValueError("Surge profile has no [Proxy] section")
    in_proxy = not with_sections
    policies: list[str] = []
    names: set[str] = set()
    for line in profile.splitlines():
        line = line.strip()
        match_section = SECTION_RE.fullmatch(line)
        if match_section:
            in_proxy = match_section.group(1).strip().lower() == "proxy"
            continue
        if not in_proxy or not line or line.startswith(("#", ";", "//")):
            continue
        match = POLICY_RE.fullmatch(line)
        if not match:
            continue
        name, protocol, parameters = match.groups()
        name, protocol = name.strip(), protocol.lower()
        # DIRECT, REJECT and named policies such as 全球直连 are deliberately
        # excluded by the outbound family allowlist, not by their display name.
        if protocol not in PROXY_TYPES or not name:
            continue
        key = name.casefold()
        if key in names:
            raise ValueError("duplicate Surge proxy name")
        names.add(key)
        policies.append(f"{name} = {protocol}, {parameters}")
    if not policies:
        raise ValueError("Surge conversion contains no supported proxy nodes")
    return "\n".join(policies) + "\n"
