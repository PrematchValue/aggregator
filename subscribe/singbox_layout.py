"""Make generated sing-box rules and proxy DNS refer to real outbounds.

SubConverter supplies proxy protocols and rule conversion. This module adds
our named regional/service selectors after conversion, without rewriting
endpoint credentials or assigning rules on its own.
"""
from __future__ import annotations

import json

from profile_layout import SERVICES, SPECIAL, build_members, service_choices

_SPECIAL_TYPES = frozenset({"direct", "block", "dns", "selector", "urltest"})


def apply_singbox_layout(text: str) -> str:
    try:
        doc = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid sing-box JSON") from exc
    if not isinstance(doc, dict):
        raise ValueError("sing-box root must be an object")
    outbounds = doc.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds or any(not isinstance(x, dict) for x in outbounds):
        raise ValueError("no valid sing-box outbounds")
    tags = [o.get("tag") for o in outbounds]
    if any(not isinstance(t, str) or not t for t in tags) or len(set(tags)) != len(tags):
        raise ValueError("missing or duplicate sing-box outbound tags")
    reserved = {"节点选择", "国内直连", *SERVICES, SPECIAL,
                "香港节点", "台湾节点", "狮城节点", "日本节点", "美国节点"}
    if reserved.intersection(tags):
        raise ValueError("existing sing-box outbound conflicts with local policy")
    nodes = [o["tag"] for o in outbounds if o.get("type") not in _SPECIAL_TYPES]
    enabled, members = build_members(nodes)

    dns = doc.get("dns")
    servers = dns.get("servers") if isinstance(dns, dict) else None
    candidates = [s for s in servers if isinstance(s, dict) and s.get("tag") == "dns_proxy"] if isinstance(servers, list) else []
    if len(candidates) != 1:
        raise ValueError("missing or ambiguous proxy DNS server")
    candidates[0]["detour"] = "节点选择"

    # SubConverter versions may emit the removed legacy `dns` outbound.
    # Its rule is now a native DNS hijack action; never expose it as proxy.
    legacy_dns = {o["tag"] for o in outbounds if o.get("type") == "dns"}
    route = doc.get("route")
    if not isinstance(route, dict) or not isinstance(route.get("rules", []), list):
        raise ValueError("invalid sing-box routing configuration")
    for rule in route.get("rules", []):
        if not isinstance(rule, dict):
            raise ValueError("invalid sing-box route rule")
        outbound = rule.get("outbound")
        if outbound in legacy_dns:
            del rule["outbound"]
            rule["action"] = "hijack-dns"
        elif outbound == "REJECT":
            # sing-box 1.13+ does not have a block outbound: use native action.
            del rule["outbound"]
            rule["action"] = "reject"

    # Keep the upstream native DIRECT (not a Chinese alias). The generator may
    # omit builtin policies while still emitting routing rules referencing them.
    native_direct = [o for o in outbounds if o.get("tag") == "DIRECT"]
    if native_direct and native_direct[0].get("type") != "direct":
        raise ValueError("sing-box DIRECT tag is not a native direct outbound")
    native_reject = [o for o in outbounds if o.get("tag") == "REJECT"]
    if native_reject and native_reject[0].get("type") != "block":
        raise ValueError("unexpected sing-box REJECT outbound type")
    doc["outbounds"] = [o for o in outbounds
                        if o.get("type") != "dns" and o.get("tag") != "REJECT"]
    if not native_direct:
        doc["outbounds"].insert(0, {"type": "direct", "tag": "DIRECT"})

    extra = [{"type": "selector", "tag": "节点选择", "outbounds": enabled}]
    extra.extend({"type": "selector", "tag": name,
                  "outbounds": service_choices(name, enabled, "DIRECT")}
                 for name in SERVICES)
    for name in enabled:
        group = {"type": "selector", "tag": name, "outbounds": members[name]}
        if name != SPECIAL:
            group.update(type="urltest", url="https://www.gstatic.com/generate_204",
                         interval="10m", tolerance=50)
        extra.append(group)
    doc["outbounds"].extend(extra)
    if route.get("final") == "REJECT":
        # A default route requires an outbound tag. Preserve reject-all intent
        # with a terminal action rule instead of pointing at a removed outbound.
        route["rules"].append({"action": "reject"})
        route["final"] = "DIRECT"
    elif not route.get("final"):
        route["final"] = "漏网之鱼"

    # Fail closed: all converted routing tags must exist after group generation.
    final_tags = {o["tag"] for o in doc["outbounds"]}
    for rule in route.get("rules", []):
        outbound = rule.get("outbound")
        if outbound is not None and outbound not in final_tags:
            raise ValueError(f"sing-box route refers to missing outbound {outbound!r}")
    if route["final"] not in final_tags:
        raise ValueError("sing-box final outbound does not exist")
    if candidates[0]["detour"] not in final_tags:
        raise ValueError("sing-box DNS detour does not exist")
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
