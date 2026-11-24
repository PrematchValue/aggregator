"""External, independently updated rules for Mihomo, Surge, and sing-box.

Local TOML registry remains the sole authority for precedence and policy names.
Rule endpoints are versioned by the public repository and refreshed by the
existing daily validated snapshot workflow; never fetch third-party rules here.
"""
from __future__ import annotations

import ipaddress
import json
import re
import tomllib
from collections import OrderedDict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "subconverter/snippets/rulesets.toml"
BASE = ROOT / "subconverter"
RAW_BASE = "https://raw.githubusercontent.com/PrematchValue/aggregator/main/subconverter/"
SB_EXPORT = "rules/export/singbox"
INTERVAL = 86400
VALID_KINDS = {
    "DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword", "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
}


def registry(root: Path = ROOT) -> list[dict[str, str]]:
    items = tomllib.loads((root / "subconverter/snippets/rulesets.toml").read_text("utf-8"))["rulesets"]
    if not items or items[-1] != {"group": "漏网之鱼", "ruleset": "[]FINAL"}:
        raise ValueError("ruleset registry has no terminal FINAL")
    all_paths = [x["ruleset"] for x in items if not x["ruleset"].startswith("[]")]
    if len(all_paths) != len(set(all_paths)):
        raise ValueError("duplicate rule file in registry")
    for r in items:
        p = r["ruleset"]
        if p.startswith("[]"):
            if p not in ("[]FINAL", "[]GEOIP,CN"):
                raise ValueError(f"unsupported intrinsic rule {p}")
        elif not p.startswith("rules/") or "/../" in p or not (root / "subconverter" / p).is_file():
            raise ValueError(f"invalid rule path: {p}")
    return items


def tag_for(path: str) -> str:
    if not re.fullmatch(r"rules/(?:custom|auto)/[A-Za-z0-9]+\.list|rules/LocalAreaNetwork\.list", path):
        raise ValueError(f"invalid provider source {path}")
    return path.removeprefix("rules/").removesuffix(".list").replace("/", "_")


def read_rules(path: str, root: Path = ROOT) -> list[str]:
    text = (root / "subconverter" / path).read_text("utf-8")
    rules: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        bits = [x.strip() for x in line.split(",")]
        kind = bits[0]
        if kind not in VALID_KINDS:
            raise ValueError(f"unsupported {path} rule type {kind}")
        if len(bits) not in (2, 3) or (len(bits) == 3 and (bits[2] != "no-resolve" or not kind.startswith("IP-CIDR"))):
            raise ValueError(f"unsupported {path} rule syntax: {line}")
        if not bits[1] or "," in bits[1]:
            raise ValueError(f"invalid {path} rule syntax: {line}")
        if kind.startswith("IP-CIDR"):
            net = ipaddress.ip_network(bits[1], strict=True)
            if (kind == "IP-CIDR") != (net.version == 4):
                raise ValueError(f"wrong address family {line}")
        elif not re.fullmatch(r"[a-zA-Z0-9*_.-]+", bits[1]):
            raise ValueError(f"invalid domain value: {line}")
        rules.append(line)
    if not rules:
        raise ValueError(f"empty rule file: {path}")
    return rules


def export_singbox_rule(path: str, root: Path = ROOT) -> str:
    """sing-box source rule-set JSON, with OR semantics for mixed patterns.

    A single headless rule with multiple domain types would be AND; instead
    build one headless rule per type, grouping only values of the same type.
    """
    grouped: OrderedDict[str, list[str]] = OrderedDict()
    for line in read_rules(path, root):
        pieces = line.split(",")
        key = VALID_KINDS[pieces[0]]
        values = grouped.setdefault(key, [])
        if pieces[1] not in values:
            values.append(pieces[1])
    if not grouped:
        raise ValueError("cannot export empty rule set")
    return json.dumps({"version": 2, "rules": [{key: vals} for key, vals in grouped.items()]},
                      ensure_ascii=False, indent=2) + "\n"


def exported_files(root: Path = ROOT) -> dict[Path, str]:
    return {Path("subconverter") / SB_EXPORT / f"{tag_for(r['ruleset'])}.json":
            export_singbox_rule(r["ruleset"], root)
            for r in registry(root) if not r["ruleset"].startswith("[]")}


def sync_exports(root: Path = ROOT, *, check: bool = False) -> int:
    files = exported_files(root)
    changed = 0
    for relative, expected in files.items():
        destination = root / relative
        current = destination.read_text("utf-8") if destination.is_file() else None
        if current != expected:
            changed += 1
            if not check:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(expected, "utf-8")
    stale = set((root / "subconverter" / SB_EXPORT).glob("*.json")) - {root / p for p in files}
    if check and (changed or stale):
        raise ValueError(f"{changed} sing-box exports stale, {len(stale)} obsolete exports; run --write")
    if not check:
        for p in sorted(stale):
            p.unlink()
    return changed


def _surge_rule_lines(items: list[dict[str, str]]) -> list[str]:
    lines = []
    for entry in items:
        source, group = entry["ruleset"], entry["group"]
        if source == "[]GEOIP,CN":
            lines.append("GEOIP,CN,国内直连")
        elif source == "[]FINAL":
            lines.append("FINAL,漏网之鱼")
        else:
            policy = "国内直连" if group == "DIRECT" else ("REJECT" if group == "REJECT" else group)
            lines.append(f"RULE-SET,{RAW_BASE}{source},{policy},update-interval={INTERVAL}")
    return lines

def externalize_surge(profile: str, root: Path = ROOT) -> str:
    items = registry(root)
    match = list(re.finditer(r"(?m)^\[Rule\][ \t]*$", profile))
    if len(match) != 1:
        raise ValueError("Surge must contain exactly one [Rule] section")
    start = match[0].end()
    ending = re.search(r"(?m)^\[[^\]\n]+\][ \t]*$", profile[start:])
    end = start + ending.start() if ending else len(profile)
    replacement = "\n" + "\n".join(_surge_rule_lines(items)) + "\n\n"
    result = profile[:start] + replacement + profile[end:]
    if "[Proxy]\n" not in result or "[Proxy Group]\n" not in result:
        raise ValueError("Surge ruleset rewrite removed proxy sections")
    return result


def externalize_singbox(profile: str, root: Path = ROOT) -> str:
    items = registry(root)
    # Fail before publishing when the latest daily exports aren't committed.
    sync_exports(root, check=True)
    doc = json.loads(profile)
    route = doc.get("route")
    if not isinstance(route, dict) or not isinstance(route.get("rules", []), list):
        raise ValueError("invalid sing-box route")
    if route.get("rule_set"):
        raise ValueError("unexpected pre-existing sing-box rule sets")
    old = route.get("rules", [])
    keep = []
    for r in old:
        if not isinstance(r, dict):
            raise ValueError("invalid sing-box rule")
        if r.get("action") in {"hijack-dns", "sniff", "resolve"}:
            keep.append(r)
    remote, compact = [], []
    for e in items:
        src, group = e["ruleset"], e["group"]
        if src == "[]FINAL":
            continue
        if src == "[]GEOIP,CN":
            compact.append({"rule_set": "geoip-cn", "outbound": "DIRECT"})
            continue
        tag = tag_for(src)
        remote.append({"type": "remote", "tag": tag, "format": "source",
                       "url": RAW_BASE + f"{SB_EXPORT}/{tag}.json", "update_interval": "1d"})
        if group == "REJECT":
            compact.append({"rule_set": tag, "action": "reject"})
        else:
            compact.append({"rule_set": tag,
                            "outbound": "DIRECT" if group == "DIRECT" else group})
    remote.append({"type": "remote", "tag": "geoip-cn", "format": "binary",
                   "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                   "update_interval": "1d"})
    route["rules"] = keep + compact
    route["rule_set"] = remote
    route["final"] = "漏网之鱼"
    experiment = doc.setdefault("experimental", {})
    if not isinstance(experiment, dict):
        raise ValueError("invalid sing-box experimental config")
    cache = experiment.setdefault("cache_file", {})
    if not isinstance(cache, dict):
        raise ValueError("invalid sing-box cache_file")
    cache["enabled"] = True
    tags = {o["tag"] for o in doc["outbounds"]}
    ids = {r["tag"] for r in remote}
    if len(ids) != len(remote):
        raise ValueError("duplicate remote sing-box ruleset tag")
    for rule in compact:
        if rule["rule_set"] not in ids:
            raise ValueError("missing sing-box remote ruleset")
        if "outbound" in rule and rule["outbound"] not in tags:
            raise ValueError("missing sing-box rule outbound")
    if route["final"] not in tags:
        raise ValueError("missing final sing-box selector")
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    a = parser.parse_args()
    n = sync_exports(check=not a.write)
    print(f"Sing-box 规则导出：{'已更新' if a.write else '已校验'} {n} 个文件")