"""Verified source-category snapshots. Failures preserve the last usable copy.

Only trusted RuleGo and blackmatrix7 source paths are allowed. Unsupported
process/user-agent/GEOIP rules are deliberately excluded from all-platform
snapshots rather than silently changing their meaning on sing-box/Mihomo.
"""
from __future__ import annotations
import ipaddress
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULEGO = "https://raw.githubusercontent.com/ConnersHua/RuleGo/master/Surge/Ruleset/"
BLACKMATRIX = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/"
MAX_BYTES = 256 * 1024

@dataclass(frozen=True)
class PublicSource:
    name: str
    url: str
    minimum: int
    maximum: int
    anchor: str

SOURCES = (
    PublicSource("Advertising.list", RULEGO+"Extra/Reject/Advertising.list", 850, 1200, "DOMAIN-SUFFIX,17gouwuba.com"),
    PublicSource("Tracking.list", RULEGO+"Extra/Reject/Tracking.list", 75, 170, "DOMAIN-SUFFIX,adjust.com"),
    PublicSource("DirectPlus.list", RULEGO+"Direct+.list", 17, 80, "DOMAIN,app.adjust.com"),
    PublicSource("StreamingCN.list", RULEGO+"Extra/Streaming/CN.list", 14, 50, "DOMAIN,www.bilibili.com"),
    PublicSource("InternationalMediaFull.list", RULEGO+"Extra/Streaming/!CN.list", 170, 360, "DOMAIN-SUFFIX,netflix.com"),
    PublicSource("GitHubService.list", BLACKMATRIX+"GitHub/GitHub.list", 25, 100, "DOMAIN-SUFFIX,github.com"),
    PublicSource("MicrosoftService.list", BLACKMATRIX+"Microsoft/Microsoft.list", 560, 760, "DOMAIN-SUFFIX,microsoft.com"),
    PublicSource("Direct.list", RULEGO+"Direct.list", 17, 70, "DOMAIN-SUFFIX,flyert.com"),
    PublicSource("WeChat.list", RULEGO+"Extra/WeChat.list", 10, 70, "DOMAIN-SUFFIX,wechat.com"),
)
ALLOWED_KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6"}
DOMAIN = re.compile(r"[a-zA-Z0-9*_.-]{2,253}")

def download(url: str) -> str:
    if not (url.startswith(RULEGO) or url.startswith(BLACKMATRIX)):
        raise ValueError("unapproved rule source")
    req = urllib.request.Request(url, headers={"User-Agent": "aggregator-verified-rules/1.0"})
    with urllib.request.urlopen(req, timeout=25) as response:
        data = response.read(MAX_BYTES+1)
    if len(data) > MAX_BYTES:
        raise ValueError("rule file too large")
    return data.decode("utf-8-sig")

def normalized(text: str) -> list[str]:
    out, seen = [], set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        p = [x.strip() for x in line.split(",")]
        if len(p) < 2 or p[0].upper() not in ALLOWED_KINDS:
            continue
        kind, value = p[0].upper(), p[1]
        if not value:
            continue
        if kind.startswith("IP-CIDR"):
            try:
                ip = ipaddress.ip_network(value, strict=True)
            except ValueError:
                continue
            if (kind == "IP-CIDR") != (ip.version == 4):
                continue
            if ip.prefixlen < (8 if ip.version == 4 else 24):
                continue
            rule = f"{kind},{ip},no-resolve"
        elif not DOMAIN.fullmatch(value):
            continue
        else:
            rule = f"{kind},{value.lower()}"
        if rule not in seen:
            out.append(rule)
            seen.add(rule)
    return out

def snapshot(spec: PublicSource, raw: str) -> str:
    rows = normalized(raw)
    if not spec.minimum <= len(rows) <= spec.maximum or spec.anchor not in rows:
        raise ValueError(f"{spec.name}: unusual rule source count/anchor {len(rows)}")
    return "# VERIFIED-PUBLIC: category snapshot for Clash, Surge and sing-box\n" + f"# Source: {spec.url}\n" + "\n".join(rows) + "\n"

def check_snapshot(spec: PublicSource, content: str) -> None:
    if not content.startswith("# VERIFIED-PUBLIC:") or f"# Source: {spec.url}\n" not in content:
        raise ValueError(f"{spec.name}: missing verified source header")
    data = [x for x in content.splitlines() if x.strip() and not x.startswith("#")]
    if len(data) != len(set(data)) or not spec.minimum <= len(data) <= spec.maximum:
        raise ValueError(f"{spec.name}: bad snapshot count")
    if data != normalized("\n".join(data)) or spec.anchor not in data:
        raise ValueError(f"{spec.name}: invalid snapshot entries")

def check(root: Path = ROOT) -> None:
    for spec in SOURCES:
        path = root/"subconverter/rules/auto"/spec.name
        check_snapshot(spec, path.read_text("utf-8"))

def bootstrap(downloader=download) -> dict[str, str]:
    """Fetch all sources without modifying files; used by atomic installer."""
    found = {}
    for spec in SOURCES:
        found[spec.name] = snapshot(spec, downloader(spec.url))
    return found

def update(root: Path = ROOT, downloader=download) -> dict[str, str]:
    result = {}
    for spec in SOURCES:
        path = root/"subconverter/rules/auto"/spec.name
        try:
            previous = path.read_text("utf-8")
            check_snapshot(spec, previous)
            fresh = snapshot(spec, downloader(spec.url))
            prior_count = previous.count("\n") - 2
            new_count = fresh.count("\n") - 2
            if new_count*2 < prior_count:
                raise ValueError(f"unusual count reduction {prior_count} -> {new_count}")
            if fresh == previous:
                result[spec.name] = "unchanged"
            else:
                path.write_text(fresh, encoding="utf-8")
                result[spec.name] = f"updated {prior_count} -> {new_count}"
        except (OSError, ValueError, UnicodeError) as exc:
            result[spec.name] = f"retained previous: {type(exc).__name__}: {exc}"
    return result
