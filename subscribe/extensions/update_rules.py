"""Conservative, persisted, service-specific rule snapshots from trusted sources.

Never overwrite the handwritten rules. An invalid/unreachable source retains
its previous committed snapshot; a separate daily workflow commits valid diffs.
Data are from SukkaW/Surge, AGPL-3.0: https://github.com/SukkaW/Surge
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "subconverter/rules"
AUTO = RULES / "auto"
SOURCE_BASE = "https://ruleset.skk.moe/List/"
GLOBAL_URL = "https://raw.githubusercontent.com/ConnersHua/RuleGo/master/Surge/Ruleset/Proxy.list"
MAX_BYTES = 512 * 1024
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$", re.I)


@dataclass(frozen=True)
class Source:
    filename: str
    remote_path: str
    base_filename: str
    allow: tuple[str, ...]
    anchor: str
    minimum: int
    ip: bool = False
    source_url: str = ""
    global_proxy: bool = False


SOURCES = (
    Source("GlobalProxy.list", "global/Proxy.list", "GlobalProxy.list", (),
           "DOMAIN-SUFFIX,fbcdn.net", 25, False, GLOBAL_URL, True),
)


def download(url: str) -> str:
    if not (url.startswith(SOURCE_BASE) or url == GLOBAL_URL):
        raise ValueError("untrusted rule host")
    request = urllib.request.Request(url, headers={"User-Agent": "aggregator-rules/1.0"})
    with urllib.request.urlopen(request, timeout=25) as response:
        size = response.headers.get("Content-Length", "")
        if size.isdigit() and int(size) > MAX_BYTES:
            raise ValueError("rule source too large")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("rule source too large")
    return data.decode("utf-8-sig")


def extract(spec: Source, source: str) -> list[str]:
    result, seen = [], set()
    for line in source.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        columns = line.split(",")
        kind = columns[0].upper()
        normalized = None
        if spec.ip:
            if kind not in {"IP-CIDR", "IP-CIDR6"} or len(columns) < 2:
                continue
            try:
                network = ipaddress.ip_network(columns[1].strip(), strict=True)
            except ValueError:
                continue
            if kind == "IP-CIDR" and network.version != 4:
                continue
            if kind == "IP-CIDR6" and network.version != 6:
                continue
            if network.prefixlen < (8 if network.version == 4 else 24):
                continue
            normalized = f"{kind},{network},no-resolve"
        else:
            if len(columns) < 2:
                continue
            if kind == "DOMAIN-KEYWORD" and spec.global_proxy:
                token = columns[1].strip().lower()
                if len(token) < 5 or not re.fullmatch(r"[a-z0-9._-]+", token):
                    continue
                normalized = f"{kind},{token}"
            elif kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
                domain = columns[1].strip().lower().strip(".")
                if len(domain) > 253 or ".." in domain or not DOMAIN_RE.fullmatch(domain):
                    continue
                if "7h15.ru1353t" in domain:  # upstream tracking sentinel
                    continue
                if spec.global_proxy:
                    if domain.endswith((".cn", ".local")) or domain in {"cn", "localhost"}:
                        continue
                elif not any(domain == root or domain.endswith("." + root) for root in spec.allow):
                    continue
                normalized = f"{kind},{domain}"
            else:
                continue
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    if spec.anchor not in seen:
        raise ValueError(f"missing required anchor: {spec.anchor}")
    if len(result) < spec.minimum or len(result) > (800 if spec.global_proxy else 400):
        raise ValueError(f"unexpected rule count: {len(result)}")
    return result


def snapshot(spec: Source, source: str, *, base_text: str = "") -> str:
    rows = extract(spec, source)
    existing = set()
    for raw in base_text.splitlines():
        line = raw.strip().lower()
        if line.startswith(("DOMAIN,", "DOMAIN-SUFFIX,", "IP-CIDR,", "IP-CIDR6,")):
            existing.add(line)
    # Avoid exact duplicates and redundant subdomains already covered by
    # handwritten suffix rules for the same service.
    suffixes = [line.split(",", 1)[1] for line in existing
                if line.startswith("domain-suffix,")]
    filtered = []
    for rule in rows:
        if rule.lower() in existing:
            continue
        if not spec.ip:
            domain = rule.split(",", 1)[1]
            if any(domain == suffix or domain.endswith("." + suffix) for suffix in suffixes):
                continue
        filtered.append(rule)
    if not filtered:
        raise ValueError("no nonredundant rules; retain previous snapshot")
    source = spec.source_url or SOURCE_BASE + spec.remote_path
    return ("# AUTO-GENERATED: trusted, service-filtered upstream supplement.\n"
            f"# Source: {source} (SukkaW/Surge or ConnersHua/RuleGo)\n"
            "# Handwritten ../custom/ rules always take precedence.\n"
            + "\n".join(filtered) + "\n")


def validate_snapshot_file(spec: Source, text: str) -> None:
    if not text.startswith("# AUTO-GENERATED:"):
        raise ValueError(f"{spec.filename}: missing origin marker")
    if (spec.source_url or SOURCE_BASE + spec.remote_path) not in text:
        raise ValueError(f"{spec.filename}: invalid origin")
    rows = [x.strip() for x in text.splitlines() if x.strip() and not x.startswith("#")]
    if not rows or len(rows) != len(set(rows)) or len(rows) > (800 if spec.global_proxy else 400):
        raise ValueError(f"{spec.filename}: empty/duplicated/oversized snapshot")
    for row in rows:
        parts = row.split(",")
        if spec.ip:
            if parts[0] not in ("IP-CIDR", "IP-CIDR6") or parts[-1] != "no-resolve":
                raise ValueError(f"{spec.filename}: invalid CIDR rule {row!r}")
            try:
                address = ipaddress.ip_network(parts[1], strict=True)
            except ValueError as e:
                raise ValueError(f"{spec.filename}: invalid CIDR") from e
            if len(parts) != 3 or (parts[0] == "IP-CIDR") != (address.version == 4):
                raise ValueError(f"{spec.filename}: IP family mismatch")
        else:
            if parts[0] not in (("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD")
                                  if spec.global_proxy else ("DOMAIN", "DOMAIN-SUFFIX")) or len(parts) != 2:
                raise ValueError(f"{spec.filename}: unsupported rule {row!r}")
            domain = parts[1]
            if spec.global_proxy:
                if not re.fullmatch(r"[a-z0-9._-]+", domain) or (
                        parts[0] != "DOMAIN-KEYWORD" and (domain.endswith(".cn") or ".." in domain)):
                    raise ValueError(f"{spec.filename}: invalid general proxy rule {row!r}")
            elif not DOMAIN_RE.fullmatch(domain) or ".." in domain or not any(
                    domain == root or domain.endswith("." + root) for root in spec.allow):
                raise ValueError(f"{spec.filename}: out-of-category rule {row!r}")


def update(root: Path = ROOT, downloader=download) -> dict[str, str]:
    results = {}
    cache: dict[str, str] = {}
    for spec in SOURCES:
        dst = root / "subconverter/rules/auto" / spec.filename
        base = root / "subconverter/rules/custom" / spec.base_filename
        try:
            url = spec.source_url or SOURCE_BASE + spec.remote_path
            if url not in cache:
                cache[url] = downloader(url)
            new = snapshot(spec, cache[url], base_text=base.read_text("utf-8") if base.is_file() else "")
            validate_snapshot_file(spec, new)
            old = dst.read_text("utf-8")
            validate_snapshot_file(spec, old)
            old_lines = sum(bool(x) and not x.startswith("#") for x in old.splitlines())
            new_lines = sum(bool(x) and not x.startswith("#") for x in new.splitlines())
            if new_lines * 2 < old_lines:
                raise ValueError(f"rule count dropped sharply: {old_lines} -> {new_lines}")
            if old == new:
                results[spec.filename] = "unchanged"
            else:
                dst.write_text(new, encoding="utf-8")
                results[spec.filename] = f"updated: {old_lines} -> {new_lines}"
        except (OSError, UnicodeError, ValueError) as exc:
            # Never replace the last committed good snapshot on source failure.
            results[spec.filename] = f"retained previous: {type(exc).__name__}: {exc}"
    return results


def check(root: Path = ROOT) -> None:
    for spec in SOURCES:
        path = root / "subconverter/rules/auto" / spec.filename
        validate_snapshot_file(spec, path.read_text("utf-8"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--update", action="store_true", help="fetch, validate, persist only valid snapshots")
    args = parser.parse_args()
    if args.update:
        for name, status in update().items():
            print(f"{name}: {status}")
        from extensions.verified_public_rules import update as update_public
        for name, status in update_public().items():
            print(f"{name}: {status}")
    else:
        check()
        from extensions.verified_public_rules import check as check_public
        check_public()
        print("自动规则快照检查通过")
