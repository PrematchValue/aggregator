"""Conservatively identify proxy *egress* regions and apply sorted Chinese labels.

A region is NEVER inferred from entry-server IP or a numeric original name.
An existing confirmed region may be reused if the same proxy cannot be checked
on this run. Refresh re-sorts and renumbers every region from 001.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import defaultdict

import yaml

# Relative priority for familiar regions. Others follow by ISO code; unknown last.
PRIORITY = ("HK", "TW", "JP", "SG", "KR", "US", "GB", "DE", "FR", "NL", "CA", "AU", "CN")
UNKNOWN = "ZZ"
IGNORE_KEYS = {"name", "sub", "liveness", "cdn", "renamed", "delay", "_region", "_verified_http"}
LABEL_RE = re.compile(r"^(?P<flag>[\U0001f1e6-\U0001f1ff]{2}) (?P<country>.+?) (?P<number>\d{3,})$")
ALIASES = {
    "中国香港": "HK", "香港特别行政区": "HK", "香港": "HK", "HONG KONG": "HK",
    "中国台湾": "TW", "台湾": "TW", "TAIWAN": "TW",
    "日本": "JP", "JAPAN": "JP", "新加坡": "SG", "SINGAPORE": "SG",
    "韩国": "KR", "SOUTH KOREA": "KR", "美国": "US", "UNITED STATES": "US",
    "英国": "GB", "UNITED KINGDOM": "GB", "德国": "DE", "GERMANY": "DE",
    "法国": "FR", "FRANCE": "FR", "荷兰": "NL", "NETHERLANDS": "NL",
    "加拿大": "CA", "CANADA": "CA", "澳大利亚": "AU", "AUSTRALIA": "AU",
    "中国": "CN", "CHINA": "CN", "澳门": "MO", "中国澳门": "MO", "MACAO": "MO", "MACAU": "MO",
}


def identity(proxy: dict) -> str:
    """Hash normalized connection parameters, never expose passwords or tokens."""
    details = {k: v for k, v in proxy.items() if k not in IGNORE_KEYS}
    details["server"] = str(details.get("server", "")).strip().lower()
    details["type"] = str(details.get("type", "")).lower()
    # Passwords are hashed as part of the identity and never printed.
    blob = json.dumps(details, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def flag(code: str) -> str:
    if code == UNKNOWN:
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def _map_region(region: str, countries: dict[str, str]) -> str:
    text = str(region or "").strip()
    if not text:
        return UNKNOWN
    upper = text.upper()
    if upper in countries:
        return upper
    if text in ALIASES:
        return ALIASES[text]
    if upper in ALIASES:
        return ALIASES[upper]
    normalized = {v: k for k, v in countries.items()}
    return normalized.get(text, UNKNOWN)


def _history(previous_clash: str, countries: dict[str, str]) -> dict[str, tuple[str, int]]:
    """Remember previous Gist labels only if their emoji, country and number agree."""
    if not isinstance(previous_clash, str) or not previous_clash.strip():
        return {}
    try:
        root = yaml.safe_load(previous_clash)
        nodes = root.get("proxies", []) if isinstance(root, dict) else []
        if not isinstance(nodes, list):
            return {}
        result = {}
        for p in nodes:
            if not isinstance(p, dict):
                continue
            m = LABEL_RE.fullmatch(str(p.get("name", "")))
            if not m:
                continue
            code = _map_region(m.group("country"), countries)
            if code != UNKNOWN and m.group("flag") == flag(code):
                result[identity(p)] = (code, int(m.group("number")))
        return result
    except (ValueError, TypeError, yaml.YAMLError):
        return {}


def relabel_and_sort(
    proxies: list[dict], previous_clash: str = "", num_threads: int = 24, chunk_size: int = 80,
    *, batch_query=None, query_func=None, countries: dict[str, str] | None = None,
    retry_unknown: bool = False,
) -> tuple[list[dict], dict[str, int]]:
    """Use mihomo outbound HTTP requests for egress location; never delete proxies.

    `batch_query`/`query_func` are injectable to test without external network.
    A failed query or missing mihomo retains the proxy in the unknown section.
    """
    if countries is None:
        from location import ISO_TO_CHINESE
        countries = ISO_TO_CHINESE
    if batch_query is None or query_func is None:
        from location import batch_query as real_batch_query
        from egress_region import locate_with_fallback
        batch_query = batch_query or real_batch_query
        query_func = query_func or locate_with_fallback

    old = _history(previous_clash, countries)
    items = [copy.deepcopy(proxy) for proxy in proxies]
    ids = [identity(p) for p in items]
    discovered: dict[str, str] = {}
    checked = set()
    live_by_id: dict[str, bool] = {}
    step = max(1, min(120, int(chunk_size)))

    def check_batch(batch: list[dict]) -> None:
        # Mihomo creates per-node listeners, and may normalize names on its
        # private copies. Never modify source connection parameters.
        try:
            queried = batch_query(
                proxies=copy.deepcopy(batch), func=query_func,
                num_threads=max(1, min(32, num_threads)), show_progress=False,
                description="Checking egress regions and HTTPS", digits=4,
            ) or []
        except Exception:
            queried = []
        for entry in queried:
            candidate = getattr(entry, "proxy", None)
            info = getattr(entry, "result", None)
            if not isinstance(candidate, dict):
                continue
            key = identity(candidate)
            if "_verified_http" in candidate:
                live_by_id[key] = live_by_id.get(key, False) or bool(candidate["_verified_http"])
            if not getattr(entry, "success", False) or info is None or getattr(info, "is_cdn", False):
                continue
            code = _map_region(getattr(info, "country", ""), countries)
            if code != UNKNOWN:
                discovered[key] = code
                checked.add(key)
                live_by_id[key] = True  # A successful HTTPS geolocation is real HTTP.
        # An invalid config can make an entire Mihomo batch fail. One bounded
        # bisect avoids letting a single unsupported proxy discard its peers.
        if retry_unknown and len(batch) > 20 and not any(
            isinstance(getattr(entry, "proxy", None), dict)
            and "_verified_http" in entry.proxy for entry in queried
        ):
            midpoint = len(batch) // 2
            for part in (batch[:midpoint], batch[midpoint:]):
                try:
                    extra = batch_query(proxies=copy.deepcopy(part), func=query_func,
                        num_threads=max(1, min(32, num_threads)), show_progress=False,
                        description="Retry split listener batch", digits=4) or []
                except Exception:
                    extra = []
                for entry in extra:
                    candidate = getattr(entry, "proxy", None)
                    info = getattr(entry, "result", None)
                    if not isinstance(candidate, dict):
                        continue
                    key = identity(candidate)
                    if "_verified_http" in candidate:
                        live_by_id[key] = live_by_id.get(key, False) or bool(candidate["_verified_http"])
                    if getattr(entry, "success", False) and info is not None and not getattr(info, "is_cdn", False):
                        code = _map_region(getattr(info, "country", ""), countries)
                        if code != UNKNOWN:
                            discovered[key] = code
                            checked.add(key)
                            live_by_id[key] = True

    for offset in range(0, len(items), step):
        check_batch(items[offset:offset + step])

    first_count = len(discovered)
    if retry_unknown:
        # Second complete pass only for nodes still without an actual egress
        # location. The second pass may use a different live proxy path/result.
        pending = [p for p, key in zip(items, ids) if key not in discovered]
        for offset in range(0, len(pending), step):
            check_batch(pending[offset:offset + step])

    groups = defaultdict(list)
    cached = 0
    for i, proxy in enumerate(items):
        key = ids[i]
        country = discovered.get(key, UNKNOWN)
        if country == UNKNOWN and key in old and live_by_id.get(key, not retry_unknown):
            country = old[key][0]
            cached += 1
        groups[country].append((key, proxy))

    results: list[dict] = []
    # Rebuild contiguous numbering every Collect/Refresh. An old Gist label can
    # confirm a region, but its old number never controls the new ordering.
    def region_order(code: str) -> tuple[int, str]:
        if code in PRIORITY:
            return PRIORITY.index(code), code
        if code == UNKNOWN:
            return len(PRIORITY) + 1, code
        return len(PRIORITY), code

    for country in sorted(groups, key=region_order):
        group = sorted(groups[country], key=lambda item: item[0])
        prefix = "🌐 未知地区" if country == UNKNOWN else f"{flag(country)} {countries[country]}"
        for number, (_, proxy) in enumerate(group, start=1):
            proxy["name"] = f"{prefix} {number:03d}"
            results.append(proxy)

    counts = {"total": len(items), "fresh": len(checked), "historical": cached, "unknown": len(groups.get(UNKNOWN, []))}
    if retry_unknown:
        counts.update({"live": sum(bool(x) for x in live_by_id.values()),
                       "not_live": len(ids) - sum(bool(live_by_id.get(k, False)) for k in ids),
                       "recovered": len(discovered) - first_count})
    return results, counts


def only_confirmed(proxies: list[dict]) -> tuple[list[dict], int]:
    """Keep only recognized country-flagged nodes after relabel_and_sort.

    Does not change proxy parameters or mutate the source list. Historical
    confirmed egress regions remain eligible; unknown never masquerades as US.
    """
    kept = []
    for proxy in proxies:
        if isinstance(proxy, dict) and LABEL_RE.fullmatch(str(proxy.get("name", ""))):
            kept.append(proxy)
    return kept, len(proxies) - len(kept)
