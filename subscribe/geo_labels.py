"""Minimal locale-specific presentation layer over upstream location.batch_query.

Original aggregator remains responsible for node collection, liveness checks,
proxy parsing, location network requests and SubConverter publishing. No
entry-IP guesses or protocol conversion occur here.
"""
from __future__ import annotations

import copy
import hashlib
import json
from collections import defaultdict

ORDER = ("HK", "TW", "JP", "SG", "KR", "US", "GB", "DE", "FR", "NL", "CA", "AU", "CN")
ALIASES = {"香港": "HK", "中国香港": "HK", "香港特别行政区": "HK",
           "台湾": "TW", "中国台湾": "TW", "澳门": "MO", "中国澳门": "MO",
           "韩国": "KR", "南韩": "KR", "美国": "US", "英国": "GB"}
# Source and runtime metadata are not connection parameters.
META = frozenset({"name", "sub", "liveness", "cdn", "renamed", "delay",
                  "_region", "_verified_http"})


def _code(value, countries):
    label = str(value or "").strip()
    if label.upper() in countries:
        return label.upper()
    if label in ALIASES:
        return ALIASES[label]
    for code, name in countries.items():
        if label == name:
            return code
    return ""


def _fingerprint(proxy):
    fields = {k: v for k, v in proxy.items() if k not in META and not str(k).startswith("_")}
    encoded = json.dumps(fields, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _flag(code):
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code)


def label_verified_nodes(proxies, num_threads=24, chunk_size=32):
    """Label upstream liveness-checked nodes by confirmed egress country.

    Uses upstream Mihomo batch_query and locate_by_ipinfo. An unconfirmed
    region is excluded rather than assigned an invented flag or entry region.
    No node protocol, server, credential or transport is altered.
    """
    from location import ISO_TO_CHINESE, batch_query, locate_by_ipinfo

    grouped = defaultdict(list)
    failures = 0
    step = max(1, min(int(chunk_size), 64))
    for index in range(0, len(proxies), step):
        batch = [copy.deepcopy(p) for p in proxies[index:index + step]]
        try:
            results = batch_query(proxies=batch, func=locate_by_ipinfo,
                                  num_threads=max(1, min(int(num_threads), 32)),
                                  show_progress=False, description="地区查询", digits=3)
        except Exception:
            results = []
        for result in results or []:
            node = getattr(result, "proxy", None)
            info = getattr(result, "result", None)
            country = _code(getattr(info, "country", ""), ISO_TO_CHINESE)
            if (not getattr(result, "success", False) or not isinstance(node, dict)
                    or not country or getattr(info, "is_cdn", False)):
                continue
            clean = {key: value for key, value in node.items() if key not in META and not str(key).startswith("_")}
            if clean.get("server") and clean.get("port") and clean.get("type"):
                grouped[country].append(clean)
    output = []
    ordered_countries = sorted(grouped, key=lambda code: (ORDER.index(code) if code in ORDER else len(ORDER), code))
    for code in ordered_countries:
        name = ISO_TO_CHINESE[code]
        for index, node in enumerate(sorted(grouped[code], key=_fingerprint), 1):
            node["name"] = f"{_flag(code)} {name} {index:03d}"
            output.append(node)
    return output, {"checked": len(proxies), "kept": len(output), "unknown": len(proxies) - len(output)}
