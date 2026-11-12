"""Read a small, explicitly-reviewed catalogue of public Clash YAML feeds.

Do not persist these URLs as private airport subscriptions: their transient
failure must not trigger the old-subscription expiry safeguard. Parsed nodes
remain subject to the aggregator's existing protocol validators and real
outbound checks before being published. Never infer egress from their names.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import urllib.parse
import urllib.request
from collections import Counter

import yaml

# Each URL was checked as an existing public Clash/Mihomo subscription on
# 2026-11-12. Review changes to this allowlist deliberately; do not crawl
# arbitrary proxy URLs supplied by a node or a third-party YAML.
SOURCES = (
    ("Au1rxx", "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml"),
    ("Zhuhai", "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/clash_config.yaml"),
    ("YYProxyPool", "https://raw.githubusercontent.com/yy1588133/proxy-pool/main/clash.yaml"),
    ("ShareDaily", "https://raw.githubusercontent.com/share-daily/node/main/clash.yaml"),
    ("NodesRadar", "https://radarhub.top/clash.yaml"),
)
MAX_BYTES = 8 * 1024 * 1024
MAX_PER_FEED = 4500
MAX_TOTAL = 12000
_HOST = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$", re.I)


class _HttpsAllowlistedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]):
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname not in self.allowed_hosts:
            raise ValueError("public feed redirected outside its allowlisted HTTPS host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str, timeout: int = 20) -> str:
    host = urllib.parse.urlsplit(url).hostname
    opener = urllib.request.build_opener(_HttpsAllowlistedRedirect({host}))
    req = urllib.request.Request(url, headers={"User-Agent": "aggregator-public-feeds/1", "Accept": "text/yaml, text/plain, */*"})
    with opener.open(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise ValueError("public feed HTTP response not 200")
        body = resp.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("public feed exceeds size limit")
    return body.decode("utf-8-sig", errors="strict")


def _safe_server(item: dict) -> bool:
    """Reject literal non-public addresses and obviously private hostnames."""
    server = str(item.get("server", "")).strip().strip("[]")
    if not server or any(char in server for char in ("/", "\\", "@", "?", "#", " ")):
        return False
    try:
        return ipaddress.ip_address(server).is_global
    except ValueError:
        lower = server.lower().rstrip(".")
        return (bool(_HOST.fullmatch(lower)) and not lower.endswith(
            (".local", ".localhost", ".internal", ".test", ".invalid", ".example")
        ))


def _connection_id(item: dict) -> str:
    # Name/source labels are not protocol credentials. Do not print this digest.
    value = {k: v for k, v in item.items() if k not in ("name", "sub", "liveness", "delay", "cdn", "renamed")}
    value["server"] = str(value.get("server", "")).lower().strip()
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def parse_feed(content: str, limit: int = MAX_PER_FEED) -> list[dict]:
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        raise ValueError("invalid public Clash YAML") from None
    proxies = doc.get("proxies") if isinstance(doc, dict) else None
    if not isinstance(proxies, list):
        raise ValueError("not a Clash YAML proxies list")
    result, seen = [], set()
    for item in proxies:
        if not isinstance(item, dict) or not _safe_server(item):
            continue
        if not isinstance(item.get("name"), str) or not item["name"].strip():
            continue
        if not isinstance(item.get("type"), str) or not item["type"].strip():
            continue
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        if not (1 <= port <= 65535):
            continue
        key = _connection_id(item)
        if key in seen:
            continue
        seen.add(key)
        copied = dict(item)
        copied.pop("sub", None)  # Never persist a remote feed's claimed subscription URL.
        result.append(copied)
        if len(result) >= max(1, limit):
            break
    return result


def gather_public_nodes(*, fetch=None, logger=None, limit: int = MAX_TOTAL, sources=SOURCES) -> tuple[list[dict], dict[str, int]]:
    """Failures are isolated per public feed; no fetch is allowed from node fields."""
    fetch = fetch or _download
    seen, nodes, counts = set(), [], Counter()
    for label, url in sources:
        if len(nodes) >= limit:
            break
        try:
            raw = fetch(url)
            parsed = parse_feed(raw, limit=min(MAX_PER_FEED, limit-len(nodes)))
        except Exception as exc:
            counts[label] = 0
            if logger:
                logger.warning(f"公开节点源 {label} 读取失败：{type(exc).__name__}，跳过该源")
            continue
        for item in parsed:
            key = _connection_id(item)
            if key in seen:
                continue
            seen.add(key)
            nodes.append(item)
            counts[label] += 1
        if logger:
            logger.info(f"公开节点源 {label}：读取={len(parsed)}，本轮新增去重节点={counts[label]}")
    return nodes, dict(counts)
