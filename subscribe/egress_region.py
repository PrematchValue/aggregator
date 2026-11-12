"""Conservative, protocol-independent proxy *egress* geolocation.

All IP-echo requests run THROUGH the Mihomo per-node listener.  Only the IP
thus observed may be geolocated directly from the Actions runner.  Never use
an entry-server IP, original node name, or guessed region as location proof.
"""

from __future__ import annotations

import hashlib
from collections import Counter
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request

# Distinct JSON providers through the proxy, with a bounded request budget.
# Several of them can refuse a given exit IP; don't randomly pick the same
# unavailable provider three times like the old locate_by_ipinfo did.
PROXY_GEO_TRIES = 5
PROXY_TIMEOUT = 10
ECHO_TIMEOUT = 10
DIRECT_TIMEOUT = 6
ECHO_URLS = (
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://api.ipify.org",
    "https://ipinfo.io/ip",
    "https://ipv4.icanhazip.com",
    "https://api-ipv4.ip.sb/ip",
    "https://api4.ipify.org",
)
DIRECT_GEO_ENDPOINTS = (
    ("https://ipwho.is/", ""),
    ("https://ipapi.co/", "/json/"),
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _public_ip(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        addr = ipaddress.ip_address(value.strip())
        return str(addr) if addr.is_global else ""
    except (ValueError, TypeError):
        return ""


def _parse_echo(data: object) -> str:
    """Read only explicit IP fields or plain-IP responses; never scrape arbitrary text."""
    if isinstance(data, dict):
        for key in ("ip", "origin", "address", "query"):
            ip = _public_ip(data.get(key))
            if ip:
                return ip
        return ""
    if not isinstance(data, str):
        return ""
    value = data.strip()
    direct = _public_ip(value)
    if direct:
        return direct
    try:
        obj = json.loads(value)
        if isinstance(obj, dict):
            return _parse_echo(obj)
    except (ValueError, TypeError):
        pass
    for line in value.splitlines():
        if line.startswith("ip="):
            return _public_ip(line[3:])
    return ""


def _code(data: object, key: str, countries: dict[str, str]) -> str:
    if not isinstance(data, dict) or data.get("success") is False or data.get("error") is True:
        return ""
    raw = data.get(key)
    if not isinstance(raw, str):
        return ""
    code = raw.strip().upper()
    return code if re.fullmatch(r"[A-Z]{2}", code) and code in countries else ""


def _fetch_ip_region(ip: str, countries: dict[str, str], *, fetch=None) -> str:
    """Query fixed, HTTPS-only services for a public IP observed via a proxy."""
    ip = _public_ip(ip)
    if not ip:
        return ""
    if fetch is None:
        fetch = _fetch_json
    for prefix, suffix in DIRECT_GEO_ENDPOINTS:
        # ip is a validated address, escaped as a URL path segment.
        url = prefix + urllib.parse.quote(ip, safe="") + suffix
        try:
            response = fetch(url)
        except Exception:
            continue
        for key in ("country_code", "countryCode", "country"):
            code = _code(response, key, countries)
            if code:
                return code
    return ""


def _fetch_json(url: str) -> dict:
    # Only URLs built by _fetch_ip_region can reach this method.
    request = urllib.request.Request(
        url, headers={"User-Agent": "aggregator-egress-region/1", "Accept": "application/json"}
    )
    with urllib.request.build_opener(_NoRedirect()).open(request, timeout=DIRECT_TIMEOUT) as response:
        if response.status != 200:
            return {}
        body = response.read(16385)
    if len(body) > 16384:
        return {}
    data = json.loads(body.decode("utf-8"))
    return data if isinstance(data, dict) else {}


def query_country(proxy: dict, port: int, *, request, services, countries, direct_fetch=None) -> tuple[str, str]:
    """Return (verified country ISO code, failure category) without guessing.

    `request` is location.make_proxy_request, always routed via the selected
    node's 127.0.0.1 Mihomo HTTP listener, never directly via the runner.
    """
    if not port:
        return "", "missing_listener"
    seed = f"{proxy.get('type', '')}:{proxy.get('server', '')}:{proxy.get('port', '')}"
    offset = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16)
    rotated = list(services)
    if rotated:
        offset %= len(rotated)
        rotated = rotated[offset:] + rotated[:offset]
    had_http_reply = False
    for service in rotated[:PROXY_GEO_TRIES]:
        try:
            ok, payload = request(
                port=port, url=service["url"], timeout=PROXY_TIMEOUT,
                max_retries=1, quiet=True,
            )
        except Exception:
            continue
        if not ok:
            continue
        had_http_reply = True
        code = _code(payload, service["country_key"], countries)
        if code:
            return code, "proxy_geo"

    ip = ""
    for url in ECHO_URLS:
        try:
            ok, data = request(
                port=port, url=url, timeout=ECHO_TIMEOUT,
                max_retries=1, deserialize=False, quiet=True,
            )
        except Exception:
            continue
        if ok:
            had_http_reply = True
            ip = _parse_echo(data)
            if ip:
                break
    if ip:
        code = _fetch_ip_region(ip, countries, fetch=direct_fetch)
        if code:
            return code, "egress_ip_geo"
        return "", "egress_ip_geo_unavailable"
    if had_http_reply:
        return "", "proxy_geo_unavailable"
    return "", "proxy_requests_failed"


def locate_with_fallback(proxy: dict, port: int):
    """Plug into location.batch_query without modifying its protocol handling."""
    from location import (
        ISO_TO_CHINESE, LOCATION_API_SERVICES,
        ProxyInfo, ProxyQueryResult, make_proxy_request,
    )
    from logger import logger

    code, source = query_country(
        proxy, port, request=make_proxy_request,
        services=LOCATION_API_SERVICES, countries=ISO_TO_CHINESE,
    )
    country = ISO_TO_CHINESE.get(code, "")
    # Real per-node HTTPS requests: independent 204 targets, two rounds,
    # 5s then 9s timeouts. Geo success itself also proves live HTTP.
    from node_health import check_http
    http_ok, http_reason = check_http(port)
    proxy["_verified_http"] = bool(http_ok or country)
    if not country:
        logger.warning(
            f"出口地区未确认：协议={str(proxy.get('type', 'unknown')).lower()}，"
            f"原因={source}，HTTPS实测={http_reason}；不按入口 IP 或节点名猜测"
        )
    return ProxyQueryResult(
        proxy=proxy,
        result=ProxyInfo(name=str(proxy.get("name", "")), country=country, provider=source),
        success=bool(country),
    )


def format_protocol_summary(original: list[str], retained: list[str]) -> str:
    """Compact, credential-free protocol counts for the Collect/Refresh log."""
    original_counts = Counter(str(t or "unknown").lower() for t in original)
    retained_counts = Counter(str(t or "unknown").lower() for t in retained)
    return "；".join(
        f"{kind}: 原始={original_counts[kind]}，保留={retained_counts[kind]}，"
        f"地区未确认={max(0, original_counts[kind] - retained_counts[kind])}"
        for kind in sorted(original_counts)
    ) or "无节点"
