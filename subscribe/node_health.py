"""Actual HTTPS-over-proxy checks through Mihomo node listeners (not TCP ping).

All destinations are constant public HTTPS test URLs. HTTP 204 response or
strict Cloudflare trace with a global public exit IP counts as success.
This proves reachability from the GitHub runner, NOT from mainland China.
"""
from __future__ import annotations

import ipaddress
import re
import ssl
import socket

TESTS = (
    ("https://cp.cloudflare.com/generate_204", 204),
    ("https://www.gstatic.com/generate_204", 204),
    ("https://www.google.com/generate_204", 204),
    ("https://www.cloudflare.com/cdn-cgi/trace", 200),
)


def _valid_trace(body: bytes) -> bool:
    if not isinstance(body, bytes) or len(body) > 8192:
        return False
    try:
        content = body.decode("utf-8")
    except UnicodeDecodeError:
        return False
    matched = re.search(r"(?m)^ip=([0-9.]+)\s*$", content)
    if not matched:
        return False
    try:
        return ipaddress.ip_address(matched.group(1)).is_global
    except ValueError:
        return False


def classify_failure(error: Exception) -> str:
    if isinstance(error, (TimeoutError, socket.timeout)):
        return "超时"
    if isinstance(error, ssl.SSLError):
        return "TLS握手失败"
    if isinstance(error, (ConnectionRefusedError, ConnectionResetError, BrokenPipeError)):
        return "连接被拒绝或重置"
    text = str(error).lower()
    if any(word in text for word in ("timeout", "timed out", "deadline")):
        return "超时"
    if any(word in text for word in ("handshake", "tls", "certificate", "ssl")):
        return "TLS握手失败"
    if any(word in text for word in ("resolve", "no such host", "dns")):
        return "DNS失败"
    return "请求失败"


def check_http(port: int, *, request=None) -> tuple[bool, str]:
    """Two rounds, independent services, progressively longer timeouts.

    `request` has same signature as location._request_through_proxy.
    """
    if not port:
        return False, "代理监听端口缺失"
    if request is None:
        from location import _request_through_proxy
        request = _request_through_proxy
    failures = []
    for index, (url, expected_status) in enumerate(TESTS):
        # First 2 checks use shorter timeouts. Last 2 are a deliberate retry.
        timeout = 5 if index < 2 else 9
        try:
            status, body = request(port=port, url=url,
                                   headers={"User-Agent": "aggregator-http-probe/1"},
                                   timeout=timeout, redirects=0)
            if status == expected_status and (status == 204 or _valid_trace(body)):
                return True, "HTTPS请求成功"
            failures.append("HTTP响应异常")
        except Exception as error:
            failures.append(classify_failure(error))
    # Severity: if some targets responded but none was a known test result,
    # don't declare the node alive merely on arbitrary HTTP 200 status.
    for kind in ("TLS握手失败", "连接被拒绝或重置", "超时", "DNS失败", "HTTP响应异常"):
        if kind in failures:
            return False, kind
    return False, "请求失败"
