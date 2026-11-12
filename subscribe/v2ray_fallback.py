"""Generate conservative share URIs when legacy subconverter returns empty v2rayN.

This is deliberately a *fallback*, not a replacement for an existing successful
conversion. It will never guess missing authentication or fabricate node data.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from collections import Counter


SUPPORTED = frozenset({"hysteria2", "hy2", "tuic", "ss", "trojan", "vless", "vmess"})


def _q(value: object) -> str:
    return urllib.parse.quote(str(value), safe="")


def _host(value: object) -> str:
    hostname = str(value or "").strip()
    if not hostname or any(char in hostname for char in "@/?#\\\n\r "):
        raise ValueError("invalid hostname")
    if ":" in hostname and not (hostname.startswith("[") and hostname.endswith("]")):
        # IPv6 literal, not an address with a user-supplied port.
        hostname = f"[{hostname}]"
    return hostname


def _port(node: dict) -> str:
    value = node.get("port")
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("invalid port") from None
    if port <= 0 or port > 65535:
        raise ValueError("invalid port")
    return str(port)


def _nonempty(node: dict, key: str) -> str:
    value = str(node.get(key, "")).strip()
    if not value:
        raise ValueError(f"missing {key}")
    return value


def _param(query: dict[str, str], key: str, value: object) -> None:
    if value is not None and str(value) != "":
        query[key] = str(value)


def _tls_query(node: dict, query: dict[str, str], *, insecure_key: str = "insecure") -> None:
    _param(query, "sni", node.get("sni") or node.get("servername") or node.get("server-name"))
    if node.get("skip-cert-verify") is True:
        query[insecure_key] = "1"
    if isinstance(node.get("alpn"), list) and node["alpn"]:
        query["alpn"] = ",".join(str(x) for x in node["alpn"])


def _query_string(query: dict[str, str]) -> str:
    return "?" + urllib.parse.urlencode(query, quote_via=urllib.parse.quote) if query else ""


def _transport(node: dict, query: dict[str, str]) -> None:
    network = str(node.get("network", "tcp")).lower()
    if network not in ("tcp", "ws", "grpc", "http", "h2"):
        raise ValueError("unsupported transport")
    if network != "tcp":
        query["type"] = network
    if network == "ws":
        opts = node.get("ws-opts") or {}
        if not isinstance(opts, dict):
            raise ValueError("bad websocket settings")
        _param(query, "path", opts.get("path"))
        headers = opts.get("headers") or {}
        if isinstance(headers, dict):
            _param(query, "host", headers.get("Host") or headers.get("host"))
    if network == "grpc":
        opts = node.get("grpc-opts") or {}
        if not isinstance(opts, dict):
            raise ValueError("bad grpc settings")
        _param(query, "serviceName", opts.get("grpc-service-name") or opts.get("serviceName"))
    if network in ("http", "h2"):
        opts = node.get("http-opts") or node.get("h2-opts") or {}
        if isinstance(opts, dict):
            _param(query, "path", opts.get("path"))
            host = opts.get("host")
            if isinstance(host, list):
                host = host[0] if host else ""
            _param(query, "host", host)


def make_uri(node: dict) -> str:
    """Create a standard URI for a supported, well-formed proxy. Else raise.

    Caller only uses this when the original converter returns an empty artifact.
    """
    if not isinstance(node, dict):
        raise ValueError("not a proxy")
    kind = str(node.get("type", "")).lower()
    if kind not in SUPPORTED:
        raise ValueError("unsupported protocol")
    name = _q(_nonempty(node, "name"))
    server = _host(node.get("server"))
    port = _port(node)
    address = f"{server}:{port}"
    query: dict[str, str] = {}

    if kind in ("hysteria2", "hy2"):
        # Hysteria 2 official URI scheme: https://www.hy2.app/docs/developers/URI-Scheme/
        auth = _q(_nonempty(node, "password"))
        _tls_query(node, query)
        opts = node.get("obfs")
        if isinstance(opts, str):
            _param(query, "obfs", opts)
            _param(query, "obfs-password", node.get("obfs-password"))
        elif isinstance(opts, dict):
            _param(query, "obfs", opts.get("type"))
            _param(query, "obfs-password", opts.get("password"))
        if node.get("ports"):
            # Hysteria2 multi-port address supports `:443,5000-6000`.
            hops = str(node["ports"])
            if any(x not in "0123456789,-" for x in hops):
                raise ValueError("invalid hopping ports")
            address = f"{server}:{hops}"
        _param(query, "pinSHA256", node.get("pinSHA256"))
        return f"hysteria2://{auth}@{address}/{_query_string(query)}#{name}"

    if kind == "tuic":
        user = _q(_nonempty(node, "uuid"))
        password = _q(_nonempty(node, "password"))
        _tls_query(node, query)
        _param(query, "congestion_control", node.get("congestion-controller") or node.get("congestion_control"))
        _param(query, "udp_relay_mode", node.get("udp-relay-mode") or node.get("udp_relay_mode"))
        if node.get("disable-sni") is True:
            query["disable_sni"] = "1"
        return f"tuic://{user}:{password}@{address}/{_query_string(query)}#{name}"

    if kind == "ss":
        if node.get("plugin"):
            # Plugins need precise plugin options; never emit a deceptive plain-SS link.
            raise ValueError("unsupported shadowsocks plugin")
        method = _nonempty(node, "cipher")
        password = _nonempty(node, "password")
        credentials = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return f"ss://{credentials}@{address}#{name}"

    if kind == "trojan":
        auth = _q(_nonempty(node, "password"))
        query["security"] = "tls" if node.get("tls", True) is not False else "none"
        _tls_query(node, query)
        _transport(node, query)
        return f"trojan://{auth}@{address}{_query_string(query)}#{name}"

    if kind == "vless":
        auth = _q(_nonempty(node, "uuid"))
        query["encryption"] = str(node.get("encryption") or "none")
        reality = node.get("reality-opts") or {}
        if not isinstance(reality, dict):
            raise ValueError("invalid reality config")
        query["security"] = "reality" if reality else ("tls" if node.get("tls") else "none")
        _tls_query(node, query)
        _param(query, "flow", node.get("flow"))
        _param(query, "fp", node.get("client-fingerprint"))
        if reality:
            _param(query, "pbk", reality.get("public-key"))
            _param(query, "sid", reality.get("short-id"))
            if not query.get("pbk"):
                raise ValueError("missing reality public key")
        _transport(node, query)
        return f"vless://{auth}@{address}{_query_string(query)}#{name}"

    if kind == "vmess":
        opts = node.get("ws-opts") if str(node.get("network", "tcp")).lower() == "ws" else {}
        if not isinstance(opts or {}, dict):
            raise ValueError("invalid vmess transport")
        _transport(node, query)
        record = {
            "v": "2", "ps": str(node["name"]), "add": str(node["server"]),
            "port": port, "id": _nonempty(node, "uuid"),
            "aid": str(node.get("alterId", node.get("alter-id", 0))),
            "scy": str(node.get("cipher", "auto")),
            "net": str(node.get("network") or "tcp"),
            "type": "none", "host": query.get("host", ""),
            "path": query.get("path", ""),
            "tls": "tls" if node.get("tls") else "",
            "sni": str(node.get("servername") or node.get("sni") or ""),
        }
        encoded = base64.urlsafe_b64encode(json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode()).decode().rstrip("=")
        return "vmess://" + encoded

    raise ValueError("unsupported protocol")


def build_subscription(nodes: list[dict]) -> tuple[str, dict[str, int]]:
    """Return traditional base64 v2rayN subscription, with safe type-only counts.

    Explicitly reject empty output: never fabricate a dummy node.
    """
    lines: list[str] = []
    skipped = Counter()
    for proxy in nodes:
        try:
            lines.append(make_uri(proxy))
        except (ValueError, TypeError, KeyError):
            kind = str(proxy.get("type", "unknown")) if isinstance(proxy, dict) else "unknown"
            skipped[kind] += 1
    if not lines:
        raise ValueError("no supported proxy URI can be safely encoded")
    text = "\n".join(lines) + "\n"
    return base64.b64encode(text.encode("utf-8")).decode("ascii"), dict(skipped)
