"""Conservative publication checks for Collect/Refresh; never log subscription bodies."""

import base64
import copy
import ipaddress
import json
import re
import socket
import urllib.parse
import urllib.request

import yaml
from outbound import verify


class PublicationError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PublicationError("unexpected redirect while reading publication baseline")


def read_gist(gist_id, token):
    """Authenticated, uncached snapshot; unreadable is different from empty."""
    if not re.fullmatch(r"[a-fA-F0-9]+", gist_id):
        raise PublicationError("invalid gist id")
    opener = urllib.request.build_opener(NoRedirect())

    def read(url, headers):
        try:
            request = urllib.request.Request(url, headers=headers)
            with opener.open(request, timeout=30) as response:
                body = response.read(16 * 1024 * 1024 + 1)
            if len(body) > 16 * 1024 * 1024:
                raise ValueError("oversized response")
            return body.decode("utf-8")
        except Exception:
            raise PublicationError("cannot read complete gist baseline; keeping previous publication") from None

    try:
        snapshot = json.loads(read(f"https://api.github.com/gists/{gist_id}", {
            "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
            "User-Agent": "aggregator", "Cache-Control": "no-cache",
        }))
        files = {}
        for name, entry in snapshot["files"].items():
            content = entry.get("content")
            if entry.get("truncated"):
                url = entry.get("raw_url", "")
                parsed = urllib.parse.urlsplit(url)
                if parsed.scheme != "https" or parsed.netloc != "gist.githubusercontent.com":
                    raise ValueError("unexpected raw host")
                content = read(url, {"User-Agent": "aggregator"})
            if not isinstance(content, str):
                raise ValueError("missing file content")
            files[name] = content
        return snapshot["updated_at"], files
    except PublicationError:
        raise
    except Exception:
        raise PublicationError("invalid gist baseline; keeping previous publication") from None


def subscription_urls(content):
    return set(re.findall(r"^https?://[^\s]+", content, flags=re.M))


def valid_nodes(nodes):
    """Reuse protocol validators on copies; built-in routes are not proxy nodes."""
    result = []
    for node in nodes:
        if not isinstance(node, dict) or not node.get("server"):
            continue
        item = copy.deepcopy(node)
        if verify(item, True):
            result.append(item)
    return result


def artifact_count(content, target):
    """Validate the supported default formats, including decoded URI subscriptions."""
    if not isinstance(content, str) or not content.strip():
        raise PublicationError("empty converted artifact")
    try:
        if "clash" in target:
            nodes = yaml.safe_load(content)["proxies"]
            if not isinstance(nodes, list) or len(valid_nodes(nodes)) != len(nodes):
                raise ValueError("invalid nodes")
            count = len(nodes)
        elif target == "singbox":
            data = json.loads(content)
            nodes = data if isinstance(data, list) else data["outbounds"]
            if not isinstance(nodes, list):
                raise ValueError("invalid outbounds")
            count = sum(isinstance(x, dict) and bool(x.get("server")) and bool(x.get("type")) for x in nodes)
        elif target in ("v2ray", "mixed"):
            text = content.strip()
            if "://" not in text:
                encoded = "".join(text.split())
                text = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True).decode("utf-8")
            lines = [x.strip() for x in text.splitlines() if x.strip()]
            if not all(re.match(r"(?:ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic|snell|socks5?|https?|anytls)://\S+$", x) for x in lines):
                raise ValueError("invalid URI subscription")
            count = len(lines)
        elif target.startswith("surge"):
            # Full profiles contain other sections; list-only output has none.
            section, count = "proxy", 0
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1].lower()
                elif section == "proxy" and re.match(
                    r"[^#;=]+\s*=\s*(?:ss|ssr|vmess|trojan|https?|socks5(?:-tls)?|snell|tuic|hysteria2|wireguard)\s*,\s*\S+",
                    line, re.I,
                ):
                    count += 1
        else:
            if content.lstrip().startswith(("<", "{")):
                raise ValueError("unexpected error document")
            count = 1
        if count < 1:
            raise ValueError("no nodes")
        return count
    except Exception:
        raise PublicationError(f"invalid or empty converted artifact: {target}") from None


def check_publication(artifacts, previous, urls, *, allow_public_only=False):
    """Only validate publishing prerequisites and artifact integrity.

    Deliberately do not compare with old source or node counts: every Collect
    and Refresh publishes the nodes that actually passed the current checks.
    """
    if not urls and not allow_public_only:
        raise PublicationError("no successful source subscriptions; cannot publish")
    for _, (target, content) in artifacts.items():
        artifact_count(content, target)


def tcp_probe(node):
    """Advisory only. Pin public DNS answers, never connect to local/private IPs."""
    if node.get("type") not in {"ss", "ssr", "vmess", "vless", "trojan", "http", "socks5", "anytls", "snell"}:
        return "skipped"
    try:
        addresses = socket.getaddrinfo(node["server"], int(node["port"]), type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(x[4][0]).is_global for x in addresses):
            return "skipped"
        for family, kind, proto, _, address in addresses[:2]:
            try:
                with socket.socket(family, kind, proto) as connection:
                    connection.settimeout(2)
                    connection.connect(address)
                return "reachable"
            except OSError:
                continue
    except Exception:
        pass
    return "unknown"
