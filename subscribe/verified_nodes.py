"""One rolling snapshot of verified nodes; no permanent node pool or rotation.

The existing Gist is the sole persistence store. Every new Refresh merges the
last verified snapshot with newly acquired nodes and subjects both to the
original Mihomo liveness and exit-country checks.
"""
from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request

import yaml

SNAPSHOT = "verified-nodes.json"
META = frozenset({"name", "sub", "liveness", "cdn", "renamed", "delay", "_region", "_verified_http"})
MAX_BYTES = 24 * 1024 * 1024
MAX_NODES = 30000


def _identity(node: dict) -> str:
    clean = {str(k): v for k, v in node.items()
             if k not in META and not str(k).startswith("_")}
    encoded = json.dumps(clean, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _valid(node: object) -> bool:
    return (isinstance(node, dict) and isinstance(node.get("server"), str)
            and bool(node["server"].strip()) and bool(node.get("port"))
            and isinstance(node.get("type"), str) and bool(node["type"].strip()))


def merge_candidates(fresh: list[dict], old: list[dict]) -> tuple[list[dict], int]:
    """Prefer fresh settings over history and deduplicate regardless of label."""
    output, seen = [], set()
    added_old = 0
    for from_old, collection in ((False, fresh), (True, old)):
        for entry in collection:
            if not _valid(entry):
                continue
            identity = _identity(entry)
            if identity in seen:
                continue
            seen.add(identity)
            node = dict(entry)
            if from_old:
                # A snapshot never owns a subscription URL or run-time flags.
                node = {key: value for key, value in node.items()
                        if key not in ("sub", "liveness", "cdn", "renamed", "delay")
                        and not str(key).startswith("_")}
                node["name"] = node.get("name") or f"历史节点 {identity[:12]}"
                added_old += 1
            output.append(node)
    return output, added_old


def snapshot_content(nodes: list[dict]) -> str:
    """Only publish nodes that passed liveness AND egress validation."""
    clean, seen = [], set()
    for node in nodes:
        if not _valid(node):
            continue
        identity = _identity(node)
        if identity in seen:
            continue
        seen.add(identity)
        clean.append({key: value for key, value in node.items()
                      if key not in ("sub", "liveness", "cdn", "renamed", "delay")
                      and not str(key).startswith("_")})
    return json.dumps({"version": 1, "nodes": clean}, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")) + "\n"


def _read_url(url: str, token: str = "") -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {"api.github.com", "gist.githubusercontent.com"}:
        raise ValueError("Unexpected Gist host")
    headers = {"User-Agent": "aggregator-verified-nodes", "Accept": "application/vnd.github+json"}
    if token and parsed.hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("Previous Gist content exceeds safety limit")
    return body.decode("utf-8")


def _file_content(item: dict) -> str:
    if not item.get("truncated") and isinstance(item.get("content"), str):
        return item["content"]
    url = item.get("raw_url")
    if not isinstance(url, str):
        raise ValueError("Truncated Gist file has no raw URL")
    return _read_url(url)


def load_verified_nodes(gist_id: str, token: str) -> list[dict]:
    """Load last snapshot; bootstrap from existing Clash profile once.

    Network/malformed-data failures propagate so a fresh run cannot silently
    discard prior good nodes. First run with no existing snapshot is normal.
    """
    if not gist_id or not token:
        return []
    # Gist IDs are hexadecimal; avoid injecting paths into the API URL.
    if not all(c in "0123456789abcdefABCDEF" for c in gist_id):
        raise ValueError("Invalid Gist ID")
    gist = json.loads(_read_url(f"https://api.github.com/gists/{gist_id}", token))
    files = gist.get("files")
    if not isinstance(files, dict):
        raise ValueError("Malformed Gist response")
    history = files.get(SNAPSHOT)
    if isinstance(history, dict):
        payload = json.loads(_file_content(history))
        if not isinstance(payload, dict) or payload.get("version") != 1:
            raise ValueError("Invalid verified node snapshot version")
        nodes = payload.get("nodes")
    elif isinstance(files.get("clash.yaml"), dict):
        # Only for migration from the upstream-first build. Not a second pool.
        profile = yaml.safe_load(_file_content(files["clash.yaml"]))
        if not isinstance(profile, dict):
            raise ValueError("Malformed existing Clash profile")
        nodes = profile.get("proxies", [])
    else:
        return []
    if not isinstance(nodes, list) or len(nodes) > MAX_NODES:
        raise ValueError("Invalid verified node collection")
    return [dict(n) for n in nodes if _valid(n)]
