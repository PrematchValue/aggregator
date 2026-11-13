"""Persist only recently verified nodes and stage independent collection runs.

Historical nodes are always rechecked with the current run before publication.
"""
from __future__ import annotations
import json
from pathlib import Path

import collect_safety as safety
from node_history import previous_confirmed_candidates
from node_labels import identity

POOL_FILE = "node-pool.json"
MAX_BYTES = 16 * 1024 * 1024
MAX_NODES = 50000


def merge_nodes(*groups: list[dict]) -> list[dict]:
    """Dedupe by transport parameters, preferring the newest appearance."""
    merged = {}
    for group in groups:
        for node in safety.valid_nodes(group):
            node.pop("_verified_http", None)
            merged[identity(node)] = node
    return list(merged.values())


def previous_candidates(files: dict[str, str]) -> list[dict]:
    """Read dedicated pool or bootstrap from existing flag-confirmed Clash file."""
    content = files.get(POOL_FILE, "")
    if not content:
        return merge_nodes(previous_confirmed_candidates(files.get("clash.yaml", "")))
    try:
        if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_BYTES:
            raise ValueError("bad pool size")
        payload = json.loads(content)
        if (not isinstance(payload, dict) or payload.get("v") != 1
                or not isinstance(payload.get("nodes"), list)
                or len(payload["nodes"]) > MAX_NODES):
            raise ValueError("bad pool format")
        rows = payload["nodes"]
        valid = safety.valid_nodes(rows)
        if len(valid) != len(rows):
            raise ValueError("bad pool proxy")
        return merge_nodes(valid)
    except (ValueError, TypeError, KeyError):
        raise safety.PublicationError("invalid node pool; refusing to discard history") from None


def encode_pool(nodes: list[dict]) -> str:
    cleaned = merge_nodes(nodes)
    if not cleaned or len(cleaned) > MAX_NODES:
        raise safety.PublicationError("invalid verified node pool size")
    content = json.dumps({"v": 1, "nodes": cleaned}, ensure_ascii=False, separators=(",", ":"))
    if len(content.encode("utf-8")) > MAX_BYTES:
        raise safety.PublicationError("verified pool exceeds safe size")
    return content


def write_stage(path: str, nodes: list[dict], subscriptions: set[str], rotation: str = "") -> None:
    payload = {"v": 1, "nodes": merge_nodes(nodes),
               "subscriptions": sorted(subscriptions), "rotation": rotation}
    content = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if len(content.encode("utf-8")) > MAX_BYTES:
        raise safety.PublicationError("collection stage too large")
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")


def read_stage(path: str) -> dict:
    try:
        source = Path(path)
        if source.stat().st_size > MAX_BYTES:
            raise ValueError("oversized stage")
        payload = json.loads(source.read_text(encoding="utf-8"))
        if (not isinstance(payload, dict) or payload.get("v") != 1
                or not isinstance(payload.get("nodes"), list)
                or len(payload["nodes"]) > MAX_NODES
                or not isinstance(payload.get("subscriptions"), list)
                or any(not isinstance(x, str) for x in payload["subscriptions"])
                or not isinstance(payload.get("rotation"), str)):
            raise ValueError("invalid stage")
        rows = payload["nodes"]
        if len(safety.valid_nodes(rows)) != len(rows):
            raise ValueError("invalid staged proxy")
        payload["nodes"] = merge_nodes(rows)
        return payload
    except (OSError, ValueError, TypeError, KeyError):
        raise safety.PublicationError("cannot read complete collection stage") from None


def merge_rotation(current: str, staged: str) -> str:
    """Never undo the progress of a more recent Refresh cycle."""
    from refresh_rotation import RefreshRotation
    if not staged:
        return ""
    try:
        latest = RefreshRotation.load(current)
        incoming = RefreshRotation.load(staged)
        if latest.cycle > incoming.cycle:
            return latest.encode()
        if latest.cycle == incoming.cycle:
            incoming.done.update(latest.done)
        return incoming.encode()
    except (ValueError, TypeError):
        raise safety.PublicationError("invalid Refresh rotation metadata") from None
