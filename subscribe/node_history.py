"""Recover previously *published and confirmed* nodes as retry candidates.

Failure to fetch a subscription must not erase its last confirmed nodes from
future testing. Prior nodes are ONLY candidates; they receive no automatic
pass and may be published again solely after real egress validation.
"""
from __future__ import annotations

import copy
import yaml

from node_labels import LABEL_RE


def previous_confirmed_candidates(content: str, max_nodes: int = 20000) -> list[dict]:
    if not isinstance(content, str) or not content.strip():
        return []
    try:
        document = yaml.safe_load(content)
    except (yaml.YAMLError, TypeError, ValueError):
        return []
    rows = document.get("proxies", []) if isinstance(document, dict) else []
    if not isinstance(rows, list):
        return []
    results = []
    for node in rows:
        if isinstance(node, dict) and LABEL_RE.fullmatch(str(node.get("name", ""))):
            # Do not trust ephemeral runtime health markers from old artifacts.
            result = copy.deepcopy(node)
            result.pop("_verified_http", None)
            results.append(result)
        if len(results) >= max_nodes:
            break
    return results
