"""Isolate Mihomo listener startup failures without discarding healthy peers.

A Mihomo process with one bad outbound can fail for its ENTIRE batch.  A
missing per-node `_verified_http` marker means the per-node callback did not
run; it is NOT evidence that every proxy in the batch is dead.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any


def inspect_with_isolation(
    nodes: list[dict],
    probe: Callable[[list[dict]], list],
    identity: Callable[[dict], str],
) -> tuple[list, dict[str, int], set[str]]:
    """Return individually probed results, safe summary, and unprobed hashes.

    Split only a batch (or its unresolved subset) whose callback(s) did not
    execute. Actual HTTP failures have the marker set to False and are left
    for the ordinary second-round retry, not recursively split forever.
    """
    outputs: dict[str, Any] = {}
    expected = {identity(node) for node in nodes}
    attempts = 0
    splits = 0
    max_attempts = max(3, 3 * len(nodes) + 1)

    def visit(batch: list[dict]) -> None:
        nonlocal attempts, splits
        if not batch or attempts >= max_attempts:
            return
        attempts += 1
        try:
            results = probe(batch) or []
        except Exception:
            results = []
        for entry in results:
            candidate = getattr(entry, "proxy", None)
            if not isinstance(candidate, dict) or "_verified_http" not in candidate:
                continue
            key = identity(candidate)
            if key in expected:
                outputs[key] = entry
        missing = [node for node in batch if identity(node) not in outputs]
        if not missing or len(batch) == 1:
            return
        splits += 1
        if len(missing) < len(batch):
            # Some callbacks ran: only retry the subset that lacked a callback.
            visit(missing)
        else:
            pivot = len(missing) // 2
            visit(missing[:pivot])
            visit(missing[pivot:])

    visit(nodes)
    unprobed = expected - set(outputs)
    return list(outputs.values()), {"attempts": attempts, "splits": splits, "unprobed": len(unprobed)}, unprobed
