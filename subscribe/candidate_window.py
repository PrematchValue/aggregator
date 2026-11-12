"""Deterministic non-random weekly windows of discovered airport domains.

Unlike repeatedly sampling a different pseudorandom subset, consecutive
windows traverse a stable sorted catalogue before repeating. An explicit
COLLECT_WINDOW integer can select a window for manual additional runs.
"""
from __future__ import annotations

import hashlib
import math
import os
from datetime import date


def window_candidates(discovered: dict, budget: int, *, today: date | None = None, window: int | None = None):
    ordered = sorted(discovered.items(), key=lambda item: hashlib.sha256(item[0].encode("utf-8")).digest())
    n = len(ordered)
    if not n or budget <= 0 or budget >= n:
        return ordered, (0, 1)
    parts = math.ceil(n / budget)
    if window is None:
        override = os.environ.get("COLLECT_WINDOW", "").strip()
        if override.isdecimal():
            window = int(override)
        else:
            when = today or date.today()
            window = when.toordinal() // 7
    index = window % parts
    start = index * budget
    # Wrap around only when the last window holds fewer than budget entries;
    # coverage remains complete over each parts-week cycle.
    subset = (ordered[start:] + ordered[:start])[:budget]
    return subset, (index, parts)
