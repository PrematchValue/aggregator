#!/usr/bin/env python3
"""Lightweight GitHub-only Refresh fallback: inspect the preceding primary slot.

No collection is run in this workflow. If the scheduled Refresh is absent or
finished unsuccessfully, dispatch a backup run through GitHub Actions.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import urllib.request

UTC = timezone.utc
PRIMARY_MINUTE = 17
PRIMARY_HOURS = 4
BACKUP_DELAY = timedelta(minutes=90)
ACTIVE = frozenset({"queued", "pending", "waiting", "in_progress", "requested"})


def parse_utc(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except (ValueError, TypeError, OverflowError):
        return None


def primary_slot_for_backup(now: datetime) -> datetime:
    """Most recent primary cron slot at least 90 minutes before *now* (UTC)."""
    threshold = now.astimezone(UTC) - BACKUP_DELAY
    slot = threshold.replace(hour=(threshold.hour // PRIMARY_HOURS) * PRIMARY_HOURS,
                             minute=PRIMARY_MINUTE, second=0, microsecond=0)
    if slot > threshold:
        slot -= timedelta(hours=PRIMARY_HOURS)
    return slot


def valid_slot(slot: datetime | None) -> bool:
    return bool(slot is not None and slot.utcoffset() == timedelta(0)
                and slot.minute == PRIMARY_MINUTE and slot.hour % PRIMARY_HOURS == 0
                and slot.second == 0 and slot.microsecond == 0)


def should_dispatch_backup(runs: list[dict], slot: datetime, now: datetime,
                           current_id: int | None = None) -> tuple[bool, str]:
    """Fail closed on uncertainty; never dispatch over another active Refresh.

    Success/active run created since the primary slot means the backup is not
    needed. An earlier active run also prevents concurrent full collections.
    A completed failure is retryable. The same check is rerun by the dispatched
    Refresh, after its concurrency lock has been acquired.
    """
    now = now.astimezone(UTC)
    if not valid_slot(slot) or not isinstance(runs, list):
        return False, "计划时段或运行记录无效"
    age = now - slot
    if age < BACKUP_DELAY:
        return False, "尚未到备用检查时间"
    if age >= timedelta(hours=PRIMARY_HOURS):
        return False, "备用检查已过期，交给下一轮正式计划"

    failures = []
    for entry in runs:
        if not isinstance(entry, dict) or entry.get("id") == current_id:
            continue
        if entry.get("head_branch") != "main" or entry.get("event") not in {"schedule", "workflow_dispatch"}:
            continue
        created = parse_utc(entry.get("created_at"))
        if created is None or created > now:
            continue
        status = entry.get("status")
        conclusion = entry.get("conclusion")
        rid = entry.get("id")
        if status in ACTIVE and now - created < timedelta(hours=6):
            return False, f"Refresh {rid} 正在运行或排队"
        if created < slot:
            continue
        if conclusion == "success":
            return False, f"Refresh {rid} 本时段已经成功"
        if status in ACTIVE:
            return False, f"Refresh {rid} 状态未结束，避免重叠"
        if status != "completed":
            return False, f"Refresh {rid} 状态不明确，避免重叠"
        failures.append(rid)
    if failures:
        return True, "本时段 Refresh 已失败，可补跑：" + ", ".join(map(str, failures[:4]))
    return True, "本时段未发现 Refresh，允许备用补跑"


def github_runs(repo: str, token: str) -> list[dict]:
    url = f"https://api.github.com/repos/{repo}/actions/workflows/refresh.yaml/runs?branch=main&per_page=100"
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "aggregator-conditional-backup",
    })
    with urllib.request.urlopen(request, timeout=20) as resp:
        data = json.load(resp)
    if not isinstance(data, dict) or not isinstance(data.get("workflow_runs"), list):
        raise ValueError("Invalid GitHub workflow runs response")
    return data["workflow_runs"]


def dispatch(repo: str, token: str, slot: datetime) -> None:
    endpoint = f"https://api.github.com/repos/{repo}/actions/workflows/refresh.yaml/dispatches"
    payload = json.dumps({"ref": "main", "inputs": {
        "backup_slot": slot.isoformat(timespec="seconds").replace("+00:00", "Z")
    }}).encode("utf-8")
    request = urllib.request.Request(endpoint, data=payload, method="POST", headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "aggregator-conditional-backup",
    })
    with urllib.request.urlopen(request, timeout=20) as resp:
        if resp.status not in (200, 201, 204):
            raise RuntimeError(f"Unexpected dispatch status: {resp.status}")


def main() -> None:
    repo = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GH_TOKEN"]
    now = datetime.now(UTC)
    slot = primary_slot_for_backup(now)
    # API failure is intentionally fatal: never assume a primary run is absent.
    runs = github_runs(repo, token)
    due, why = should_dispatch_backup(runs, slot, now)
    slot_label = slot.astimezone(timezone(timedelta(hours=8))).strftime("%m-%d %H:%M")
    if not due:
        print(f"备用检查｜北京时间 {slot_label}：跳过；{why}")
        return
    dispatch(repo, token, slot)
    print(f"备用检查｜北京时间 {slot_label}：已请求补跑；{why}")


if __name__ == "__main__":
    main()
