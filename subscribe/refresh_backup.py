#!/usr/bin/env python3
"""Rolling missing-Refresh watchdog, resilient to delayed GitHub cron runs.

The independent backup cron is a *check*, never an unconditional full run.
A recent successful `process` job or any active Refresh prevents a backup.
Unlike the former fixed-window check, a late watchdog still checks for gaps.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import urllib.request

UTC = timezone.utc
RECENT = timedelta(hours=4)
ACTIVE_LIMIT = timedelta(hours=6)
ACTIVE = frozenset({"queued", "pending", "waiting", "in_progress", "requested"})


def parse_utc(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except (ValueError, TypeError, OverflowError):
        return None


def github_get(repo: str, token: str, endpoint: str) -> dict:
    request = urllib.request.Request(f"https://api.github.com/repos/{repo}{endpoint}", headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "aggregator-refresh-watchdog",
    })
    with urllib.request.urlopen(request, timeout=20) as resp:
        result = json.load(resp)
    if not isinstance(result, dict):
        raise ValueError("invalid GitHub API reply")
    return result


def github_runs(repo: str, token: str) -> list[dict]:
    data = github_get(repo, token, "/actions/workflows/refresh.yaml/runs?branch=main&per_page=100")
    runs = data.get("workflow_runs")
    if not isinstance(runs, list):
        raise ValueError("invalid GitHub runs data")
    return runs


def process_conclusion(repo: str, token: str, run_id: int) -> str:
    """Do not confuse a green schedule_guard-only workflow with collection."""
    data = github_get(repo, token, f"/actions/runs/{run_id}/jobs?per_page=100")
    jobs = data.get("jobs")
    if not isinstance(jobs, list) or not jobs:
        raise ValueError("missing GitHub job results")
    matches = [j for j in jobs if isinstance(j, dict) and j.get("name", "").split(" / ")[-1] == "process"]
    if not matches:
        raise ValueError("missing process job")
    return str(matches[-1].get("conclusion") or "unknown")


def should_dispatch_backup(runs: list[dict], now: datetime, job_result,
                           current_id: int | None = None) -> tuple[bool, str]:
    """Rolling check: no live process in four hours, or latest process failed.

    Calls `job_result(run_id)` to verify the actual process job. Missing job
    data is uncertainty and must stop the backup rather than guess.
    """
    if not isinstance(runs, list) or now.tzinfo is None:
        return False, "运行记录或时间无效"
    now = now.astimezone(UTC)
    recent = []
    for r in runs:
        if not isinstance(r, dict) or r.get("id") == current_id:
            continue
        if r.get("head_branch") != "main" or r.get("event") not in {"schedule", "workflow_dispatch"}:
            continue
        when = parse_utc(r.get("created_at"))
        if when is None or when > now:
            continue
        age = now - when
        if r.get("status") in ACTIVE and age < ACTIVE_LIMIT:
            return False, f"Refresh {r.get('id')} 正在运行或排队"
        if age <= RECENT:
            recent.append((when, r))
    recent.sort(key=lambda pair: pair[0], reverse=True)
    for _, r in recent:
        if r.get("status") in ACTIVE:
            return False, f"Refresh {r.get('id')} 状态尚未结束"
        if r.get("status") != "completed":
            return False, f"Refresh {r.get('id')} 状态不明确"
        state = job_result(r.get("id"))  # May throw: fail closed.
        if state == "skipped":
            continue
        if state == "success":
            return False, f"Refresh {r.get('id')} 已完成真正的采集"
        if state in {"failure", "cancelled", "timed_out"}:
            return True, f"Refresh {r.get('id')} 采集失败，需要补跑"
        return False, f"Refresh {r.get('id')} 采集状态无法确认"
    return True, "最近四小时没有成功执行的采集，允许补跑"


def dispatch(repo: str, token: str, moment: datetime) -> None:
    endpoint = f"https://api.github.com/repos/{repo}/actions/workflows/refresh.yaml/dispatches"
    payload = json.dumps({"ref": "main", "inputs": {
        # Only an internal backup marker; the dispatched job uses rolling state.
        "backup_slot": moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    }}).encode("utf-8")
    request = urllib.request.Request(endpoint, data=payload, method="POST", headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "aggregator-refresh-watchdog",
    })
    with urllib.request.urlopen(request, timeout=20) as resp:
        if resp.status not in (200, 201, 204):
            raise RuntimeError("Backup dispatch not accepted")


def main() -> None:
    repo = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GH_TOKEN"]
    now = datetime.now(UTC)
    runs = github_runs(repo, token)
    due, why = should_dispatch_backup(
        runs, now, lambda run_id: process_conclusion(repo, token, run_id)
    )
    if not due:
        print(f"备用检查：跳过；{why}")
        return
    dispatch(repo, token, now)
    print(f"备用检查：已请求一次补跑；{why}")


if __name__ == "__main__":
    main()
