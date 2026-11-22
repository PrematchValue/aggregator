"""One shared recheck for externally dispatched Refresh recovery.

Cloudflare may dispatch refresh.yaml with backup_slot; the scheduled GitHub
backup workflow is removed. No second cron or dispatch engine lives here.
The actual `process` job, not a green schedule_guard, proves success.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
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
        "User-Agent": "aggregator-refresh-guard",
    })
    with urllib.request.urlopen(request, timeout=20) as resp:
        result = json.load(resp)
    if not isinstance(result, dict):
        raise ValueError("invalid GitHub API reply")
    return result


def process_conclusion(repo: str, token: str, run_id: int) -> str:
    data = github_get(repo, token, f"/actions/runs/{run_id}/jobs?per_page=100")
    jobs = data.get("jobs")
    if not isinstance(jobs, list) or not jobs:
        raise ValueError("missing GitHub job results")
    matches = [j for j in jobs if isinstance(j, dict)
               and j.get("name", "").split(" / ")[-1] == "process"]
    if not matches:
        raise ValueError("missing process job")
    return str(matches[-1].get("conclusion") or "unknown")


def should_dispatch_backup(runs: list[dict], now: datetime, job_result,
                           current_id: int | None = None) -> tuple[bool, str]:
    """Fail closed on unclear status; reject duplicates and active refreshes."""
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
        state = job_result(r.get("id"))
        if state == "skipped":
            continue
        if state == "success":
            return False, f"Refresh {r.get('id')} 已完成真正的采集"
        if state in {"failure", "cancelled", "timed_out"}:
            return True, f"Refresh {r.get('id')} 采集失败，需要补跑"
        return False, f"Refresh {r.get('id')} 采集状态无法确认"
    return True, "最近四小时没有成功执行的采集，允许补跑"
