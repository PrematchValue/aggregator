#!/usr/bin/env python3
"""Idempotency gate for primary Refresh and conditional standby retries.

A user-initiated Refresh always runs. Scheduled Refresh skips overlapping
work. Internally dispatched standby jobs recheck the primary slot before
starting collection; a status lookup failure suppresses standby only.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import urllib.request

from refresh_backup import parse_utc, should_dispatch_backup

RECENT_START_SECONDS = 115 * 60
RECENT_FINISH_SECONDS = 20 * 60
ACTIVE = {"queued", "pending", "waiting", "in_progress", "requested"}


def parsed_time(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (AttributeError, ValueError, TypeError):
        return None


def should_start(event: str, runs: list[dict], current_id: int, now=None) -> tuple[bool, str]:
    if event != "schedule":
        return True, "manual trigger always executes"
    now = now or datetime.now(timezone.utc)
    for entry in runs:
        if not isinstance(entry, dict) or entry.get("id") == current_id:
            continue
        if entry.get("head_branch") != "main" or entry.get("event") not in {"schedule", "workflow_dispatch"}:
            continue
        created, finished = parsed_time(entry.get("created_at")), parsed_time(entry.get("updated_at"))
        status, conclusion = entry.get("status"), entry.get("conclusion")
        if not created:
            continue
        age = (now - created).total_seconds()
        if age < 0:
            continue
        if status in ACTIVE and age < RECENT_START_SECONDS:
            return False, f"Refresh {entry.get('id')} recently started and is still active"
        if conclusion == "success" and (
            age < RECENT_START_SECONDS or
            (finished is not None and 0 <= (now - finished).total_seconds() < RECENT_FINISH_SECONDS)
        ):
            return False, f"Refresh {entry.get('id')} already succeeded recently"
    return True, "no recent successful or active Refresh"


def main():
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    backup_slot = os.environ.get("BACKUP_SLOT", "").strip() if event == "workflow_dispatch" else ""
    due, why = True, "manual trigger"
    if event == "schedule" or backup_slot:
        try:
            repo = os.environ["GITHUB_REPOSITORY"]
            token = os.environ["GH_TOKEN"]
            run_id = int(os.environ["GITHUB_RUN_ID"])
            url = f"https://api.github.com/repos/{repo}/actions/workflows/refresh.yaml/runs?per_page=100"
            req = urllib.request.Request(url, headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "aggregator-refresh-gate",
            })
            with urllib.request.urlopen(req, timeout=20) as resp:
                runs = json.load(resp).get("workflow_runs", [])
            if not isinstance(runs, list):
                raise ValueError("invalid GitHub runs response")
            if backup_slot:
                # The standby was dispatched, but a delayed primary may have
                # appeared meanwhile. Check again under Refresh concurrency.
                due, why = should_dispatch_backup(
                    runs, parse_utc(backup_slot), datetime.now(timezone.utc), run_id
                )
            else:
                due, why = should_start(event, runs, run_id)
        except (OSError, KeyError, ValueError, TypeError) as exc:
            # Ordinary scheduled Refresh stays available during API errors,
            # but a standby must never guess that the primary is absent.
            due = not bool(backup_slot)
            why = f"GitHub status unavailable ({type(exc).__name__}); " + (
                "standby fails closed" if backup_slot else "scheduled Refresh fails open"
            )
    value = "true" if due else "false"
    print(f"Refresh trigger: {'RUN' if due else 'SKIP'}; {why}")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"run_refresh={value}\n")


if __name__ == "__main__":
    main()
