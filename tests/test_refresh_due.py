"""Reliable Refresh dispatch gate, without external API test requests."""
from datetime import datetime, timezone, timedelta
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "subscribe"))
from refresh_due import should_start

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


def run(run_id, mins, status="completed", conclusion="success", updated_min=None, event="schedule"):
    created = NOW - timedelta(minutes=mins)
    finished = NOW - timedelta(minutes=updated_min if updated_min is not None else mins)
    return {"id": run_id, "event": event, "head_branch": "main", "status": status,
            "conclusion": conclusion, "created_at": created.isoformat().replace("+00:00", "Z"),
            "updated_at": finished.isoformat().replace("+00:00", "Z")}


class RefreshDueTests(unittest.TestCase):
    def test_backup_skips_recent_success(self):
        self.assertFalse(should_start("schedule", [run(1, 30)], 2, NOW)[0])

    def test_next_two_hour_slot_allowed(self):
        self.assertTrue(should_start("schedule", [run(1, 121)], 2, NOW)[0])

    def test_failure_retries_in_backup_slot(self):
        self.assertTrue(should_start("schedule", [run(1, 30, conclusion="failure")], 2, NOW)[0])

    def test_recent_active_skipped(self):
        self.assertFalse(should_start("schedule", [run(1, 60, status="in_progress", conclusion=None)], 2, NOW)[0])

    def test_manual_never_suppressed(self):
        self.assertTrue(should_start("workflow_dispatch", [run(1, 2)], 2, NOW)[0])

    def test_long_ended_run_skips_immediate_backup(self):
        self.assertFalse(should_start("schedule", [run(1, 130, updated_min=2)], 2, NOW)[0])

    def test_old_or_foreign_runs_not_suppressing(self):
        foreign = run(1, 30)
        foreign["head_branch"] = "other"
        self.assertTrue(should_start("schedule", [foreign, run(2, 200)], 3, NOW)[0])

    def test_current_run_does_not_suppress_itself(self):
        self.assertTrue(should_start("schedule", [run(2, 1)], 2, NOW)[0])


if __name__ == "__main__":
    unittest.main()
