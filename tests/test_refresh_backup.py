"""Offline tests for conditional Refresh backup and second-stage de-duplication."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import io
import os
import tempfile
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "subscribe"))
from refresh_backup import (primary_slot_for_backup, should_dispatch_backup,
                            valid_slot, dispatch, parse_utc)

UTC = timezone.utc
SLOT = datetime(2026, 11, 14, 4, 17, tzinfo=UTC)
NOW = SLOT + timedelta(minutes=90)


def run(rid=1, minutes=5, status="completed", conclusion="success", branch="main", event="schedule"):
    return {"id": rid, "event": event, "head_branch": branch,
            "created_at": (SLOT + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
            "status": status, "conclusion": conclusion}


class BackupTests(unittest.TestCase):
    def test_expected_slots(self):
        for hour in range(0, 24, 4):
            slot = SLOT.replace(hour=hour)
            self.assertEqual(primary_slot_for_backup(slot + timedelta(minutes=90)), slot)
            self.assertEqual(primary_slot_for_backup(slot + timedelta(minutes=139)), slot)
        self.assertEqual(primary_slot_for_backup(SLOT + timedelta(minutes=89)),
                         SLOT - timedelta(hours=4))

    def test_slot_validation(self):
        self.assertTrue(valid_slot(SLOT))
        self.assertFalse(valid_slot(SLOT.replace(minute=47)))
        self.assertFalse(valid_slot(SLOT.replace(hour=3)))
        self.assertIsNone(parse_utc("garbage"))

    def test_absent_primary_dispatches(self):
        self.assertTrue(should_dispatch_backup([], SLOT, NOW)[0])
        self.assertTrue(should_dispatch_backup([run(conclusion="failure")], SLOT, NOW)[0])
        self.assertTrue(should_dispatch_backup([run(conclusion="cancelled")], SLOT, NOW)[0])

    def test_success_or_active_prevents_dispatch(self):
        for status, conclusion in [("completed", "success"), ("in_progress", None),
                                   ("queued", None), ("pending", None)]:
            with self.subTest(status=status):
                self.assertFalse(should_dispatch_backup([run(status=status, conclusion=conclusion)],
                                                        SLOT, NOW)[0])
        self.assertFalse(should_dispatch_backup([run(1, 2, conclusion="failure"), run(2, 10)], SLOT, NOW)[0])

    def test_earlier_active_and_manual_runs(self):
        self.assertFalse(should_dispatch_backup([run(minutes=-60, status="in_progress", conclusion=None)], SLOT, NOW)[0])
        self.assertFalse(should_dispatch_backup([run(event="workflow_dispatch")], SLOT, NOW)[0])
        self.assertTrue(should_dispatch_backup([run(minutes=-80)], SLOT, NOW)[0])

    def test_unrelated_or_self_does_not_block(self):
        self.assertTrue(should_dispatch_backup([run(branch="feature")], SLOT, NOW)[0])
        self.assertTrue(should_dispatch_backup([run()], SLOT, NOW, current_id=1)[0])

    def test_time_limits_and_uncertainty(self):
        self.assertFalse(should_dispatch_backup([], SLOT, SLOT+timedelta(minutes=89))[0])
        self.assertFalse(should_dispatch_backup([], SLOT, SLOT+timedelta(hours=4))[0])
        self.assertFalse(should_dispatch_backup([], SLOT.replace(minute=47), NOW)[0])
        self.assertFalse(should_dispatch_backup(None, SLOT, NOW)[0])
        self.assertFalse(should_dispatch_backup([run(status="whatever", conclusion=None)], SLOT, NOW)[0])

    def test_dispatch_payload_has_unversioned_slot_and_main_branch(self):
        class FakeResponse:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *_): return False
        with patch('refresh_backup.urllib.request.urlopen', return_value=FakeResponse()) as sender:
            dispatch('owner/repo', 'token', SLOT)
        req = sender.call_args.args[0]
        self.assertEqual(req.method, 'POST')
        self.assertTrue(req.full_url.endswith('/refresh.yaml/dispatches'))
        payload = json.loads(req.data)
        self.assertEqual(payload['ref'], 'main')
        self.assertEqual(payload['inputs']['backup_slot'], '2026-11-14T04:17:00Z')

    def test_dispatched_backup_checks_again_and_skips_delayed_primary(self):
        # A backup dispatch is a workflow_dispatch event, but unlike a user
        # clicking Run workflow it must not bypass the duplicate guard.
        from refresh_due import main as gate_main
        api = json.dumps({'workflow_runs': [run(1, 8), run(9, 80, status='in_progress', conclusion=None)]}).encode()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'output.txt'
            env = {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REPOSITORY': 'owner/repo',
                   'GITHUB_RUN_ID': '9', 'GH_TOKEN': 'x', 'BACKUP_SLOT': SLOT.isoformat().replace('+00:00', 'Z'),
                   'GITHUB_OUTPUT': str(out)}
            with patch.dict(os.environ, env), patch('refresh_due.datetime') as clock, \
                    patch('refresh_due.urllib.request.urlopen', return_value=io.BytesIO(api)):
                clock.now.return_value = NOW
                gate_main()
            self.assertIn('run_refresh=false', out.read_text())

    def test_backup_gate_fails_closed_on_api_error(self):
        from refresh_due import main as gate_main
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'output.txt'
            env = {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REPOSITORY': 'owner/repo',
                   'GITHUB_RUN_ID': '9', 'GH_TOKEN': 'x', 'BACKUP_SLOT': SLOT.isoformat().replace('+00:00', 'Z'),
                   'GITHUB_OUTPUT': str(out)}
            with patch.dict(os.environ, env), \
                    patch('refresh_due.urllib.request.urlopen', side_effect=OSError('network')):
                gate_main()
            self.assertIn('run_refresh=false', out.read_text())

    def test_workflow_no_second_always_on_cron(self):
        primary = (ROOT / '.github/workflows/refresh.yaml').read_text(encoding='utf-8')
        backup = (ROOT / '.github/workflows/refresh-backup.yaml').read_text(encoding='utf-8')
        self.assertIn('cron: "17 */4 * * *"', primary)
        self.assertNotIn('cron: "47 */4 * * *"', primary)
        self.assertIn('cron: "47 1-23/4 * * *"', backup)
        self.assertIn('actions: write', backup)
        self.assertIn('GH_TOKEN: ${{ github.token }}', backup)
        self.assertIn('BACKUP_SLOT: ${{ github.event.inputs.backup_slot }}', primary)
        self.assertIn('queue: max', primary)


if __name__ == '__main__':
    unittest.main()
