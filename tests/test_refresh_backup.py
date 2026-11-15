"""Regression tests for late GitHub cron and true process-level health."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'subscribe'))
from refresh_backup import (should_dispatch_backup, dispatch, process_conclusion, parse_utc)

UTC = timezone.utc
NOW = datetime(2026, 11, 15, 14, 20, tzinfo=UTC)


def run(rid=1, minutes_ago=5, status='completed', conclusion='success',
        branch='main', event='schedule'):
    return {'id': rid, 'event': event, 'head_branch': branch,
            'created_at': (NOW - timedelta(minutes=minutes_ago)).isoformat().replace('+00:00', 'Z'),
            'status': status, 'conclusion': conclusion}


class RollingBackupTests(unittest.TestCase):
    def test_missing_primary_even_after_old_four_hour_cutoff_dispatches(self):
        self.assertTrue(should_dispatch_backup([], NOW, lambda _: 'success')[0])
        self.assertTrue(should_dispatch_backup([run(minutes_ago=290)], NOW, lambda _: 'success')[0])
        self.assertTrue(should_dispatch_backup([run(minutes_ago=580)], NOW, lambda _: 'success')[0])

    def test_current_real_process_success_skips(self):
        self.assertFalse(should_dispatch_backup([run(minutes_ago=60)], NOW, lambda _: 'success')[0])
        self.assertFalse(should_dispatch_backup([run(minutes_ago=239)], NOW, lambda _: 'success')[0])

    def test_green_guard_only_success_does_not_count(self):
        self.assertTrue(should_dispatch_backup([run()], NOW, lambda _: 'skipped')[0])
        jobs = {3: 'skipped', 2: 'success'}
        self.assertFalse(should_dispatch_backup([run(3, 7), run(2, 90)], NOW, jobs.get)[0])

    def test_failure_retry_even_when_last_success_is_just_earlier(self):
        jobs = {3: 'failure', 2: 'success'}
        self.assertTrue(should_dispatch_backup([run(2, 120), run(3, 5, conclusion='failure')], NOW, jobs.get)[0])
        self.assertTrue(should_dispatch_backup([run(3, 5, conclusion='cancelled')], NOW,
                                               lambda _: 'cancelled')[0])

    def test_active_and_pending_block(self):
        for state in ('queued', 'waiting', 'pending', 'requested', 'in_progress'):
            with self.subTest(state=state):
                self.assertFalse(should_dispatch_backup(
                    [run(1, 110, status=state, conclusion=None)], NOW, lambda _: 'failure')[0])
        self.assertFalse(should_dispatch_backup([run(1, 280, status='in_progress', conclusion=None)],
                                                NOW, lambda _: 'success')[0])

    def test_uncertainty_fails_closed(self):
        self.assertFalse(should_dispatch_backup([run(status='mystery')], NOW, lambda _: 'success')[0])
        self.assertFalse(should_dispatch_backup(None, NOW, lambda _: 'success')[0])
        self.assertFalse(should_dispatch_backup([run()], NOW.replace(tzinfo=None), lambda _: 'success')[0])
        self.assertFalse(should_dispatch_backup([run()], NOW, lambda _: 'unknown')[0])

    def test_different_branch_or_self_ignored(self):
        self.assertTrue(should_dispatch_backup([run(branch='feature')], NOW, lambda _: 'success')[0])
        self.assertTrue(should_dispatch_backup([run()], NOW, lambda _: 'success', current_id=1)[0])

    def test_job_api_confirms_only_process(self):
        with patch('refresh_backup.github_get', return_value={'jobs': [
            {'name': 'schedule_guard', 'conclusion': 'success'},
            {'name': 'process', 'conclusion': 'skipped'},
        ]}):
            self.assertEqual(process_conclusion('a/b', 'x', 1), 'skipped')
        with patch('refresh_backup.github_get', return_value={'jobs': [
            {'name': 'schedule_guard', 'conclusion': 'success'}
        ]}):
            with self.assertRaises(ValueError):
                process_conclusion('a/b', 'x', 1)

    def test_marker_dispatch_payload(self):
        class Response:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *_): return False
        with patch('refresh_backup.urllib.request.urlopen', return_value=Response()) as sender:
            dispatch('owner/repo', 'token', NOW)
        req = sender.call_args.args[0]
        self.assertEqual(req.method, 'POST')
        self.assertTrue(req.full_url.endswith('refresh.yaml/dispatches'))
        self.assertEqual(json.loads(req.data)['inputs']['backup_slot'], '2026-11-15T14:20:00Z')
        self.assertIsNone(parse_utc('invalid'))

    def test_dispatched_backup_rechecks_rolling_state_before_collect(self):
        from refresh_due import main as guard_main
        api = json.dumps({'workflow_runs': [run(1, 20), run(9, 1, 'in_progress', None, event='workflow_dispatch')]}).encode()
        with tempfile.TemporaryDirectory() as tmp:
            outfile = Path(tmp) / 'github_output'
            env = {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REPOSITORY': 'owner/repo',
                   'GITHUB_RUN_ID': '9', 'GH_TOKEN': 'x', 'BACKUP_SLOT': NOW.isoformat(),
                   'GITHUB_OUTPUT': str(outfile)}
            with patch.dict(os.environ, env), patch('refresh_due.datetime') as clock, \
                    patch('refresh_due.urllib.request.urlopen', return_value=io.BytesIO(api)), \
                    patch('refresh_due.process_conclusion', return_value='success'):
                clock.now.return_value = NOW
                guard_main()
            self.assertIn('run_refresh=false', outfile.read_text())

    def test_rolling_backup_gate_skips_on_api_error(self):
        from refresh_due import main as guard_main
        with tempfile.TemporaryDirectory() as tmp:
            outfile = Path(tmp) / 'github_output'
            env = {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REPOSITORY': 'owner/repo',
                   'GITHUB_RUN_ID': '9', 'GH_TOKEN': 'x', 'BACKUP_SLOT': NOW.isoformat(),
                   'GITHUB_OUTPUT': str(outfile)}
            with patch.dict(os.environ, env), \
                    patch('refresh_due.urllib.request.urlopen', side_effect=OSError('network')):
                guard_main()
            self.assertIn('run_refresh=false', outfile.read_text())

    def test_workflows_keep_one_primary_and_independent_backup(self):
        p = (ROOT / '.github/workflows/refresh.yaml').read_text(encoding='utf-8')
        b = (ROOT / '.github/workflows/refresh-backup.yaml').read_text(encoding='utf-8')
        self.assertIn('cron: "17 */4 * * *"', p)
        self.assertNotIn('cron: "47 */4 * * *"', p)
        self.assertIn('cron: "47 1-23/4 * * *"', b)
        self.assertIn('actions: write', b)
        self.assertIn('BACKUP_SLOT: ${{ github.event.inputs.backup_slot }}', p)


if __name__ == '__main__':
    unittest.main()
