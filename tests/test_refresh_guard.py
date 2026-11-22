"""Cloudflare-dispatched backup recheck remains; GitHub backup cron removed."""
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
from refresh_guard import should_dispatch_backup, process_conclusion, parse_utc

UTC = timezone.utc
NOW = datetime(2026, 11, 15, 14, 20, tzinfo=UTC)


def run(rid=1, minutes_ago=5, status='completed', conclusion='success', event='schedule'):
    return {'id': rid, 'event': event, 'head_branch': 'main',
            'created_at': (NOW - timedelta(minutes=minutes_ago)).isoformat(),
            'status': status, 'conclusion': conclusion}


class RefreshGuardTests(unittest.TestCase):
    def test_recent_success_skips_cloudflare_backup(self):
        self.assertFalse(should_dispatch_backup([run(1, 60)], NOW, lambda _: 'success')[0])
        self.assertTrue(should_dispatch_backup([], NOW, lambda _: 'success')[0])

    def test_latest_failure_allows_cloudflare_backup(self):
        results = {1: 'success', 2: 'failure'}
        self.assertTrue(should_dispatch_backup([run(2, 5), run(1, 60)], NOW, results.get)[0])

    def test_active_run_blocks_duplicate(self):
        self.assertFalse(should_dispatch_backup([run(1, 90, status='in_progress')], NOW,
                                                lambda _: 'failure')[0])

    def test_skipped_guard_is_not_a_real_collection(self):
        results = {1: 'success', 2: 'skipped'}
        self.assertFalse(should_dispatch_backup([run(2, 5), run(1, 90)], NOW, results.get)[0])

    def test_process_job_only(self):
        with patch('refresh_guard.github_get', return_value={'jobs': [
            {'name': 'schedule_guard', 'conclusion': 'success'},
            {'name': 'process', 'conclusion': 'skipped'}]}):
            self.assertEqual(process_conclusion('owner/repo', 'x', 5), 'skipped')

    def test_cloudflare_marker_rechecked_by_refresh_due(self):
        from refresh_due import main as guard_main
        api = json.dumps({'workflow_runs': [run(1, 20), run(9, 1, 'in_progress', event='workflow_dispatch')]}).encode()
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

    def test_independent_github_backup_workflow_is_gone(self):
        refresh = (ROOT / '.github/workflows/refresh.yaml').read_text()
        self.assertIn('BACKUP_SLOT: ${{ github.event.inputs.backup_slot }}', refresh)
        self.assertIn('cron: "17 */4 * * *"', refresh)
        self.assertFalse((ROOT / '.github/workflows/refresh-backup.yaml').exists())
        self.assertFalse((ROOT / 'subscribe/refresh_backup.py').exists())
        self.assertIsNone(parse_utc('invalid'))


if __name__ == '__main__':
    unittest.main()
