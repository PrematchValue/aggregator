"""Non-Clash profile templates and GitHub schedule safeguards."""
from pathlib import Path
import json
import re
import tomllib
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "subconverter/base/all_base.tpl"


class ProfileAndScheduleTests(unittest.TestCase):
    def test_surges_default_without_mitm_or_extra_scripts(self):
        text = TEMPLATE.read_text(encoding="utf-8")
        surge = text.split('{% if request.target == "surge" %}', 1)[1].split('{% if request.target == "loon" %}', 1)[0]
        self.assertIn("encrypted-dns-server =", surge)
        self.assertIn("dns-server =", surge)
        self.assertNotIn("[MITM]", surge)
        self.assertNotIn("ca-p12", surge)
        self.assertNotIn("script-path", surge)
        self.assertNotIn("[Script]", surge)

    def test_singbox_uses_modern_dns_and_tun_without_legacy_fields(self):
        text = TEMPLATE.read_text(encoding="utf-8")
        part = text.split('{% if request.target == "singbox" %}', 1)[1].rsplit('{% endif %}', 1)[0]
        part = re.sub(r'(?m)^\s*\{%.*?%\}\s*$', '', part)
        part = re.sub(r'\{\{\s*default\([^,]+,\s*"([^\"]+)"\)\s*\}\}', r'\1', part)
        # Omit one of the two mutually exclusive listen lines for JSON parsing.
        part = part.replace('"listen": "0.0.0.0",', '')
        config = json.loads(part)
        self.assertEqual(config['dns']['final'], 'dns_proxy')
        self.assertTrue(all('type' in server for server in config['dns']['servers']))
        self.assertEqual(config['route']['default_domain_resolver'], 'dns_direct')
        self.assertIn('address', config['inbounds'][1])
        self.assertNotIn('inet4_address', config['inbounds'][1])
        self.assertIn('dns_fakeip', [s['tag'] for s in config['dns']['servers']])
        self.assertEqual(config['inbounds'][0]['listen'], '127.0.0.1')

    def test_singbox_dns_detour_group_exists(self):
        groups = tomllib.loads((ROOT/'subconverter/snippets/groups.toml').read_text(encoding='utf-8'))
        names = [g['name'] for g in groups['custom_groups']]
        self.assertIn('🔰 节点选择', names)
        pref = tomllib.loads((ROOT/'subconverter/pref.toml').read_text(encoding='utf-8'))
        keyed = {g['key']:g['value'] for g in pref['template']['globals']}
        self.assertEqual(keyed['singbox.allow_lan'], 'false')

    def test_refresh_four_hour_full_scan(self):
        yml = (ROOT/'.github/workflows/refresh.yaml').read_text(encoding='utf-8')
        self.assertIn('cron: "17 */4 * * *"', yml)
        self.assertNotIn('cron: "47 */4 * * *"', yml)
        self.assertIn('backup_slot:', yml)
        standby = (ROOT / ".github/workflows/refresh-backup.yaml").read_text(encoding="utf-8")
        self.assertIn('cron: "47 1-23/4 * * *"', standby)
        self.assertIn("actions: write", standby)
        self.assertIn(' --geo-rename ', yml)
        self.assertNotIn('--max-candidates', yml)
        self.assertNotIn('--stage-output', yml)
        self.assertNotIn('--publish-stage', yml)
        self.assertNotIn('  publish:', yml)
        self.assertNotIn('--refresh', yml)
        self.assertNotIn('--overwrite --refresh', yml)
        self.assertIn('timeout-minutes: 330', yml)
        self.assertIn('queue: max', yml)
        self.assertIn('needs: schedule_guard', yml)
        self.assertIn('needs.schedule_guard.outputs.run_refresh', yml)
        workflow = yaml.safe_load(yml)
        self.assertIn('schedule_guard', workflow['jobs'])
        self.assertEqual(workflow['jobs']['process']['needs'], 'schedule_guard')
        self.assertEqual(set(workflow['jobs']), {'schedule_guard', 'process'})

    def test_weekly_workflow_only_checks_upstream(self):
        yml = (ROOT/'.github/workflows/collect.yaml').read_text(encoding='utf-8')
        self.assertIn('name: Weekly Upstream Check', yml)
        self.assertIn('cron: "0 0 * * 1"', yml)
        self.assertIn("git fetch --no-tags https://github.com/wzdnzd/aggregator.git", yml)
        workflow = yaml.safe_load(yml)
        self.assertEqual(list(workflow['jobs']), ['upstream'])
        self.assertNotIn('candidate-stage.json', yml)
        self.assertNotIn('GIST_PAT', yml)
        self.assertIn('git restore --source="$BASE" --staged --worktree', yml)
        self.assertIn('subconverter/base/all_base.tpl subconverter/pref.toml', yml)


if __name__ == '__main__':
    unittest.main()
