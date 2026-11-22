"""Historical node snapshot and merge regression (no network calls)."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'subscribe'))
from verified_nodes import merge_candidates, snapshot_content, load_verified_nodes


def node(name, server='hk.example', password='pw', typ='trojan'):
    return {'name': name, 'server': server, 'port': 443, 'type': typ, 'password': password}


class VerifiedHistoryTests(unittest.TestCase):
    def test_rename_does_not_create_duplicates_and_fresh_wins(self):
        fresh = [dict(node('新名称'), sub='source-link')]
        prior = [node('🇭🇰 香港 001'), node('🇯🇵 日本 001', 'jp.example')]
        merged, old_count = merge_candidates(fresh, prior)
        self.assertEqual(len(merged), 2)
        self.assertEqual(old_count, 1)
        self.assertEqual(merged[0]['name'], '新名称')
        self.assertEqual(merged[0]['sub'], 'source-link')
        self.assertEqual(merged[1]['server'], 'jp.example')
        self.assertEqual(fresh[0]['name'], '新名称')

    def test_same_endpoint_different_credentials_kept(self):
        merged, added = merge_candidates([node('A')], [node('B', password='different')])
        self.assertEqual((len(merged), added), (2, 1))

    def test_invalid_entries_are_removed(self):
        merged, added = merge_candidates([{}, node('A')], [{'server': 'x'}, node('B', 'jp')])
        self.assertEqual((len(merged), added), (2, 1))

    def test_snapshot_only_valid_and_strips_runtime_labels(self):
        source = [dict(node('🇭🇰 香港 001'), sub='secret-link', liveness=True),
                  node('重复名'), {}, node('日本', 'jp.example')]
        result = json.loads(snapshot_content(source))
        self.assertEqual(result['version'], 1)
        self.assertEqual(len(result['nodes']), 2)
        self.assertNotIn('sub', result['nodes'][0])
        self.assertNotIn('liveness', result['nodes'][0])
        self.assertEqual(source[0]['sub'], 'secret-link')

    def test_gist_first_run_bootstraps_clash_yaml(self):
        raw = yaml.safe_dump({'proxies': [node('已存在旧节点', 'old.example')]}, allow_unicode=True)
        result = {'files': {'clash.yaml': {'content': raw, 'truncated': False}}}
        with patch('verified_nodes._read_url', return_value=json.dumps(result)):
            old = load_verified_nodes('abcdef0123', 'token')
        self.assertEqual(old[0]['server'], 'old.example')

    def test_gist_snapshot_overrides_bootstrap(self):
        gist = {'files': {
            'verified-nodes.json': {'content': snapshot_content([node('历史', 'old.example')])},
            'clash.yaml': {'content': yaml.safe_dump({'proxies': [node('忽略', 'bad.example')]})},
        }}
        with patch('verified_nodes._read_url', return_value=json.dumps(gist)):
            old = load_verified_nodes('abc123', 'token')
        self.assertEqual([n['server'] for n in old], ['old.example'])

    def test_malformed_snapshot_does_not_return_empty_and_erase_history(self):
        result = {'files': {'verified-nodes.json': {'content': '{broken'}}}
        with patch('verified_nodes._read_url', return_value=json.dumps(result)):
            with self.assertRaises(ValueError):
                load_verified_nodes('abc123', 'token')

    def test_gist_read_error_fails_closed(self):
        with patch('verified_nodes._read_url', side_effect=OSError('network')):
            with self.assertRaises(OSError):
                load_verified_nodes('abc123', 'token')

    def test_raw_url_host_validation(self):
        from verified_nodes import _read_url
        with self.assertRaises(ValueError):
            _read_url('http://gist.githubusercontent.com/abc')
        with self.assertRaises(ValueError):
            _read_url('https://some-other-domain.example/private')

    def test_code_joins_before_mihomo_and_publishes_same_gist_patch(self):
        source = (ROOT / 'subscribe/collect.py').read_text(encoding='utf-8')
        self.assertLess(source.index('merge_candidates(proxies, previous)'),
                        source.index('clash.generate_config(workspace'))
        self.assertIn('snapshot_content(nodes)', source)
        self.assertIn('shared["verified-nodes.json"]', source)
        self.assertIn('push_client.push_to(', source)


if __name__ == '__main__':
    unittest.main()
