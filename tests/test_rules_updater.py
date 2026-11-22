"""Rule snapshot validation, safe updates and service-first policy ordering."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "subscribe"))
from update_rules import (SOURCES, SOURCE_BASE, check, extract, snapshot, update,
                          validate_snapshot_file)
from profile_layout import groups_for_clash
from singbox_layout import apply_singbox_layout


class RuleUpdaterTests(unittest.TestCase):
    def test_committed_rule_snapshots_are_safe(self):
        check(ROOT)
        self.assertEqual(len(SOURCES), 7)
        registry = (ROOT / "subconverter/snippets/rulesets.toml").read_text("utf-8")
        self.assertIn('rules/auto/AI.list', registry)
        self.assertIn('rules/auto/TelegramIP.list', registry)
        self.assertLess(registry.index('rules/custom/AI.list'), registry.index('rules/auto/AI.list'))
        self.assertLess(registry.index('rules/custom/BilibiliRegion.list'),
                        registry.index('rules/auto/InternationalMedia.list'))
        self.assertLess(registry.index('rules/custom/ChinaDirect.list'),
                        registry.index('rules/auto/TelegramIP.list'))

    def test_ai_source_does_not_capture_github_or_general_google(self):
        spec = SOURCES[0]
        src = ('DOMAIN-SUFFIX,chatgpt.com\nDOMAIN-SUFFIX,anthropic.com\n'
               'DOMAIN,api.github.com\nDOMAIN,gemini.google.com\n'
               'DOMAIN,7h15.ru1353t.1s.m4d3.by.5ukk4w.skk.moe\n')
        # A short synthetic sample must fail the minimum rule count safety gate.
        with self.assertRaisesRegex(ValueError, 'unexpected rule count'):
            extract(spec, src)
        src += ('\n'.join(f'DOMAIN,a{i}.chatgpt.com' for i in range(10)) + '\n')
        rows = extract(spec, src)
        self.assertNotIn('DOMAIN,api.github.com', rows)
        self.assertTrue(all('7h15.' not in row for row in rows))

    def test_media_source_cannot_capture_bilibili_or_tiktok(self):
        spec = next(x for x in SOURCES if x.filename == 'InternationalMedia.list')
        sample = ['DOMAIN-SUFFIX,netflix.com',
                  'DOMAIN-SUFFIX,youtube.com', 'DOMAIN-SUFFIX,hulu.com',
                  'DOMAIN-SUFFIX,max.com', 'DOMAIN-SUFFIX,disneyplus.com',
                  'DOMAIN-SUFFIX,primevideo.tv', 'DOMAIN-SUFFIX,spotify.com',
                  'DOMAIN-SUFFIX,twitch.tv', 'DOMAIN-SUFFIX,googlevideo.com',
                  'DOMAIN-SUFFIX,peacocktv.com', 'DOMAIN-SUFFIX,paramountplus.com',
                  'DOMAIN-SUFFIX,bamgrid.com',
                  'DOMAIN-SUFFIX,bilibili.tv', 'DOMAIN-SUFFIX,tiktok.com',
                  'IP-CIDR,17.0.0.0/8,no-resolve']
        rules = extract(spec, '\n'.join(sample))
        self.assertIn('DOMAIN-SUFFIX,netflix.com', rules)
        self.assertNotIn('DOMAIN-SUFFIX,bilibili.tv', rules)
        self.assertNotIn('DOMAIN-SUFFIX,tiktok.com', rules)
        self.assertFalse(any(x.startswith('IP-CIDR') for x in rules))

    def test_failed_remote_retains_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'subconverter/rules/auto').mkdir(parents=True)
            (root / 'subconverter/rules/custom').mkdir(parents=True)
            for spec in SOURCES:
                actual = (ROOT / 'subconverter/rules/auto' / spec.filename).read_bytes()
                (root / 'subconverter/rules/auto' / spec.filename).write_bytes(actual)
                (root / 'subconverter/rules/custom' / spec.base_filename).write_bytes(
                    (ROOT / 'subconverter/rules/custom' / spec.base_filename).read_bytes())
            def failed(url):
                raise OSError('source offline')
            results = update(root, failed)
            self.assertEqual(len(results), 7)
            self.assertTrue(all('retained previous' in v for v in results.values()))
            for spec in SOURCES:
                self.assertEqual((root / 'subconverter/rules/auto' / spec.filename).read_bytes(),
                                 (ROOT / 'subconverter/rules/auto' / spec.filename).read_bytes())

    def test_valid_one_category_updates_without_touching_other_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'subconverter/rules/auto').mkdir(parents=True)
            (root / 'subconverter/rules/custom').mkdir(parents=True)
            for spec in SOURCES:
                (root / 'subconverter/rules/auto' / spec.filename).write_bytes(
                    (ROOT / 'subconverter/rules/auto' / spec.filename).read_bytes())
                (root / 'subconverter/rules/custom' / spec.base_filename).write_bytes(
                    (ROOT / 'subconverter/rules/custom' / spec.base_filename).read_bytes())
            def source(url):
                if not url.endswith('/non_ip/ai.conf'):
                    raise OSError('unreachable')
                return ('DOMAIN-SUFFIX,chatgpt.com\n'
                        + '\n'.join(f'DOMAIN,s{i}.chatgpt.com' for i in range(22)))
            original_telegram = (root / 'subconverter/rules/auto/TelegramDomain.list').read_bytes()
            result = update(root, source)
            self.assertIn('updated', result['AI.list'])
            self.assertIn('retained previous', result['TelegramDomain.list'])
            self.assertEqual((root / 'subconverter/rules/auto/TelegramDomain.list').read_bytes(),
                             original_telegram)
            check(root)

    def test_reject_bad_rule_origin_and_wrong_category(self):
        spec = SOURCES[0]
        with self.assertRaisesRegex(ValueError, 'origin marker'):
            validate_snapshot_file(spec, 'DOMAIN-SUFFIX,chatgpt.com\n')
        with self.assertRaisesRegex(ValueError, 'out-of-category'):
            validate_snapshot_file(spec, '# AUTO-GENERATED:\n# Source: '
                                         + SOURCE_BASE + spec.remote_path
                                         + '\nDOMAIN-SUFFIX,bilibili.com\n')

    def test_legacy_remote_refs_are_removed(self):
        legacy = (ROOT / 'subconverter/snippets/rulesets_remote.txt').read_text('utf-8')
        self.assertNotIn('DivineEngine/Profiles', legacy)
        self.assertIn('subscribe/update_rules.py', legacy)

    def test_rule_update_workflow_and_weekly_protection(self):
        workflow = (ROOT / '.github/workflows/rules-update.yaml').read_text('utf-8')
        weekly = (ROOT / '.github/workflows/collect.yaml').read_text('utf-8')
        self.assertIn('python -u subscribe/update_rules.py --update', workflow)
        self.assertIn('git push origin HEAD:main', workflow)
        for path in ('subscribe/update_rules.py', 'subconverter/rules/auto',
                     'tests/test_rules_updater.py'):
            self.assertIn(path, weekly)
        self.assertIn('git merge --no-commit --no-ff "$UPSTREAM"', weekly)

    def test_policy_default_order_and_japan_missing(self):
        nodes = ['🇭🇰 香港 001', '🇹🇼 台湾 001', '🇯🇵 日本 001', '🇸🇬 新加坡 001']
        groups = {x['name']: x['proxies'] for x in groups_for_clash(nodes)}
        self.assertEqual(groups['苹果服务'][0], '国内直连')
        self.assertEqual(groups['港台番剧'][0], '国内直连')
        self.assertEqual(groups['AI服务'][0], '日本节点')
        self.assertEqual(groups['TikTok'][0], '日本节点')
        self.assertEqual(groups['苹果推送'],
                         ['香港节点','台湾节点','日本节点','狮城节点','国内直连'])
        self.assertEqual(groups['漏网之鱼'], ['全球加速', '国内直连'])
        no_japan = {x['name']: x['proxies'] for x in groups_for_clash(nodes[:2])}
        self.assertEqual(no_japan['AI服务'][0], '香港节点')
        self.assertEqual(no_japan['TikTok'][0], '香港节点')

    def test_singbox_native_direct_and_final_only_two(self):
        config = {'dns': {'servers': [{'tag':'dns_proxy','type':'https'}]},
                  'outbounds':[{'tag':'🇯🇵 日本 001','type':'trojan'}],
                  'route': {'rules': []}}
        result = json.loads(apply_singbox_layout(json.dumps(config)))
        groups = {o['tag']:o['outbounds'] for o in result['outbounds'] if 'outbounds' in o}
        self.assertEqual(groups['漏网之鱼'], ['全球加速','DIRECT'])
        self.assertEqual(groups['AI服务'][0], '日本节点')
        self.assertEqual(groups['苹果服务'][0], 'DIRECT')
        self.assertEqual(groups['苹果推送'], ['日本节点','DIRECT'])


if __name__ == '__main__':
    unittest.main()
