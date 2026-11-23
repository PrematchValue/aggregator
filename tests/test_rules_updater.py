"""Conservative daily snapshots: one maintained global upstream, plus public sets."""
from __future__ import annotations
import json
import sys
import tempfile
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "subscribe"))
from update_rules import SOURCES, SOURCE_BASE, check, extract, snapshot, update, validate_snapshot_file
from verified_public_rules import SOURCES as PUBLIC_SOURCES, check as public_check
from profile_layout import groups_for_clash
from singbox_layout import apply_singbox_layout

class RuleUpdaterTests(unittest.TestCase):
    def test_only_registered_active_snapshots(self):
        check(ROOT)
        public_check(ROOT)
        self.assertEqual([x.filename for x in SOURCES], ['GlobalProxy.list'])
        self.assertEqual({x.name for x in PUBLIC_SOURCES}, {
            'Advertising.list','Tracking.list','StreamingCN.list',
            'InternationalMediaFull.list','GitHubService.list','MicrosoftService.list'})
        reg=(ROOT/'subconverter/snippets/rulesets.toml').read_text('utf-8')
        self.assertIn('rules/auto/GlobalProxy.list',reg)
        self.assertNotIn('rules/custom/GlobalProxy.list',reg)
        self.assertNotIn('rules/auto/AI.list',reg)
        self.assertNotIn('rules/auto/TikTok.list',reg)
        self.assertNotIn('rules/auto/TelegramIP.list',reg)
        self.assertNotIn('Google语音',reg)
    def test_global_source_validates_and_rejects_wrong_origin(self):
        spec=SOURCES[0]
        data=(ROOT/'subconverter/rules/auto/GlobalProxy.list').read_text('utf-8')
        validate_snapshot_file(spec,data)
        with self.assertRaisesRegex(ValueError,'origin marker'):
            validate_snapshot_file(spec,'DOMAIN-SUFFIX,facebook.com\n')
        with self.assertRaisesRegex(ValueError,'unexpected rule count'):
            extract(spec,'DOMAIN-SUFFIX,fbcdn.net\n')
    def test_failed_fetch_keeps_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            dest=root/'subconverter/rules/auto';dest.mkdir(parents=True)
            original=(ROOT/'subconverter/rules/auto/GlobalProxy.list').read_bytes()
            (dest/'GlobalProxy.list').write_bytes(original)
            def down(_): raise OSError('offline')
            result=update(root,down)
            self.assertEqual(list(result), ['GlobalProxy.list'])
            self.assertIn('retained previous',result['GlobalProxy.list'])
            self.assertEqual((dest/'GlobalProxy.list').read_bytes(),original)
    def test_updates_global_without_writing_extra_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            auto=root/'subconverter/rules/auto';auto.mkdir(parents=True)
            auto.joinpath('GlobalProxy.list').write_bytes(
                (ROOT/'subconverter/rules/auto/GlobalProxy.list').read_bytes())
            def down(_):
                old=auto.joinpath('GlobalProxy.list').read_text('utf-8')
                body='\n'.join(x for x in old.splitlines() if x and not x.startswith('#'))
                return 'DOMAIN-SUFFIX,fbcdn.net\n'+body+'\nDOMAIN-SUFFIX,extra-test-domain.example\n'
            result=update(root,down)
            self.assertIn('updated',result['GlobalProxy.list'])
            check(root)
            self.assertEqual(len(list(auto.glob('*.list'))),1)
    def test_rules_update_and_weekly_protection(self):
        daily=(ROOT/'.github/workflows/rules-update.yaml').read_text('utf-8')
        weekly=(ROOT/'.github/workflows/collect.yaml').read_text('utf-8')
        self.assertIn('python -u subscribe/update_rules.py --update',daily)
        for p in ('subscribe/update_rules.py','subconverter/rules/auto'):
            self.assertIn(p,weekly)
    def test_selector_priorities(self):
        ns=['🇭🇰 香港 001','🇹🇼 台湾 001','🇯🇵 日本 001','🇸🇬 新加坡 001','🇺🇸 美国 001']
        groups={x['name']:x['proxies'] for x in groups_for_clash(ns)}
        self.assertEqual(groups['苹果服务'][0],'国内直连')
        self.assertEqual(groups['港台番剧'][0],'国内直连')
        self.assertEqual(groups['人工智能'][0],'日本节点')
        self.assertEqual(groups['TikTok'][0],'日本节点')
        self.assertEqual(groups['微软服务'][0],'美国节点')
        self.assertEqual(groups['GitHub服务'][0],'香港节点')
        self.assertEqual(groups['漏网之鱼'], ['节点选择','国内直连'])
        self.assertNotIn('Google语音',groups)
    def test_singbox_uses_native_direct_and_new_final(self):
        sample={'dns':{'servers':[{'tag':'dns_proxy','type':'https'}]},
                'outbounds':[{'tag':'🇯🇵 日本 001','type':'trojan'}],
                'route':{'rules':[]}}
        result=json.loads(apply_singbox_layout(json.dumps(sample)))
        groups={o['tag']:o['outbounds'] for o in result['outbounds'] if 'outbounds' in o}
        self.assertEqual(groups['漏网之鱼'],['节点选择','DIRECT'])
        self.assertEqual(groups['人工智能'][0],'日本节点')
        self.assertEqual(groups['苹果服务'][0],'DIRECT')
        self.assertEqual(result['dns']['servers'][0]['detour'],'节点选择')

if __name__ == '__main__': unittest.main()
