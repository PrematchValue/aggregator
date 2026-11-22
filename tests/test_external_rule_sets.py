"""No network required: cross-client remote rule-set and priority verification."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "subscribe"))
from external_rule_sets import (RAW_BASE, registry, tag_for, exported_files,
                                read_rules, externalize_surge,
                                externalize_singbox, sync_exports)
from profile_layout import apply_profile_layout
from singbox_layout import apply_singbox_layout


class ExternalRulesTests(unittest.TestCase):
    def test_every_remote_resource_exists_and_exports_synced(self):
        sync_exports(check=True)
        self.assertEqual(len(exported_files()), len([
            x for x in registry() if not x['ruleset'].startswith('[]')]))
        for rel, contents in exported_files().items():
            self.assertTrue((ROOT / rel).is_file(), rel)
            obj = json.loads(contents)
            self.assertEqual(obj['version'], 2)
            self.assertTrue(obj['rules'])
            for r in obj['rules']:
                self.assertEqual(len(r), 1)  # OR, not accidental AND

    def test_global_after_special_and_explicit_domestic_before_geoip(self):
        items = registry()
        names = [e['ruleset'] for e in items]
        global_at = names.index('rules/auto/GlobalProxy.list')
        self.assertGreater(global_at, names.index('rules/custom/ChinaDirect.list'))
        self.assertGreater(global_at, names.index('rules/custom/AppleService.list'))
        self.assertLess(global_at, names.index('[]GEOIP,CN'))
        self.assertIn('DOMAIN-SUFFIX,facebook.com', read_rules('rules/custom/GlobalProxy.list'))
        self.assertTrue(read_rules('rules/auto/GlobalProxy.list'))

    def test_clash_mi_uses_stable_inline_subconverter_rules(self):
        # Clash now keeps SubConverter's original inline rules. No remote
        # rule providers can fail during first boot. Other formats remain external.
        collect = (ROOT / 'subscribe/collect.py').read_text('utf-8')
        self.assertNotIn('externalize_clash(updated)', collect)
        self.assertIn("target_name == 'surge'", collect)
        self.assertIn('externalize_surge(updated)', collect)
        names = [r['ruleset'] for r in registry()]
        self.assertLess(names.index('rules/custom/BilibiliRegion.list'),
                        names.index('rules/custom/ChinaDirect.list'))
        bilibili = read_rules('rules/custom/BilibiliRegion.list')
        self.assertIn('DOMAIN,www.bilibili.com', bilibili)
        self.assertIn('DOMAIN,m.bilibili.com', bilibili)
        self.assertIn('DOMAIN-KEYWORD,cn-hk-eq-bcache-', bilibili)

    def test_surge_remote_sets_and_pure_proxy_section(self):
        source = '[General]\ndns-server = 223.5.5.5\n[Proxy]\n🇯🇵 日本 001 = ss, x, 443, encrypt-method=aes-128-gcm, password=secret\n[Proxy Group]\n全球加速 = select, 🇯🇵 日本 001\n[Rule]\nDOMAIN-SUFFIX,example.com,DIRECT\nFINAL,漏网之鱼\n[Host]\nwww.example.com = 1.1.1.1\n'
        result = externalize_surge(apply_profile_layout(source, 'surge'))
        self.assertIn('[Host]\nwww.example.com = 1.1.1.1', result)
        self.assertIn('🇯🇵 日本 001 = ss, x', result)
        self.assertIn('RULE-SET,' + RAW_BASE + 'rules/auto/GlobalProxy.list,全球加速,update-interval=86400',result)
        self.assertLess(result.index('rules/custom/ChinaDirect.list,国内直连'),
                        result.index('rules/auto/GlobalProxy.list,全球加速'))
        self.assertTrue(result.rstrip().endswith('www.example.com = 1.1.1.1'))
        self.assertEqual(result.count('FINAL,漏网之鱼'),1)

    def test_singbox_json_external_and_preserves_dns_sniff(self):
        sample = {'dns': {'servers':[{'type':'https','tag':'dns_proxy','server':'1.1.1.1'}]},
                  'outbounds':[{'type':'trojan','tag':'🇯🇵 日本 001','server':'x.example'}],
                  'route':{'rules':[{'protocol':'dns','outbound':'dns-out'},
                                    {'domain_suffix':['facebook.com'],'outbound':'漏网之鱼'},
                                    {'domain_suffix':['doubleclick.net'],'outbound':'REJECT'}]}}
        sample['outbounds'].append({'tag':'dns-out','type':'dns'})
        layout = apply_singbox_layout(json.dumps(sample))
        obj = json.loads(externalize_singbox(layout))
        rule_sets = obj['route']['rule_set']
        self.assertTrue(all(s['type']=='remote' for s in rule_sets))
        self.assertEqual(obj['route']['rules'][0]['action'], 'hijack-dns')
        self.assertEqual(obj['route']['final'], '漏网之鱼')
        self.assertIn({'rule_set':'auto_GlobalProxy','outbound':'全球加速'},obj['route']['rules'])
        self.assertIn({'rule_set':'geoip-cn','outbound':'DIRECT'},obj['route']['rules'])
        self.assertIn({'rule_set':'custom_BlockAds','action':'reject'},obj['route']['rules'])
        self.assertTrue(obj['experimental']['cache_file']['enabled'])
        self.assertEqual(obj['outbounds'][0]['server'],'x.example') if obj['outbounds'][0].get('type')=='trojan' else self.assertTrue(any(o.get('server')=='x.example' for o in obj['outbounds']))
        self.assertIn('https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs',[x['url'] for x in rule_sets])

    def test_daily_refresh_keeps_sync_exports_and_weekly_protection(self):
        daily = (ROOT / '.github/workflows/rules-update.yaml').read_text('utf-8')
        weekly = (ROOT / '.github/workflows/collect.yaml').read_text('utf-8')
        for term in ('subscribe/external_rule_sets.py --write',
                     'subconverter/rules/export/singbox', 'subconverter/rules/auto'):
            self.assertIn(term, daily)
        self.assertIn('subscribe/external_rule_sets.py',weekly)
        self.assertIn('subconverter/rules/export/singbox',weekly)
        self.assertIn('subconverter/rules/custom',weekly)
        collect = (ROOT / 'subscribe/collect.py').read_text('utf-8')
        for func in ('externalize_surge','externalize_singbox'):
            self.assertIn(func, collect)


if __name__ == '__main__':
    unittest.main()