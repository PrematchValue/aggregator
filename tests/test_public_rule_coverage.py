"""Behavior regressions based on the user's previously working multi-provider rules."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'subscribe'))
from verified_public_rules import SOURCES, check, snapshot, normalized
from test_targeted_routing import route_domain
from profile_layout import groups_for_clash

class RuleCoverageTests(unittest.TestCase):
    def test_all_public_snapshots_have_validated_sources(self):
        check(ROOT)
        self.assertEqual(len(SOURCES), 9)

    def test_real_service_routing(self):
        expected={
            'www.bilibili.com':'港台番剧',
            'm.bilibili.com':'港台番剧',
            'api.biliapi.net':'港台番剧',
            'grpc.biliapi.net':'港台番剧',
            'www.bilibili.tv':'港台番剧',
            'www.netflix.com':'国际媒体',
            'www.github.com':'GitHub服务',
            'githubusercontent.com':'GitHub服务',
            'www.microsoft.com':'微软服务',
            'lens.l.google.com':'Google语音',
            'api.openai.com':'AI服务',
            'api.ledger.com':'冷钱包',
            'app.adjust.com':'REJECT',
            'www.baidu.com':'DIRECT',
            'www.bilibili.com':'港台番剧',
            'www.facebook.com':'全球加速',
            'www.whatsapp.com':'全球加速',
        }
        for domain,policy in expected.items():
            with self.subTest(domain=domain):
                self.assertEqual(route_domain(domain),policy)

    def test_region_preferences_without_missing_regions(self):
        ns=['🇭🇰 香港 001','🇺🇸 美国 001','🇯🇵 日本 001']
        groups={g['name']:g['proxies'] for g in groups_for_clash(ns)}
        self.assertEqual(groups['GitHub服务'][0],'香港节点')
        self.assertEqual(groups['微软服务'][0],'美国节点')
        self.assertEqual(groups['Google语音'][0],'美国节点')
        no_us={g['name']:g['proxies'] for g in groups_for_clash(['🇯🇵 日本 001'])}
        self.assertEqual(no_us['微软服务'][0],'日本节点')

    def test_bad_upstream_is_rejected(self):
        spec=next(s for s in SOURCES if s.name=='StreamingCN.list')
        with self.assertRaises(ValueError):
            snapshot(spec,'DOMAIN,www.bilibili.com\n')
        self.assertNotIn('GEOIP,US',normalized('GEOIP,US\n'))

if __name__=='__main__':
    unittest.main()
