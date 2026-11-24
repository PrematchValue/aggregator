"""Public single-source rules, service separation and group ordering."""
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'subscribe'))
from verified_public_rules import SOURCES,check,snapshot,normalized
from profile_layout import groups_for_clash,ICON_BASE
from test_targeted_routing import route_domain

class RuleCoverageTests(unittest.TestCase):
    def test_public_snapshots(self):
        check(ROOT)
        self.assertEqual(len(SOURCES),6)
    def test_service_routing(self):
        expected={
            'www.bilibili.com':'港台番剧','m.bilibili.com':'港台番剧',
            'api.biliapi.net':'港台番剧','grpc.biliapi.net':'港台番剧',
            'www.netflix.com':'国际媒体','www.youtube.com':'国际媒体',
            'www.github.com':'GitHub','githubusercontent.com':'GitHub',
            'www.microsoft.com':'微软服务','lens.l.google.com':'谷歌服务',
            'api.openai.com':'人工智能','api.ledger.com':'冷钱包',
            'app.adjust.com':'REJECT','www.baidu.com':'DIRECT',
            'www.whatsapp.com':'节点选择',
            'www.tiktok.com':'TikTok','v16.tiktokcdn-eu.com':'TikTok',
            'p16-tiktokcdn-com.akamaized.net':'TikTok',
            'foo-tiktokcdn-bar.example.net':'TikTok',
        }
        for domain,group in expected.items():
            with self.subTest(domain=domain): self.assertEqual(route_domain(domain),group)
    def test_order_and_icons(self):
        ns=['🇭🇰 香港 001','🇺🇸 美国 001','🇯🇵 日本 001']
        groups=groups_for_clash(ns)
        names=[g['name'] for g in groups]
        self.assertEqual(names[:6],['节点选择','人工智能','苹果推送','苹果服务','微软服务','谷歌服务'])
        self.assertEqual(groups[0]['icon'],ICON_BASE+'Proxy.png')
        self.assertEqual(groups[1]['icon'],ICON_BASE+'ChatGPT.png')
        options={g['name']:g['proxies'] for g in groups}
        self.assertEqual(options['人工智能'][0],'日本节点')
        self.assertEqual(options['微软服务'][0],'美国节点')
        self.assertEqual(options['GitHub'][0],'香港节点')
        self.assertLess(names.index('谷歌服务'),names.index('GitHub'))
        self.assertLess(names.index('TikTok'),names.index('国际媒体'))
        self.assertNotIn('Google服务',names)
        self.assertNotIn('AI服务',names)
        self.assertNotIn('Google语音',names)
    def test_bad_upstream_rejected(self):
        spec=next(x for x in SOURCES if x.name=='StreamingCN.list')
        with self.assertRaises(ValueError): snapshot(spec,'DOMAIN,www.bilibili.com\n')
        self.assertNotIn('GEOIP,US',normalized('GEOIP,US\n'))
    def test_no_tiktok_in_international_media(self):
        from verified_public_rules import is_tiktok_rule
        src=(ROOT/'subconverter/rules/auto/InternationalMediaFull.list').read_text('utf-8')
        self.assertFalse([x for x in src.splitlines() if x and not x.startswith('#') and is_tiktok_rule(x)])
    def test_google_voice_group_gone(self):
        self.assertEqual(route_domain('lens.l.google.com'),'谷歌服务')
        self.assertFalse((ROOT/'subconverter/rules/custom/GoogleVoice.list').exists())
        self.assertFalse((ROOT/'subconverter/rules/export/singbox/custom_GoogleVoice.json').exists())

if __name__=='__main__': unittest.main()
