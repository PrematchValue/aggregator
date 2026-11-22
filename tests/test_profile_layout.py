"""Offline output-layout regression: no real proxy credentials or network needed."""
from pathlib import Path
import re
import sys
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "subscribe"))
from profile_layout import ICONS, SERVICES, apply_profile_layout

NAMES = ["🇭🇰 香港 001", "🇹🇼 台湾 001", "🇯🇵 日本 001",
         "🇸🇬 新加坡 001", "🇺🇸 美国 001", "🇩🇪 德国 001"]


class PolicyLayoutTests(unittest.TestCase):
    def test_clash_groups_are_region_only_at_main_and_service_has_direct(self):
        original = yaml.safe_dump({"proxies": [dict(name=n, type="ss", server="example.org",
                                                   port=443, cipher="aes-128-gcm", password="x")
                                                for n in NAMES],
                                   "proxy-groups": None, "rules": ["FINAL,漏网之鱼"],
                                   "dns": {"nameserver": ["223.5.5.5"]}}, allow_unicode=True,
                                  sort_keys=False)
        after = yaml.safe_load(apply_profile_layout(original, "clash"))
        groups = {g["name"]: g for g in after["proxy-groups"]}
        self.assertEqual(groups["全球加速"]["proxies"],
                         ["香港节点", "台湾节点", "日本节点", "狮城节点", "美国节点", "特殊节点"])
        normal = ["香港节点", "台湾节点", "日本节点", "狮城节点", "美国节点",
                  "特殊节点", "国内直连"]
        expected = {
            "苹果服务": ["国内直连", *normal[:-1]],
            "港台番剧": ["国内直连", *normal[:-1]],
            "AI服务": ["日本节点", *[x for x in normal if x != "日本节点"]],
            "TikTok": ["日本节点", *[x for x in normal if x != "日本节点"]],
            "漏网之鱼": ["全球加速", "国内直连"],
            "微软服务": ["美国节点", *[x for x in normal if x != "美国节点"]],
            "Google语音": ["美国节点", *[x for x in normal if x != "美国节点"]],
        }
        for name in SERVICES:
            self.assertEqual(groups[name]["proxies"], expected.get(name, normal))
        for name, expected in zip(["香港节点", "台湾节点", "日本节点", "狮城节点", "美国节点", "特殊节点"], NAMES):
            self.assertEqual(groups[name]["proxies"], [expected])
        self.assertEqual(after["proxies"][-1], {"name": "国内直连", "type": "direct"})
        self.assertEqual(len(after["proxies"]), len(NAMES) + 1)
        self.assertNotIn("全球加速", groups["AI服务"]["proxies"])
        self.assertNotIn("DIRECT", groups["AI服务"]["proxies"])
        self.assertNotIn("国内直连", groups["全球加速"]["proxies"])
        self.assertTrue(groups["Google服务"]["icon"].endswith("/Google_Search.png"))
        for region in ("香港节点", "台湾节点", "日本节点", "狮城节点", "美国节点"):
            self.assertEqual(groups[region]["type"], "url-test")
            self.assertEqual(groups[region]["interval"], 600)
            self.assertEqual(groups[region]["url"], "https://www.gstatic.com/generate_204")
        self.assertEqual(groups["特殊节点"]["type"], "select")
        self.assertEqual(groups["全球加速"]["type"], "select")
        self.assertEqual(after["dns"], {"nameserver": ["223.5.5.5"]})
        self.assertEqual(after["rules"], ["FINAL,漏网之鱼"])
        self.assertEqual(len(groups), len(ICONS))
        for name, group in groups.items():
            self.assertRegex(group["icon"], r"^https://.+\.png$")
            self.assertNotRegex(name, r"[🇭🇰🇹🇼🇸🇬🇯🇵🇺🇸🔰♻️🎯]")

    def test_surge_uses_compact_group_filters_not_thousands_of_node_names(self):
        lines = "\n".join(f"{name} = ss, example.org, 443, encrypt-method=aes-128-gcm, password=x"
                          for name in NAMES)
        original = "#!MANAGED-CONFIG https://example.com\n[General]\ndns-server = 223.5.5.5\n" + \
            "[Proxy]\n" + lines + "\n[Proxy Group]\nOld = select, DIRECT\n" + \
            "[Rule]\nFINAL,漏网之鱼\n"
        result = apply_profile_layout(original, "surge")
        self.assertNotIn("Old = select", result)
        self.assertIn("[General]\ndns-server = 223.5.5.5", result)
        self.assertIn("[Rule]\nFINAL,漏网之鱼", result)
        self.assertIn("全球加速 = select, 香港节点, 台湾节点, 日本节点, 狮城节点, 美国节点, 特殊节点, icon-url=", result)
        self.assertIn("特殊节点 = select, include-all-proxies=true, policy-regex-filter=", result)
        self.assertIn("狮城节点 = smart, include-all-proxies=true, policy-regex-filter=^🇸🇬 新加坡", result)
        self.assertIn("国内直连 = direct", result)
        self.assertNotIn("国内直连 = select", result)
        self.assertIn("AI服务 = select, 日本节点, 香港节点, 台湾节点, 狮城节点, 美国节点, 特殊节点, 国内直连, icon-url=", result)
        self.assertIn("苹果服务 = select, 国内直连, 香港节点, 台湾节点, 日本节点, 狮城节点, 美国节点, 特殊节点, icon-url=", result)
        self.assertIn("港台番剧 = select, 国内直连, 香港节点, 台湾节点, 日本节点, 狮城节点, 美国节点, 特殊节点, icon-url=", result)
        self.assertIn("TikTok = select, 日本节点, 香港节点, 台湾节点, 狮城节点, 美国节点, 特殊节点, 国内直连, icon-url=", result)
        self.assertIn("漏网之鱼 = select, 全球加速, 国内直连, icon-url=", result)
        self.assertIn("苹果推送 = select, 香港节点, 台湾节点, 日本节点, 狮城节点, 美国节点, 特殊节点, 国内直连, icon-url=", result)
        self.assertNotIn("AI服务 = select, 全球加速", result)
        self.assertIn("国内直连$", result)
        self.assertIn("香港节点 = smart, include-all-proxies=true, policy-regex-filter=^🇭🇰", result)
        self.assertEqual(result.count("icon-url="), len(ICONS))
        self.assertNotIn("全球直连", result)
        self.assertIn("🇭🇰 香港 001 = ss,", result)

    def test_empty_regions_are_omitted_without_accidental_direct_fallback(self):
        source = yaml.safe_dump({"proxies": [{"name": "🇯🇵 日本 001", "type": "ss", "server": "x", "port": 80}],
                                 "rules": ["FINAL,漏网之鱼"]}, allow_unicode=True, sort_keys=False)
        result = yaml.safe_load(apply_profile_layout(source, "clash"))
        groups = {g["name"]: g for g in result["proxy-groups"]}
        self.assertEqual(groups["全球加速"]["proxies"], ["日本节点"])
        self.assertNotIn("香港节点", groups)
        self.assertEqual(groups["苹果推送"]["proxies"], ["日本节点", "国内直连"])
        self.assertEqual(result["proxies"][-1], {"name": "国内直连", "type": "direct"})

    def test_reject_duplicate_proxy_names_and_bad_profiles(self):
        source = yaml.safe_dump({"proxies": [{"name": "A"}, {"name": "A"}],
                                 "rules": []}, allow_unicode=True)
        with self.assertRaises(ValueError):
            apply_profile_layout(source, "clash")
        with self.assertRaises(ValueError):
            apply_profile_layout("[Proxy Group]\nX = select, DIRECT\n", "surge")

    def test_local_rules_reference_valid_services_and_exist(self):
        import tomllib
        data = tomllib.loads((ROOT / 'subconverter/snippets/rulesets.toml').read_text())
        groups = {r['group'] for r in data['rulesets']}
        self.assertTrue(set(SERVICES) - {'漏网之鱼'} <= groups)
        self.assertTrue(groups <= set(SERVICES) | {'DIRECT', 'REJECT', '全球加速'})
        for r in data['rulesets']:
            if not r['ruleset'].startswith('[]'):
                self.assertTrue((ROOT / 'subconverter' / r['ruleset']).is_file(), r)
        final = data['rulesets'][-1]
        self.assertEqual((final['group'], final['ruleset']), ('漏网之鱼', '[]FINAL'))
        self.assertFalse((ROOT / '.github/workflows/refresh-backup.yaml').exists())
        self.assertFalse((ROOT / 'subconverter/snippets/groups.toml').exists())
        base = (ROOT / 'subconverter/base/all_base.tpl').read_text(encoding='utf-8')
        self.assertNotIn('#🔰 节点选择', base)
        self.assertEqual(base.count('#全球加速'), 2)


if __name__ == '__main__':
    unittest.main()
