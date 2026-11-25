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
    def test_clash_groups_have_hidden_fallback_and_service_has_direct(self):
        original = yaml.safe_dump({"proxies": [dict(name=n, type="ss", server="example.org",
                                                   port=443, cipher="aes-128-gcm", password="x")
                                                for n in NAMES],
                                   "proxy-groups": None, "rules": ["FINAL,漏网之鱼"],
                                   "dns": {"nameserver": ["223.5.5.5"]}}, allow_unicode=True,
                                  sort_keys=False)
        after = yaml.safe_load(apply_profile_layout(original, "clash"))
        groups = {g["name"]: g for g in after["proxy-groups"]}
        self.assertEqual(groups["节点选择"]["proxies"],
                         ["故障转移", "香港节点", "台湾节点", "日本节点", "狮城节点", "美国节点", "特殊节点"])
        normal = ["故障转移", "香港节点", "台湾节点", "日本节点", "狮城节点", "美国节点",
                  "特殊节点", "国内直连"]
        expected = {
            "苹果服务": ["国内直连", *normal[:-1]],
            "港台番剧": ["国内直连", *normal[:-1]],
            "人工智能": ["日本节点", *[x for x in normal if x != "日本节点"]],
            "TikTok": ["日本节点", *[x for x in normal if x != "日本节点"]],
            "漏网之鱼": ["节点选择", "国内直连"],
            "微软服务": ["美国节点", *[x for x in normal if x != "美国节点"]],
            "谷歌服务": ["日本节点", *[x for x in normal if x != "日本节点"]],
            "数字资产": ["台湾节点", *[x for x in normal if x != "台湾节点"]],
        }
        fallback = groups["故障转移"]
        self.assertEqual(fallback["type"], "fallback")
        self.assertIs(fallback["hidden"], True)
        self.assertEqual(fallback["proxies"], [*normal[1:-2], "特殊自动"])
        special_auto = groups["特殊自动"]
        self.assertEqual(special_auto["type"], "url-test")
        self.assertIs(special_auto["hidden"], True)
        self.assertEqual(special_auto["proxies"], groups["特殊节点"]["proxies"])
        self.assertEqual(special_auto["icon"], groups["特殊节点"]["icon"])
        self.assertEqual(special_auto["interval"], 600)
        self.assertEqual(special_auto["tolerance"], 50)
        self.assertEqual(special_auto["url"], fallback["url"])
        self.assertNotIn("hidden", groups["特殊节点"])
        for name in ("节点选择", *SERVICES):
            self.assertNotIn("特殊自动", groups[name]["proxies"])
        for name in fallback["proxies"]:
            self.assertEqual(groups[name]["type"], "url-test")
        self.assertEqual(fallback["url"], "https://www.gstatic.com/generate_204")
        self.assertTrue(fallback["icon"].endswith("/Auto.png"))
        self.assertEqual([g["name"] for g in after["proxy-groups"] if g.get("hidden")], ["特殊自动", "故障转移"])
        self.assertNotIn("Google语音", groups)
        self.assertEqual(list(groups)[:6],
                         ["节点选择", "人工智能", "苹果推送", "苹果服务", "微软服务", "谷歌服务"])
        for name in SERVICES:
            self.assertEqual(groups[name]["proxies"], expected.get(name, normal))
        for name, expected in zip(["香港节点", "台湾节点", "日本节点", "狮城节点", "美国节点", "特殊节点"], NAMES):
            self.assertEqual(groups[name]["proxies"], [expected])
        self.assertEqual(after["proxies"][-1], {"name": "国内直连", "type": "direct"})
        self.assertEqual(len(after["proxies"]), len(NAMES) + 1)
        self.assertNotIn("节点选择", groups["人工智能"]["proxies"])
        self.assertNotIn("DIRECT", groups["人工智能"]["proxies"])
        self.assertNotIn("国内直连", groups["节点选择"]["proxies"])
        self.assertTrue(groups["谷歌服务"]["icon"].endswith("/Google_Search.png"))
        self.assertLess(list(groups).index("谷歌服务"), list(groups).index("GitHub"))
        self.assertLess(list(groups).index("TikTok"), list(groups).index("国际媒体"))
        for region in ("香港节点", "台湾节点", "日本节点", "狮城节点", "美国节点"):
            self.assertEqual(groups[region]["type"], "url-test")
            self.assertEqual(groups[region]["interval"], 600)
            self.assertEqual(groups[region]["url"], "https://www.gstatic.com/generate_204")
        self.assertEqual(groups["特殊节点"]["type"], "select")
        self.assertEqual(groups["节点选择"]["type"], "select")
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
        self.assertIn("节点选择 = select, 故障转移, 香港节点, 台湾节点, 日本节点, 狮城节点, 美国节点, 特殊节点, icon-url=", result)
        self.assertIn("特殊节点 = select, include-all-proxies=true, policy-regex-filter=", result)
        self.assertIn("狮城节点 = smart, include-all-proxies=true, policy-regex-filter=^🇸🇬 新加坡", result)
        self.assertIn("国内直连 = direct", result)
        self.assertNotIn("国内直连 = select", result)
        for name, default in {"数字资产": "台湾节点", "谷歌服务": "日本节点",
                              "微软服务": "美国节点"}.items():
            self.assertIn(f"{name} = select, {default}, 故障转移,", result)
        for name in ("GitHub", "国际媒体"):
            self.assertIn(f"{name} = select, 故障转移, 香港节点,", result)
        fallback = next(line for line in result.splitlines() if line.startswith("故障转移 = "))
        self.assertEqual(fallback.split(", ")[1:7],
                         ["香港节点", "台湾节点", "日本节点", "狮城节点", "美国节点", "特殊自动"])
        self.assertIn("hidden=1", fallback)
        self.assertIn("no-alert=1", fallback)
        manual = next(line for line in result.splitlines() if line.startswith("特殊节点 = "))
        auto = next(line for line in result.splitlines() if line.startswith("特殊自动 = "))
        self.assertIn("特殊自动 = smart, include-all-proxies=true, policy-regex-filter=", auto)
        self.assertIn("hidden=1", auto)
        self.assertNotIn("hidden=", manual)
        self.assertEqual(manual.split("policy-regex-filter=")[1].split(", ")[0],
                         auto.split("policy-regex-filter=")[1].split(", ")[0])
        self.assertEqual(manual.split("icon-url=")[1], auto.split("icon-url=")[1])
        for name in ("节点选择", *SERVICES):
            line = next(line for line in result.splitlines() if line.startswith(name + " = "))
            self.assertNotIn("特殊自动", line)
        self.assertTrue(fallback.endswith("/Auto.png"))
        self.assertNotIn("国内直连", fallback)
        self.assertEqual(result.count("故障转移 = fallback,"), 1)
        self.assertEqual(result.count("hidden=1"), 2)
        self.assertNotIn("hidden=true", result)
        self.assertIn("人工智能 = select, 日本节点, 故障转移, 香港节点, 台湾节点, 狮城节点, 美国节点, 特殊节点, 国内直连, icon-url=", result)
        self.assertIn("苹果服务 = select, 国内直连, 故障转移, 香港节点, 台湾节点, 日本节点, 狮城节点, 美国节点, 特殊节点, icon-url=", result)
        self.assertIn("港台番剧 = select, 国内直连, 故障转移, 香港节点, 台湾节点, 日本节点, 狮城节点, 美国节点, 特殊节点, icon-url=", result)
        self.assertIn("TikTok = select, 日本节点, 故障转移, 香港节点, 台湾节点, 狮城节点, 美国节点, 特殊节点, 国内直连, icon-url=", result)
        self.assertIn("漏网之鱼 = select, 节点选择, 国内直连, icon-url=", result)
        self.assertIn("苹果推送 = select, 故障转移, 香港节点, 台湾节点, 日本节点, 狮城节点, 美国节点, 特殊节点, 国内直连, icon-url=", result)
        self.assertNotIn("人工智能 = select, 节点选择", result)
        self.assertIn("国内直连$", result)
        self.assertIn("香港节点 = smart, include-all-proxies=true, policy-regex-filter=^🇭🇰", result)
        self.assertEqual(result.count("icon-url="), len(ICONS))
        self.assertLess(result.index("\n谷歌服务 = select"), result.index("\nGitHub = select"))
        self.assertLess(result.index("\nTikTok = select"), result.index("\n国际媒体 = select"))
        self.assertNotIn("全球直连", result)
        self.assertIn("🇭🇰 香港 001 = ss,", result)

    def test_empty_regions_are_omitted_without_accidental_direct_fallback(self):
        source = yaml.safe_dump({"proxies": [{"name": "🇯🇵 日本 001", "type": "ss", "server": "x", "port": 80}],
                                 "rules": ["FINAL,漏网之鱼"]}, allow_unicode=True, sort_keys=False)
        result = yaml.safe_load(apply_profile_layout(source, "clash"))
        groups = {g["name"]: g for g in result["proxy-groups"]}
        self.assertEqual(groups["节点选择"]["proxies"], ["故障转移", "日本节点"])
        self.assertNotIn("香港节点", groups)
        self.assertEqual(groups["故障转移"]["proxies"], ["日本节点"])
        self.assertNotIn("特殊节点", groups)
        self.assertNotIn("特殊自动", groups)
        self.assertEqual(groups["国际媒体"]["proxies"][0], "故障转移")
        self.assertEqual(groups["数字资产"]["proxies"][0], "故障转移")
        self.assertEqual(groups["漏网之鱼"]["proxies"], ["节点选择", "国内直连"])
        self.assertEqual(groups["苹果推送"]["proxies"], ["故障转移", "日本节点", "国内直连"])
        self.assertEqual(result["proxies"][-1], {"name": "国内直连", "type": "direct"})

    def test_only_special_nodes_and_missing_special_in_both_profiles(self):
        from profile_layout import groups_for_clash
        for names, has_special, fallback in [
            (["🇯🇵 日本 001"], False, ["日本节点"]),
            (["🇩🇪 德国 001", "🇨🇦 加拿大 001"], True, ["特殊自动"]),
        ]:
            with self.subTest(names=names):
                groups = {g["name"]: g for g in groups_for_clash(names)}
                self.assertEqual(groups["故障转移"]["proxies"], fallback)
                self.assertEqual("特殊自动" in groups, has_special)
                self.assertEqual("特殊节点" in groups, has_special)
                if has_special:
                    self.assertEqual(groups["特殊自动"]["proxies"], names)
                    self.assertEqual(groups["特殊节点"]["proxies"], names)
                src = "[General]\n[Proxy]\n" + "\n".join(
                    name + " = trojan, example.org, 443, password=x" for name in names
                ) + "\n[Rule]\nFINAL,漏网之鱼\n"
                result = apply_profile_layout(src, "surge")
                line = next(row for row in result.splitlines() if row.startswith("故障转移 = "))
                self.assertEqual(line.split(", ")[1:2], fallback)
                self.assertEqual("特殊自动 = smart," in result, has_special)
                self.assertEqual("特殊节点 = select," in result, has_special)
                self.assertNotIn("国内直连", line)

    def test_singbox_shared_choices_unchanged(self):
        from profile_layout import service_choices
        enabled = ["香港节点", "台湾节点", "日本节点", "狮城节点", "美国节点", "特殊节点"]
        defaults = {"苹果服务": "DIRECT", "港台番剧": "DIRECT", "人工智能": "日本节点",
                    "TikTok": "日本节点", "GitHub": "香港节点", "微软服务": "美国节点"}
        for name in SERVICES:
            normal = [*enabled, "DIRECT"]
            first = defaults.get(name)
            if first in normal:
                normal.remove(first)
                normal.insert(0, first)
            if name == "漏网之鱼":
                normal = ["节点选择", "DIRECT"]
            self.assertEqual(service_choices(name, enabled, "DIRECT"), normal)

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
        self.assertTrue(groups <= set(SERVICES) | {'DIRECT', 'REJECT', '节点选择'})
        for r in data['rulesets']:
            if not r['ruleset'].startswith('[]'):
                self.assertTrue((ROOT / 'subconverter' / r['ruleset']).is_file(), r)
        final = data['rulesets'][-1]
        self.assertEqual((final['group'], final['ruleset']), ('漏网之鱼', '[]FINAL'))
        self.assertFalse((ROOT / '.github/workflows/refresh-backup.yaml').exists())
        self.assertFalse((ROOT / 'subconverter/snippets/groups.toml').exists())
        base = (ROOT / 'subconverter/base/all_base.tpl').read_text(encoding='utf-8')
        self.assertNotIn('#🔰 节点选择', base)
        self.assertEqual(base.count('#节点选择'), 2)


if __name__ == '__main__':
    unittest.main()
