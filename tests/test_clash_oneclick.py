"""Regression tests for the default, directly importable Mihomo profile."""
from __future__ import annotations

from pathlib import Path
import re
import tomllib
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


def simplified_clash_template() -> dict:
    """Parse the statically written Clash section without invoking SubConverter.

    This validates YAML structure; actual SubConverter output needs smoke-testing
    in the GitHub runner and a supported Mihomo client.
    """
    contents = (ROOT / "subconverter/base/all_base.tpl").read_text(encoding="utf-8")
    clash = contents.split('{% if request.target == "surge" %}', 1)[0]
    clash = re.sub(r"(?m)^\{%.*?%\}\n", "", clash)
    clash = re.sub(r'\{\{\s*default\([^,]+,\s*"([^"]+)"\)\s*\}\}', r'\1', clash)
    return yaml.safe_load(clash)


class ClashOneClickTests(unittest.TestCase):
    def test_dns_is_enabled_unconditionally_and_well_formed(self):
        contents = (ROOT / "subconverter/base/all_base.tpl").read_text(encoding="utf-8")
        self.assertNotIn('default(request.clash.dns', contents.split('{% if request.target == "surge" %}')[0])
        profile = simplified_clash_template()
        dns = profile["dns"]
        self.assertTrue(dns["enable"])
        self.assertFalse(dns["ipv6"])
        self.assertEqual(dns["enhanced-mode"], "fake-ip")
        self.assertEqual(dns["listen"], "127.0.0.1:1053")
        self.assertIn("geosite:cn,private", dns["nameserver-policy"])
        self.assertEqual(len(dns["proxy-server-nameserver"]), 2)
        self.assertTrue(all("#🔰 节点选择" in x for x in dns["nameserver"]))
        self.assertIn("+.lan", dns["fake-ip-filter"])
        self.assertIn("captive.apple.com", dns["fake-ip-filter"])

    def test_selected_dns_proxy_group_exists_and_auto_selects_by_default(self):
        config = tomllib.loads((ROOT / "subconverter/snippets/groups.toml").read_text(encoding="utf-8"))
        groups = {group["name"]: group for group in config["custom_groups"]}
        self.assertIn("🔰 节点选择", groups)
        self.assertIn("♻️ 自动选择", groups)
        self.assertEqual(groups["♻️ 自动选择"]["type"], "url-test")
        self.assertEqual(groups["🔰 节点选择"]["rule"][0], "[]♻️ 自动选择")

    def test_existing_rule_groups_and_rule_template_preserved(self):
        rules = tomllib.loads((ROOT / "subconverter/snippets/rulesets.toml").read_text(encoding="utf-8"))
        groups = tomllib.loads((ROOT / "subconverter/snippets/groups.toml").read_text(encoding="utf-8"))
        names = {group["name"] for group in groups["custom_groups"]}
        for rule in rules["rulesets"]:
            self.assertIn(rule["group"], names)
        self.assertEqual(rules["rulesets"][-1]["ruleset"], "[]FINAL")

    def test_lan_is_disabled_by_default_without_affecting_other_targets(self):
        template = simplified_clash_template()
        self.assertIs(template["allow-lan"], False)
        pref = tomllib.loads((ROOT / "subconverter/pref.toml").read_text(encoding="utf-8"))
        globals_by_name = {entry["key"]: entry["value"] for entry in pref["template"]["globals"]}
        self.assertEqual(globals_by_name["clash.allow_lan"], "false")
        self.assertEqual(globals_by_name["singbox.allow_lan"], "false")


if __name__ == "__main__":
    unittest.main()
