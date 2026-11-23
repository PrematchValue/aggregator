"""Regression for overlapping Bilibili routes, cold-wallet scope and sing-box outputs."""
from __future__ import annotations

import json
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "subscribe"))
from singbox_layout import apply_singbox_layout


def match_rule(domain: str, expression: str) -> bool:
    kind, _, arg = expression.partition(",")
    domain = domain.lower().strip(".")
    arg = arg.lower().strip(".")
    if kind == "DOMAIN":
        return domain == arg
    if kind == "DOMAIN-SUFFIX":
        return domain == arg or domain.endswith("." + arg)
    if kind == "DOMAIN-KEYWORD":
        return arg in domain
    return False


def route_domain(domain: str) -> str:
    registry = tomllib.loads((ROOT / "subconverter/snippets/rulesets.toml").read_text(encoding="utf-8"))
    for entry in registry["rulesets"]:
        rel = entry["ruleset"]
        if rel.startswith("[]"):
            continue
        for raw in (ROOT / "subconverter" / rel).read_text(encoding="utf-8").splitlines():
            if raw and not raw.startswith("#") and match_rule(domain, raw):
                return entry["group"]
    return "漏网之鱼"


class TargetedRoutingTests(unittest.TestCase):
    def test_bilibili_region_and_domestic_mainland_media_do_not_overlap_undesirably(self):
        for domain in ("api.bilibili.com", "app.bilibili.com",
                       "upos-hz-mirrorakam.akamaized.net",
                       "www.bilibili.com", "m.bilibili.com", "api.biliapi.net",
                       "grpc.biliapi.net", "cn-hk-eq-bcache-11.example.net",
                       "cache.video.iqiyi.com", "mobileso.bz.mgtv.com"):
            with self.subTest(domain=domain):
                self.assertEqual(route_domain(domain), "港台番剧")
        # The original Streaming/CN rule-set is intentionally selective.
        # Do not force whole Bilibili/CDN suffixes to DIRECT before GEOIP/fallback.
        for domain in ("data.bilibili.com", "show.bilibili.com",
                       "mall.bilibili.com", "member.bilibili.com",
                       "upos-sz-mirrorali.bilivideo.com", "static.hdslb.com"):
            with self.subTest(domain=domain):
                self.assertNotEqual(route_domain(domain), "DIRECT")
        self.assertEqual(route_domain("www.iqiyi.com"), "DIRECT")
        direct = (ROOT / "subconverter/rules/custom/ChinaDirect.list").read_text(encoding="utf-8")
        for suffix in ("bilibili.com", "bilivideo.com", "hdslb.com"):
            self.assertNotIn(f"DOMAIN-SUFFIX,{suffix}\n", direct)
        regional = (ROOT / "subconverter/rules/auto/StreamingCN.list").read_text(encoding="utf-8")
        self.assertNotIn("DOMAIN-SUFFIX,bilivideo.com", regional)
        self.assertNotIn("DOMAIN-SUFFIX,hdslb.com", regional)

    def test_cold_wallet_matches_wallet_and_rpc_not_dex_or_explorers(self):
        for domain in ("api.ledger.com", "connect.trezor.io",
                       "metamask.io", "rpc.ankr.com", "ethereum.publicnode.com"):
            with self.subTest(domain=domain):
                self.assertEqual(route_domain(domain), "冷钱包")
        for domain in ("app.uniswap.org", "etherscan.io", "solana.com", "blockchair.com"):
            with self.subTest(domain=domain):
                self.assertNotEqual(route_domain(domain), "冷钱包")

    def test_singbox_dns_detour_and_service_groups_resolve(self):
        source = {
            "dns": {"servers": [{"type": "https", "tag": "dns_proxy",
                                  "server": "1.1.1.1", "detour": "🔰 节点选择"}]},
            "outbounds": [
                {"tag": "DIRECT", "type": "direct"},
                {"tag": "REJECT", "type": "block"},
                {"tag": "dns-out", "type": "dns"},
                {"tag": "🇭🇰 香港 001", "type": "shadowsocks", "server": "hk.example"},
                {"tag": "🇸🇬 新加坡 001", "type": "trojan", "server": "sg.example"},
                {"tag": "🇩🇪 德国 001", "type": "vless", "server": "de.example"}],
            "route": {"rules": [{"protocol": "dns", "outbound": "dns-out"},
                                  {"domain_suffix": "ledger.com", "outbound": "冷钱包"}]}
        }
        result = json.loads(apply_singbox_layout(json.dumps(source)))
        tags = {o["tag"]: o for o in result["outbounds"]}
        self.assertEqual(result["dns"]["servers"][0]["detour"], "节点选择")
        self.assertEqual(tags["节点选择"]["outbounds"], ["香港节点", "狮城节点", "特殊节点"])
        self.assertEqual(tags["香港节点"]["type"], "urltest")
        self.assertEqual(tags["特殊节点"]["type"], "selector")
        self.assertEqual(tags["冷钱包"]["outbounds"][-1], "DIRECT")
        self.assertEqual(tags["漏网之鱼"]["outbounds"], ["节点选择", "DIRECT"])
        self.assertNotIn("国内直连", tags)
        self.assertNotIn("REJECT", tags)
        self.assertNotIn("GLOBAL", tags)
        self.assertNotIn("dns-out", tags)
        self.assertEqual(result["route"]["rules"][0]["action"], "hijack-dns")
        self.assertEqual(result["route"]["final"], "漏网之鱼")
        self.assertEqual(tags["🇸🇬 新加坡 001"]["server"], "sg.example")

    def test_singbox_missing_native_direct_and_legacy_reject_are_normalized(self):
        config = {
            "dns": {"servers": [{"tag": "dns_proxy", "type": "https"}]},
            "outbounds": [{"tag": "🇯🇵 日本 001", "type": "trojan"}],
            "route": {"rules": [{"domain_suffix": "ads.example", "outbound": "REJECT"},
                                {"domain_suffix": "cn", "outbound": "DIRECT"}]}
        }
        result = json.loads(apply_singbox_layout(json.dumps(config)))
        tags = {o["tag"]: o for o in result["outbounds"]}
        self.assertEqual(tags["DIRECT"]["type"], "direct")
        self.assertNotIn("国内直连", tags)
        self.assertNotIn("REJECT", tags)
        self.assertEqual(result["route"]["rules"][0]["action"], "reject")
        self.assertNotIn("outbound", result["route"]["rules"][0])
        self.assertEqual(result["route"]["rules"][1]["outbound"], "DIRECT")

    def test_singbox_reject_final_keeps_a_valid_fallback(self):
        config = {
            "dns": {"servers": [{"tag": "dns_proxy", "type": "https"}]},
            "outbounds": [{"tag": "🇯🇵 日本 001", "type": "trojan"}],
            "route": {"rules": [], "final": "REJECT"}
        }
        result = json.loads(apply_singbox_layout(json.dumps(config)))
        self.assertEqual(result["route"]["final"], "DIRECT")
        self.assertEqual(result["route"]["rules"][-1], {"action": "reject"})

    def test_singbox_uses_correct_template_and_conversion_hook(self):
        template = (ROOT / "subconverter/base/all_base.tpl").read_text(encoding="utf-8")
        self.assertNotIn('\"detour\": \"🔰 节点选择\"', template)
        self.assertIn('\"detour\": \"节点选择\"', template)
        pref = (ROOT / "subconverter/pref.toml").read_text(encoding="utf-8")
        self.assertIn("singbox_add_clash_modes = false", pref)
        collect = (ROOT / "subscribe/collect.py").read_text(encoding="utf-8")
        self.assertIn("apply_singbox_layout(profile)", collect)

    def test_singbox_fail_closed_on_missing_dns_or_invalid_route(self):
        with self.assertRaises(ValueError):
            apply_singbox_layout(json.dumps({"outbounds": [{"tag": "🇯🇵 日本 001",
                                                            "type": "trojan"}], "route": {}}))
        broken = {"outbounds": [{"tag": "🇯🇵 日本 001", "type": "trojan"}],
                  "dns": {"servers": [{"tag": "dns_proxy", "type": "https"}]},
                  "route": {"rules": [{"outbound": "missing_policy"}]}}
        with self.assertRaisesRegex(ValueError, "missing outbound"):
            apply_singbox_layout(json.dumps(broken))


if __name__ == "__main__":
    unittest.main()
