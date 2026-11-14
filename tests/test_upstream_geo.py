"""Offline tests for the thin presentation layer, without network or Mihomo."""
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "subscribe"))
from geo_labels import label_verified_nodes


class GeoLabelTests(unittest.TestCase):
    def setUp(self):
        countries = {"HK": "香港", "JP": "日本", "US": "美国", "SG": "新加坡"}

        def batch_query(proxies, func, **kwargs):
            results = []
            for proxy in reversed(proxies):
                region = {"alpha": "日本", "beta": "香港", "gamma": "日本", "unknown": ""}.get(proxy["server"], "")
                info = types.SimpleNamespace(country=region, is_cdn=False)
                results.append(types.SimpleNamespace(proxy=proxy, result=info, success=bool(region)))
            return results

        m = types.SimpleNamespace(ISO_TO_CHINESE=countries, batch_query=batch_query,
                                  locate_by_ipinfo=lambda x: x)
        p = patch.dict(sys.modules, {"location": m})
        p.start()
        self.addCleanup(p.stop)

    def test_region_order_flags_and_preserved_protocol(self):
        nodes = [{"name": "ignored", "server": "alpha", "port": 443, "type": "vless", "uuid": "secret", "sub": "private"},
                 {"name": "ignored", "server": "beta", "port": 443, "type": "trojan", "password": "secret"},
                 {"name": "ignored", "server": "gamma", "port": 443, "type": "ss", "cipher": "aes-128-gcm", "password": "secret"},
                 {"name": "ignored", "server": "unknown", "port": 443, "type": "vmess"}]
        result, stats = label_verified_nodes(nodes, chunk_size=2)
        self.assertEqual(stats, {"checked": 4, "kept": 3, "unknown": 1})
        self.assertEqual([n["name"] for n in result], ["🇭🇰 香港 001", "🇯🇵 日本 001", "🇯🇵 日本 002"])
        self.assertEqual({n["type"] for n in result}, {"vless", "trojan", "ss"})
        self.assertTrue(all("sub" not in n for n in result))
        self.assertEqual(nodes[0]["name"], "ignored")
        self.assertEqual(next(n for n in result if n["type"] == "vless")["uuid"], "secret")

    def test_empty_input(self):
        nodes, stats = label_verified_nodes([])
        self.assertEqual(nodes, [])
        self.assertEqual(stats["checked"], 0)


class WorkflowTests(unittest.TestCase):
    def test_full_refresh_reuses_upstream_collector(self):
        content = (Path(__file__).resolve().parents[1] / ".github/workflows/refresh.yaml").read_text()
        self.assertIn('17 */4 * * *', content)
        self.assertNotIn('47 */4 * * *', content)
        standby = (Path(__file__).resolve().parents[1] / ".github/workflows/refresh-backup.yaml").read_text()
        self.assertIn('47 1-23/4 * * *', standby)
        self.assertIn(' --geo-rename ', content)
        self.assertNotIn('--stage-output', content)
        self.assertNotIn('--publish-stage', content)
        self.assertNotIn('--max-candidates', content)

    def test_weekly_checks_upstream_only(self):
        content = (Path(__file__).resolve().parents[1] / ".github/workflows/collect.yaml").read_text()
        self.assertIn('name: Weekly Upstream Check', content)
        self.assertNotIn('candidate-stage.json', content)
        self.assertNotIn('  process:', content)


if __name__ == '__main__':
    unittest.main()
