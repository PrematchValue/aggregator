"""Offline regression tests: never open sockets, never require Mihomo."""
import copy
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "subscribe"))
from node_labels import identity, relabel_and_sort

COUNTRIES = {"HK": "香港", "TW": "台湾", "JP": "日本", "SG": "新加坡", "US": "美国", "GB": "英国"}


def node(n, name="8443-1C"):
    return {"name": name, "type": "trojan", "server": f"n{n}.example.org",
            "port": 8443, "password": f"secret-{n}", "sub": "https://private.example/token"}


def detector(region_by_host):
    def run(*, proxies, **_):
        result = []
        for p in proxies:
            region = region_by_host.get(p["server"])
            result.append(SimpleNamespace(proxy=p, result=SimpleNamespace(country=region, is_cdn=False),
                                          success=bool(region)))
        return result
    return run


class NodeLabelTests(unittest.TestCase):
    def label(self, nodes, regions, previous="", batch=None):
        return relabel_and_sort(nodes, previous_clash=previous,
                                countries=COUNTRIES, batch_query=batch or detector(regions),
                                query_func=lambda *_: None, chunk_size=2)

    def test_egress_region_not_numeric_name_or_entry_host(self):
        proxies = [node(1, "8443-1C"), node(2, "8443-1D"), node(3, "8443-1E")]
        previous = copy.deepcopy(proxies)
        nodes, counts = self.label(proxies, {"n1.example.org": "HK", "n2.example.org": "TW"})
        self.assertEqual([n["name"] for n in nodes], ["🇭🇰 香港 001", "🇹🇼 台湾 001", "🌐 未知地区 001"])
        self.assertEqual(counts, {"total": 3, "fresh": 2, "historical": 0, "unknown": 1})
        self.assertEqual(proxies, previous)
        self.assertEqual({n["password"] for n in nodes}, {"secret-1", "secret-2", "secret-3"})
        self.assertTrue(all(n["sub"] == "https://private.example/token" for n in nodes))

    def test_stable_order_without_previous_gist(self):
        source = [node(11), node(12), node(13)]
        one, _ = self.label(source, {p["server"]: "JP" for p in source})
        two, _ = self.label(list(reversed(source)), {p["server"]: "JP" for p in source})
        self.assertEqual([(n["name"], n["server"]) for n in one],
                         [(n["name"], n["server"]) for n in two])

    def test_refresh_reindexes_contiguously_even_with_previous_labels(self):
        old_source = [node(10), node(20)]
        old_names, _ = self.label(old_source, {p["server"]: "HK" for p in old_source})
        previous = yaml.safe_dump({"proxies": [{k: v for k, v in p.items() if k != "sub"}
                                              for p in old_names]}, allow_unicode=True)
        new_names, counts = self.label([node(30), node(20), node(10)], {"n30.example.org": "HK"}, previous)
        self.assertEqual([p["name"] for p in new_names],
                         ["🇭🇰 香港 001", "🇭🇰 香港 002", "🇭🇰 香港 003"])
        self.assertEqual({p["server"] for p in new_names},
                         {"n10.example.org", "n20.example.org", "n30.example.org"})
        self.assertEqual(counts["historical"], 2)

    def test_refresh_reindexes_when_a_node_disappears(self):
        old = node(99)
        old["name"] = "🇯🇵 日本 009"
        previous = yaml.safe_dump({"proxies": [{k: v for k, v in old.items() if k != "sub"}]},
                                  allow_unicode=True)
        new_names, counts = self.label([node(99)], {}, previous)
        self.assertEqual(new_names[0]["name"], "🇯🇵 日本 001")
        self.assertEqual(counts["historical"], 1)

    def test_failed_lookup_preserves_count_and_unknown(self):
        source = [node(5), node(6)]
        def fail(**_):
            raise RuntimeError("network down")
        values, counts = self.label(source, {}, batch=fail)
        self.assertEqual(len(values), 2)
        self.assertEqual([p["name"] for p in values], ["🌐 未知地区 001", "🌐 未知地区 002"])
        self.assertEqual(counts["unknown"], 2)

    def test_region_move_overrides_history(self):
        original = [node(9)]
        previous_node = dict(original[0], name="🇭🇰 香港 007")
        previous = yaml.safe_dump({"proxies": [{k: v for k, v in previous_node.items() if k != "sub"}]}, allow_unicode=True)
        values, _ = self.label(original, {"n9.example.org": "JP"}, previous)
        self.assertEqual(values[0]["name"], "🇯🇵 日本 001")

    def test_identity_does_not_depend_on_name_or_subscription_url(self):
        a = node(1)
        b = dict(a, name="香港", sub="https://another.invalid/sub", cdn=True)
        self.assertEqual(identity(a), identity(b))

    def test_cloudflare_is_not_inferred_to_america(self):
        source = [node(1)]
        values, _ = self.label(source, {"n1.example.org": "Cloudflare"})
        self.assertEqual(values[0]["name"], "🌐 未知地区 001")


if __name__ == "__main__":
    unittest.main()
