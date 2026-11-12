"""Stage 9 no-network regressions for damaged Mihomo batches and history."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "subscribe"))
from batch_isolation import inspect_with_isolation
from node_history import previous_confirmed_candidates
from node_labels import relabel_and_sort


def proxy(i: int, label: str | None = None) -> dict:
    return {"name": label or f"name{i}", "server": f"node{i}.example.org",
            "type": "trojan", "port": 443, "password": f"dummy{i}"}


def response(node, country="", live=True):
    return SimpleNamespace(proxy=dict(node, _verified_http=live),
                           result=SimpleNamespace(country=country, is_cdn=False),
                           success=bool(country))


class IsolationTests(unittest.TestCase):
    def test_one_invalid_proxy_does_not_discard_good_peers(self):
        source = [proxy(i) for i in range(55)]
        bad = "node18.example.org"
        seen = []
        def batch(nodes):
            seen.append(len(nodes))
            if any(x["server"] == bad for x in nodes):
                return [SimpleNamespace(proxy=x, success=False) for x in nodes]
            return [response(x, country="日本") for x in nodes]
        found, stats, unresolved = inspect_with_isolation(source, batch, lambda p: p["server"])
        self.assertEqual(len(found), 54)
        self.assertEqual(unresolved, {bad})
        self.assertGreater(stats["splits"], 1)
        self.assertIn(1, seen)

    def test_real_http_failure_does_not_cause_splits(self):
        nodes = [proxy(i) for i in range(50)]
        found, stats, unresolved = inspect_with_isolation(nodes,
            lambda xs: [response(p, live=False) for p in xs],
            lambda p: p["server"])
        self.assertEqual(len(found), 50)
        self.assertEqual(stats["attempts"], 1)
        self.assertEqual(stats["splits"], 0)
        self.assertFalse(unresolved)

    def test_partial_callback_results_isolate_missing_only(self):
        nodes = [proxy(i) for i in range(8)]
        calls = []
        def batch(xs):
            calls.append([n["server"] for n in xs])
            return [response(p) for p in xs if p["server"] != "node3.example.org"]
        found, stats, failed = inspect_with_isolation(nodes, batch, lambda p: p["server"])
        self.assertEqual(len(found), 7)
        self.assertEqual(failed, {"node3.example.org"})
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(calls[1]), 1)
        self.assertEqual(stats["splits"], 1)

    def test_callback_exception_is_isolated(self):
        source = [proxy(i) for i in range(9)]
        def batch(xs):
            if any(x["server"] == "node7.example.org" for x in xs):
                raise RuntimeError("bad config")
            return [response(p) for p in xs]
        found, _, failed = inspect_with_isolation(source, batch, lambda p: p["server"])
        self.assertEqual(len(found), 8)
        self.assertEqual(failed, {"node7.example.org"})

    def test_remote_health_marker_never_skips_real_testing(self):
        source = [dict(proxy(11), _verified_http=True)]
        def never_started(**kw):
            # Mihomo did not start: returns source config without a real probe.
            return [SimpleNamespace(proxy=x, success=False) for x in kw["proxies"]]
        nodes, stats = relabel_and_sort(source, countries={"JP": "日本"},
            batch_query=never_started, query_func=lambda *_: None,
            retry_unknown=True)
        self.assertEqual(stats["live"], 0)
        self.assertEqual(stats["unprobed"], 1)
        self.assertTrue(nodes[0]["name"].startswith("🌐 未知地区 "))
        self.assertEqual(source[0]["_verified_http"], True)  # source untouched

    def test_geo_integration_retries_isolated_healthy_nodes(self):
        source = [proxy(i) for i in range(6)]
        bad = "node1.example.org"
        def batch(**kwargs):
            xs = kwargs["proxies"]
            if len(xs) > 1 and any(x["server"] == bad for x in xs):
                return [SimpleNamespace(proxy=x, success=False) for x in xs]
            if xs[0]["server"] == bad:
                return [SimpleNamespace(proxy=xs[0], success=False)]
            return [response(x, country="JP") for x in xs]
        values, stats = relabel_and_sort(source, countries={"JP":"日本"},
            batch_query=batch, query_func=lambda *_: None, chunk_size=6, retry_unknown=True)
        self.assertEqual(sum(x["name"].startswith("🇯🇵") for x in values), 5)
        self.assertEqual(stats["unprobed"], 1)
        self.assertGreater(stats["isolated_splits"], 1)


class HistoryTests(unittest.TestCase):
    def test_previous_verified_nodes_become_candidates_not_automatic_pass(self):
        old = proxy(1, "🇯🇵 日本 001")
        old["password"] = "secret-previous"
        content = yaml.safe_dump({"proxies": [old, proxy(2, "🌐 未知地区 001")]}, allow_unicode=True)
        recovered = previous_confirmed_candidates(content)
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["password"], "secret-previous")
        recovered[0]["password"] = "changed"
        self.assertEqual(old["password"], "secret-previous")
        def no_connection(**kwargs):
            return [response(kwargs["proxies"][0], country="", live=False)]
        values, _ = relabel_and_sort(previous_confirmed_candidates(content), previous_clash=content,
            countries={"JP": "日本"}, batch_query=no_connection, query_func=lambda *_: None,
            retry_unknown=True)
        self.assertEqual(values[0]["name"], "🌐 未知地区 001")

    def test_malformed_old_gist_is_ignored(self):
        for raw in ("", "proxies: [bad]", "proxies: [", "- test", "{}"):
            self.assertEqual(previous_confirmed_candidates(raw), [])


if __name__ == "__main__":
    unittest.main()
