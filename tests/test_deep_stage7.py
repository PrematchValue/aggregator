"""No-network regressions for broad discovery and true per-proxy checks."""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import copy
import ssl
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "subscribe"))
from candidate_window import window_candidates
from node_health import check_http, classify_failure
from public_sources import SOURCES, _connection_id, _safe_server, gather_public_nodes, parse_feed
from node_labels import relabel_and_sort

GEO = {"JP": "日本", "US": "美国", "HK": "香港"}


def make_proxy(name="demo", server="sample.example.org", kind="trojan"):
    return {"name": name, "type": kind, "server": server, "port": 443, "password": "TEST_SECRET"}


class FeedTests(unittest.TestCase):
    def test_source_urls_are_public_https_allowlisted(self):
        self.assertGreaterEqual(len(SOURCES), 4)
        self.assertEqual(len(SOURCES), len({url for _, url in SOURCES}))
        self.assertTrue(all(url.startswith("https://") and "token=" not in url for _, url in SOURCES))

    def test_only_proxy_mapping_and_no_embedded_subscriptions(self):
        raw = """proxies:
  - name: JP
    type: trojan
    server: n.example.com
    port: 443
    password: x
    sub: https://untrusted.invalid/secret
  - name: second
    type: trojan
    server: n.example.com
    port: 443
    password: x
  - name: bad
    type: direct
    server: 127.0.0.1
    port: 80
proxy-groups:
  - name: 全球直连
    type: select
    proxies: [DIRECT]
"""
        values = parse_feed(raw)
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]["name"], "JP")
        self.assertNotIn("sub", values[0])

    def test_reject_private_literals_hosts_and_malformed(self):
        for host in ("127.0.0.1", "10.0.0.1", "192.168.1.2", "[::1]", "169.254.169.254", "localhost", "host.internal", "bad/name"):
            self.assertFalse(_safe_server({"server": host}), host)
        self.assertTrue(_safe_server({"server": "8.8.8.8"}))
        self.assertTrue(_safe_server({"server": "sub.example.org"}))
        self.assertRaises(ValueError, parse_feed, "[Proxy]\nDIRECT")

    def test_feed_failures_do_not_block_other_sources(self):
        raw = "proxies:\n - {name: safe, server: demo.example.org, port: 443, type: trojan, password: abc}\n"
        def fetch(url):
            if "broken" in url:
                raise TimeoutError()
            return raw
        items, counts = gather_public_nodes(fetch=fetch, sources=(("broken", "https://broken.example.org/feed"), ("one", "https://good.example.org/feed")))
        self.assertEqual(len(items), 1)
        self.assertEqual(counts, {"broken": 0, "one": 1})

    def test_dedup_across_sources_not_by_display_name(self):
        a = make_proxy("first")
        b = dict(a, name="second")
        self.assertEqual(_connection_id(a), _connection_id(b))
        from yaml import safe_dump
        out, _ = gather_public_nodes(fetch=lambda _: safe_dump({"proxies": [a, b]}),
            sources=(("first", "https://one.example.org/feed"), ("second", "https://two.example.org/feed")))
        self.assertEqual(len(out), 1)


class WindowTests(unittest.TestCase):
    def test_covers_every_candidate_without_random_resampling(self):
        records = {f"https://{i}.example.org": i for i in range(22)}
        windows = [window_candidates(records, 7, window=i)[0] for i in range(4)]
        self.assertEqual(set().union(*(set(k for k, _ in w) for w in windows)), set(records))
        self.assertEqual(window_candidates(records, 7, window=0)[0], window_candidates(records, 7, window=4)[0])

    def test_override_can_select_alternate_batch(self):
        records = {f"https://{i}.example.org": i for i in range(9)}
        with patch.dict("os.environ", {"COLLECT_WINDOW": "1"}):
            a, slot = window_candidates(records, 4, today=date(2026, 11, 12))
        self.assertEqual(slot, (1, 3))
        self.assertEqual(a, window_candidates(records, 4, window=1)[0])

    def test_all_small_catalogue_retained(self):
        records = {"https://a.org": 1, "https://b.org": 2}
        vals, slot = window_candidates(records, 6000)
        self.assertEqual({k for k, _ in vals}, set(records))
        self.assertEqual(slot, (0, 1))


class HttpTests(unittest.TestCase):
    def test_204_real_https_is_success(self):
        calls = []
        def request(**kw):
            calls.append((kw["url"], kw["timeout"]))
            return 204, b""
        self.assertEqual(check_http(20000, request=request), (True, "HTTPS请求成功"))
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].startswith("https://"))

    def test_first_target_fails_second_target_ok(self):
        calls = []
        def request(**kw):
            calls.append(kw["url"])
            if len(calls) == 1:
                raise TimeoutError("timed out")
            return 204, b""
        self.assertTrue(check_http(20000, request=request)[0])
        self.assertEqual(len(calls), 2)

    def test_never_counts_arbitrary_200_as_success(self):
        self.assertFalse(check_http(20000, request=lambda **kw: (200, b"hello"))[0])
        self.assertFalse(check_http(20000, request=lambda **kw: (200, b"ip=127.0.0.1"))[0])
        self.assertEqual(classify_failure(ssl.SSLError("handshake error")), "TLS握手失败")

    def test_second_round_has_longer_timeout(self):
        times = []
        def request(**kw):
            times.append(kw["timeout"])
            raise TimeoutError()
        result = check_http(20000, request=request)
        self.assertFalse(result[0])
        self.assertEqual(times, [5, 5, 9, 9])
        self.assertEqual(result[1], "超时")


class RegionTests(unittest.TestCase):
    def test_retry_recovers_vmess_only_on_second_pass(self):
        first = True
        original = make_proxy(kind="vmess")
        def batch(**kw):
            nonlocal first
            p = copy.deepcopy(kw["proxies"][0])
            p["_verified_http"] = True
            region = "" if first else "日本"
            first = False
            return [SimpleNamespace(proxy=p, result=SimpleNamespace(country=region, is_cdn=False), success=bool(region))]
        values, stats = relabel_and_sort([original], countries=GEO,
            batch_query=batch, query_func=lambda *_: None, retry_unknown=True)
        self.assertEqual(values[0]["name"], "🇯🇵 日本 001")
        self.assertEqual(stats["recovered"], 1)
        self.assertNotIn("_verified_http", values[0])

    def test_historical_country_kept_only_if_confirmed_live(self):
        import yaml
        old = make_proxy("🇯🇵 日本 008")
        prior = yaml.safe_dump({"proxies": [old]}, allow_unicode=True)
        def batch(live):
            def run(**kw):
                p = dict(kw["proxies"][0], _verified_http=live)
                return [SimpleNamespace(proxy=p, result=SimpleNamespace(country="", is_cdn=False), success=False)]
            return run
        source = make_proxy()
        kept, _ = relabel_and_sort([source], previous_clash=prior, countries=GEO,
            batch_query=batch(True), query_func=lambda *_: None, retry_unknown=True)
        dead, _ = relabel_and_sort([source], previous_clash=prior, countries=GEO,
            batch_query=batch(False), query_func=lambda *_: None, retry_unknown=True)
        self.assertTrue(kept[0]["name"].startswith("🇯🇵 日本 "))
        self.assertTrue(dead[0]["name"].startswith("🌐 未知地区 "))


if __name__ == "__main__":
    unittest.main()
