"""Offline egress-region tests: never require network or installed Mihomo."""
import sys
import types
from unittest.mock import patch
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "subscribe"))
from egress_region import _fetch_ip_region, _parse_echo, query_country, format_protocol_summary

COUNTRIES = {"HK": "香港", "JP": "日本", "TW": "台湾", "US": "美国", "SG": "新加坡"}
SERVICES = [
    {"url": "https://first.test/geo", "country_key": "country"},
    {"url": "https://second.test/geo", "country_key": "country_code"},
    {"url": "https://third.test/geo", "country_key": "country_code"},
    {"url": "https://fourth.test/geo", "country_key": "country_code"},
]
PROXY = {"name": "8443", "type": "trojan", "server": "example.test", "port": 443}


class QueryCountryTests(unittest.TestCase):
    def query(self, request, direct_fetch=None, services=SERVICES):
        return query_country(PROXY, 47777, request=request, services=services,
                             countries=COUNTRIES, direct_fetch=direct_fetch)

    def test_visits_distinct_providers_before_echo(self):
        called = []
        def fake(**kwargs):
            called.append(kwargs["url"])
            if kwargs["url"] == "https://third.test/geo":
                return True, {"country_code": "JP"}
            return False, {}
        country, src = self.query(fake)
        self.assertEqual((country, src), ("JP", "proxy_geo"))
        self.assertEqual(len(called), len(set(called)))
        self.assertTrue(all(".test" in url for url in called))

    def test_fallback_to_proxied_exit_ip_then_runner_geo(self):
        urls, external = [], []
        def fake(**kwargs):
            urls.append(kwargs["url"])
            if kwargs["url"].endswith("/cdn-cgi/trace"):
                return True, "h=www.cloudflare.com\nip=8.8.8.8\nloc=US\n"
            return False, {}
        def direct(url):
            external.append(url)
            return {"country_code": "HK"}
        self.assertEqual(self.query(fake, direct_fetch=direct), ("HK", "egress_ip_geo"))
        self.assertEqual(external, ["https://ipwho.is/8.8.8.8"])
        self.assertTrue(any("cdn-cgi/trace" in u for u in urls))

    def test_never_locates_entry_ip_or_private_address(self):
        external = []
        def fake(**kwargs):
            return True, "ip=127.0.0.1\n"
        def direct(url):
            external.append(url)
            return {"country_code": "HK"}
        self.assertEqual(self.query(fake, direct_fetch=direct), ("", "proxy_geo_unavailable"))
        self.assertEqual(external, [])

    def test_rejects_country_guess_and_error_json(self):
        def fake(**kwargs):
            return True, {"country_code": "Cloudflare", "success": False}
        self.assertEqual(self.query(fake, direct_fetch=lambda *_: {"country_code": "US"}),
                         ("", "proxy_geo_unavailable"))

    def test_validated_ip_never_replaced_with_entry(self):
        self.assertEqual(_parse_echo("8.8.8.8"), "8.8.8.8")
        self.assertEqual(_parse_echo("ip=10.0.0.2\nloc=US"), "")
        self.assertEqual(_parse_echo({"ip": "127.0.0.1"}), "")
        self.assertEqual(_parse_echo("hello 8.8.8.8"), "")

    def test_failed_geolocation_is_not_mislabeled(self):
        urls = []
        def direct(url):
            urls.append(url)
            return {"country_code": "Cloudflare"}
        self.assertEqual(_fetch_ip_region("8.8.8.8", COUNTRIES, fetch=direct), "")
        self.assertEqual(len(urls), 2)

    def test_no_proxy_connection_is_not_called_dead(self):
        self.assertEqual(self.query(lambda **kw: (False, {})), ("", "proxy_requests_failed"))
        self.assertEqual(query_country(PROXY, 0, request=lambda **kw: None,
                                       services=SERVICES, countries=COUNTRIES),
                         ("", "missing_listener"))

    def test_protocol_diagnostics_does_not_log_hostnames_or_secrets(self):
        report = format_protocol_summary(["trojan", "hysteria2", "trojan", "vmess"],
                                         ["hysteria2", "trojan"])
        self.assertIn("trojan: 原始=2，保留=1，地区未确认=1", report)
        self.assertIn("vmess: 原始=1，保留=0，地区未确认=1", report)

    def test_default_node_label_query_uses_new_fallback(self):
        from node_labels import relabel_and_sort
        stub = types.ModuleType("location")
        stub.batch_query = lambda **kwargs: []
        seen = []
        def batch(**kwargs):
            seen.append(kwargs["func"])
            return []
        with patch.dict(sys.modules, {"location": stub}), \
             patch("egress_region.locate_with_fallback") as improved:
            values, counts = relabel_and_sort([dict(PROXY)], countries=COUNTRIES,
                                               batch_query=batch)
            self.assertEqual(seen, [improved])
            self.assertEqual(counts["unknown"], 1)

    def test_non_global_ip_never_requested_directly(self):
        urls = []
        self.assertEqual(_fetch_ip_region("169.254.169.254", COUNTRIES,
                                          fetch=lambda url: urls.append(url)), "")
        self.assertEqual(urls, [])


if __name__ == "__main__":
    unittest.main()
