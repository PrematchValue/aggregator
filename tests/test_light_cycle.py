"""No-network tests for the lightweight full-discovery + rotating-execution plan."""
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "subscribe"))
from refresh_rotation import RefreshRotation
from light_geo import locate_once
from discovery import AirportRecord


def candidates(n):
    return {f"https://site{i}.example.org": AirportRecord(f"https://site{i}.example.org") for i in range(n)}


class RotationTests(unittest.TestCase):
    def test_each_run_full_discovery_executes_new_subset(self):
        state = RefreshRotation()
        data = candidates(7)
        visited = []
        for _ in range(5):
            chunk = state.choose(data, 2)
            visited += list(chunk)
            state.advance()
            state = RefreshRotation.load(state.encode())
        self.assertEqual(len(set(visited)), 7)
        self.assertEqual(len(visited), 9)
        self.assertEqual(state.cycle, 1)

    def test_new_candidate_is_included_without_repeating_completed(self):
        state = RefreshRotation()
        first = state.choose(candidates(4), 3)
        state.advance()
        extended = candidates(4)
        extended["https://new.example.org"] = AirportRecord("https://new.example.org")
        second = state.choose(extended, 3)
        self.assertIn("https://new.example.org", second)
        self.assertFalse(set(first) & set(second))

    def test_only_hashed_host_persisted(self):
        state = RefreshRotation()
        state.choose({"https://example.org/secret?token=TOPSECRET": AirportRecord("https://example.org")}, 3)
        state.advance()
        payload = state.encode()
        self.assertNotIn("TOPSECRET", payload)
        self.assertNotIn("example.org", payload)
        self.assertEqual(len(json.loads(payload)["done"]), 1)

    def test_private_hosts_not_queued(self):
        state = RefreshRotation()
        data = {"http://127.0.0.1": AirportRecord("http://127.0.0.1"),
                "https://node.internal": AirportRecord("https://node.internal"),
                "https://good.example.org": AirportRecord("https://good.example.org")}
        self.assertEqual(list(state.choose(data, 10)), ["https://good.example.org"])

    def test_invalid_state_fails_closed(self):
        for raw in ('{"v":2,"cycle":0,"done":[]}', '{"v":1,"cycle":0,"done":["bad"]}', '{"v":1}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                RefreshRotation.load(raw)


class GeoTests(unittest.TestCase):
    def test_country_is_observed_through_proxy(self):
        proxy = {"name":"foo","server":"node.example.org","port":443,"type":"trojan"}
        with patch("light_geo.make_proxy_request", return_value=(True, {"country_code":"JP","country":"JP"})):
            result = locate_once(proxy, 12345)
        self.assertTrue(result.success)
        self.assertEqual(result.result.country, "日本")

    def test_failed_country_query_is_not_treated_as_verified(self):
        proxy = {"name":"foo","server":"node.example.org","port":443,"type":"trojan"}
        with patch("light_geo.make_proxy_request", return_value=(False, {})):
            result = locate_once(proxy, 12345)
        self.assertFalse(result.success)


if __name__ == '__main__':
    unittest.main()
