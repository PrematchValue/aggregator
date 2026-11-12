"""Security and fail-safe regressions for the Aggregator fork."""
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "subscribe"))
import collect
import collect_safety as safety
from crawl import helpers


class SubscriptionHeaderTests(unittest.TestCase):
    def test_valid_quota(self):
        self.assertEqual(helpers.is_expired("upload=10; download=20; total=100"), (True, False))
        self.assertEqual(helpers.is_expired("upload=60; download=40; total=100"), (False, False))

    def test_real_expiration(self):
        with patch.object(helpers.time, "time", return_value=1_700_000_000):
            self.assertEqual(helpers.is_expired("upload=1;download=0;total=100;expire=1699999999"), (False, True))
            self.assertEqual(helpers.is_expired("upload=1;download=0;total=100;expire=1700100000"), (True, False))

    def test_untrusted_expression_is_never_executed(self):
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / "should_not_exist"
            injection = "upload=0;download=0;total=100;expire=__import__('pathlib').Path(%r).touch()" % str(marker)
            self.assertEqual(helpers.is_expired(injection), (True, False))
            self.assertFalse(marker.exists())

    def test_invalid_metadata_is_not_expiry_proof(self):
        for header in ["upload=1/0;total=100", "total=-100", "total=99999999999999999999999", "total=10", "total=abc"]:
            with self.subTest(header=header):
                self.assertEqual(helpers.is_expired(header), (True, False))

    @patch("crawl.helpers.urllib.request.urlopen", side_effect=socket.timeout("timeout"))
    @patch("crawl.helpers.utils.is_suspicious_url", return_value=False)
    def test_network_timeout_is_unknown_not_expired(self, suspicious, urlopen):
        self.assertEqual(helpers.check_status("https://example.invalid/sub", retry=1), (False, False))


class RefreshSourceTests(unittest.TestCase):
    @patch("collect.check_status", return_value=(False, False))
    def test_transient_failure_preserves_source_for_retry(self, check):
        with tempfile.TemporaryDirectory() as work, patch.object(collect, "DATA_BASE", work):
            unresolved = set()
            tasks = collect.assign("converter", refresh=True, subscribes_file="subscribes.txt",
                                   existing_subscriptions={"https://example.org/sub"}, display=False,
                                   unresolved_sources=unresolved)
            self.assertEqual(len(tasks), 1)
            self.assertEqual(tasks[0].nodes.subscribe_list(), ["https://example.org/sub"])
            self.assertEqual(unresolved, {"https://example.org/sub"})

    @patch("collect.pipeline.assign_sites", return_value=([], {}))
    @patch("collect.collect_airport", return_value={})
    @patch("collect.check_status", return_value=(False, False))
    def test_transient_failure_does_not_block_collect(self, check, discovery, sites):
        with tempfile.TemporaryDirectory() as work, patch.object(collect, "DATA_BASE", work):
            tasks = collect.assign("converter", refresh=False, overwrite=True,
                                   subscribes_file="subscribes.txt",
                                   existing_subscriptions={"https://example.org/sub"}, display=False)
            self.assertEqual(len(tasks), 1)
            discovery.assert_called_once()

    @patch("collect.utils.multi_thread_run", return_value=[])
    def test_missing_status_results_are_transient_not_expiry(self, runner):
        with tempfile.TemporaryDirectory() as work, patch.object(collect, "DATA_BASE", work):
            tasks = collect.assign("converter", refresh=True,
                                   subscribes_file="subscribes.txt",
                                   existing_subscriptions={"https://example.org/sub"}, display=False)
            self.assertEqual(len(tasks), 1)

    @patch("collect.check_status", return_value=(False, True))
    def test_explicit_expiry_still_removes_source(self, check):
        with tempfile.TemporaryDirectory() as work, patch.object(collect, "DATA_BASE", work):
            self.assertEqual(collect.assign("converter", refresh=True, subscribes_file="subscribes.txt", existing_subscriptions={"https://example.org/sub"}, display=False), [])

    @patch("collect.check_status", return_value=(True, False))
    def test_healthy_sources_remain_refreshable(self, check):
        with tempfile.TemporaryDirectory() as work, patch.object(collect, "DATA_BASE", work):
            tasks = collect.assign("converter", refresh=True, subscribes_file="subscribes.txt", existing_subscriptions={"https://example.org/sub"}, display=False)
            self.assertEqual(len(tasks), 1)


if __name__ == "__main__":
    unittest.main()
