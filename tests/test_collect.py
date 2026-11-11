import argparse
import base64
import copy
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "subscribe"))
import collect
import collect_safety as safety
import discovery
import yaml


def node(index=0):
    return {"name": f"node-{index}", "type": "trojan", "server": f"node{index}.example.com",
            "port": 443, "password": "test-only", "sub": "https://source.example/sub"}


def artifact(count=4):
    return yaml.safe_dump({"proxies": [node(i) for i in range(count)]})


class SafetyTests(unittest.TestCase):
    def test_structure_filters_and_does_not_mutate(self):
        source = [node(), dict(node(), port=0), dict(node(), password=""), {"type": "direct"}, None]
        original = copy.deepcopy(source)
        self.assertEqual(len(safety.valid_nodes(source)), 1)
        self.assertEqual(source, original)

    def test_default_formats(self):
        self.assertEqual(safety.artifact_count(artifact(), "clash"), 4)
        self.assertEqual(safety.artifact_count(json.dumps({"outbounds": [{"type": "trojan", "server": "example.com"}]}), "singbox"), 1)
        uri = "trojan://test-only@example.com:443#example"
        self.assertEqual(safety.artifact_count(base64.b64encode(uri.encode()).decode(), "v2ray"), 1)
        self.assertEqual(safety.artifact_count(uri, "mixed"), 1)
        self.assertEqual(safety.artifact_count("[Proxy]\nExample = trojan, example.com, 443, password=test-only\n[Proxy Group]\nAuto = select, Example", "surge"), 1)

    def test_bad_formats_rejected(self):
        for target, content in [("clash", "proxies: []"), ("clash", "proxies: [bad]"),
                                ("singbox", '{"outbounds": []}'), ("v2ray", "not-a-subscription"),
                                ("clash", "<html>error</html>"), ("v2ray", ""), ("surge", "[Proxy]\nDIRECT = direct")]:
            with self.subTest(target=target, content=content), self.assertRaises(safety.PublicationError):
                safety.artifact_count(content, target)

    def test_drop_guard_boundary(self):
        previous = {"clash.yaml": artifact(4)}
        safety.check_publication({"clash.yaml": ("clash", artifact(2))}, previous, {"https://a.example/sub"})
        with self.assertRaises(safety.PublicationError):
            safety.check_publication({"clash.yaml": ("clash", artifact(1))}, previous, {"https://a.example/sub"})

    def test_new_sources_cannot_hide_old_source_loss(self):
        previous = {"subscribes.txt": "https://a.example/sub\nhttps://b.example/sub"}
        with self.assertRaises(safety.PublicationError):
            safety.check_publication({"clash.yaml": ("clash", artifact())}, previous, {"https://new.example/sub"})

    def test_empty_sources_rejected(self):
        with self.assertRaises(safety.PublicationError):
            safety.check_publication({"clash.yaml": ("clash", artifact())}, {}, set())

    @patch("collect_safety.urllib.request.build_opener")
    def test_baseline_failure_is_closed_and_redacted(self, opener):
        opener.return_value.open.side_effect = OSError("secret-token")
        with self.assertRaises(safety.PublicationError) as caught:
            safety.read_gist("aabbcc", "secret-token")
        self.assertNotIn("secret-token", str(caught.exception))

    @patch("collect_safety.urllib.request.build_opener")
    def test_truncated_baseline_never_forwards_token(self, opener):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.side_effect = [json.dumps({"updated_at": "v1", "files": {"clash.yaml": {
            "truncated": True, "raw_url": "https://gist.githubusercontent.com/user/id/raw/rev/clash.yaml"}}}).encode(), artifact().encode()]
        opener.return_value.open.return_value = response
        revision, files = safety.read_gist("aabbcc", "secret-token")
        self.assertEqual(revision, "v1")
        self.assertEqual(files["clash.yaml"], artifact())
        calls = opener.return_value.open.call_args_list
        self.assertEqual(calls[0].args[0].get_header("Authorization"), "Bearer secret-token")
        self.assertIsNone(calls[1].args[0].get_header("Authorization"))

    @patch("collect_safety.socket.socket")
    @patch("collect_safety.socket.getaddrinfo")
    def test_probe_never_connects_private_or_mixed_answers(self, resolve, connection):
        for address in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1"]:
            resolve.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]
            self.assertEqual(safety.tcp_probe(node()), "skipped")
        resolve.return_value.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)))
        self.assertEqual(safety.tcp_probe(node()), "skipped")
        connection.assert_not_called()

    @patch("collect_safety.socket.getaddrinfo")
    def test_udp_not_tcp_probed(self, resolve):
        self.assertEqual(safety.tcp_probe(dict(node(), type="hysteria2")), "skipped")
        resolve.assert_not_called()


class AssignmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        patcher = patch.object(collect, "DATA_BASE", self.temp.name)
        patcher.start()
        self.addCleanup(patcher.stop)

    @patch("collect.collect_airport")
    @patch("collect.check_status", return_value=(False, False))
    def test_refresh_empty_never_discovers(self, status, discover):
        for sources in (set(), {"https://source.example/sub"}):
            self.assertEqual(collect.assign("converter", refresh=True, overwrite=True,
                                           subscribes_file="subscribes.txt", existing_subscriptions=sources), [])
        discover.assert_not_called()

    @patch("collect.collect_airport")
    @patch("collect.check_status", return_value=(True, False))
    def test_refresh_preserves_existing_task(self, status, discover):
        tasks = collect.assign("converter", refresh=True, subscribes_file="subscribes.txt",
                               existing_subscriptions={"https://source.example/sub"})
        self.assertEqual(len(tasks), 1)
        discover.assert_not_called()

    def test_candidate_budget_deduplicates_and_excludes(self):
        domains = ["https://known.example", "http://known.example", "https://one.example", "https://two.example"]
        records = {x: discovery.AirportRecord(x) for x in domains}
        selected = collect.select_candidates(records, {"known.example"}, 1)
        self.assertEqual(list(selected), ["https://one.example"])

    @patch("collect.pipeline.assign_sites", return_value=([], {}))
    @patch("collect.collect_airport", return_value={})
    def test_failed_overwrite_does_not_scan_old_catalogue(self, discover, assign):
        Path(self.temp.name, "domains.txt").write_text("https://stale.example")
        self.assertEqual(collect.assign("converter", overwrite=True), [])
        assign.assert_not_called()

    def test_discovery_caps_before_backend_probes(self):
        source, resolver, validator = Mock(), Mock(), Mock()
        source.persist = False
        source.crawl.return_value = [discovery.AirportRecord(f"https://site{i}.example") for i in range(20)]
        resolver.resolve.side_effect = lambda domain: domain
        validator.validate.return_value = (True, "/api/v1/")
        collector = discovery.AirportCollector([source], discovery.CollectOptions(max_candidates=3, display=False), resolver, validator)
        self.assertEqual(len(collector.collect()), 3)
        self.assertEqual(resolver.resolve.call_count, 3)
        self.assertEqual(validator.validate.call_count, 3)


class AggregateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        (root / "subconverter").mkdir()
        (root / "data").mkdir()
        self.args = argparse.Namespace(invisible=True, key="test-token", gist="user/aabbcc", overwrite=False,
            pages=1, easygoing=False, num=2, refresh=True, skip_captcha=True, custom_sites="",
            max_candidates=3, skip=True, probe_sample=0, targets=["clash", "v2ray", "singbox", "surge"],
            all=True, ignore_default_filters=False, life=0, flow=0)
        self.files = {"clash.yaml": artifact(4), "subscribes.txt": "https://source.example/sub"}
        self.mocks = {}
        for name, value in {
            "PATH": str(root), "DATA_BASE": str(root / "data"),
        }.items():
            p = patch.object(collect, name, value)
            p.start()
            self.addCleanup(p.stop)
        for name in ["executable.which_bin", "assign", "pipeline.execute_tasks", "safety.read_gist",
                     "subconverter.generate_conf", "subconverter.convert", "push.PushToGist", "workflow.cleanup"]:
            p = patch("collect." + name)
            self.mocks[name] = p.start()
            self.addCleanup(p.stop)
        self.mocks["executable.which_bin"].return_value = ("clash", "converter")
        self.mocks["assign"].return_value = [collect.TaskConfig(name="existing", bin_name="converter", nodes=collect.NodeInput(subscribe="https://source.example/sub"))]
        self.mocks["pipeline.execute_tasks"].return_value = [(1, [node(i) for i in range(4)])]
        self.mocks["safety.read_gist"].return_value = ("v1", self.files)
        self.mocks["subconverter.generate_conf"].return_value = True
        self.mocks["subconverter.convert"].side_effect = self.convert
        self.mocks["push.PushToGist"].return_value.push_to.return_value = True
        self.root = root

    def convert(self, binname, artifact):
        target = artifact.removeprefix("convert_")
        content = {"clash": globals()["artifact"](4), "v2ray": "trojan://test-only@example.com:443#example",
                   "singbox": json.dumps({"outbounds": [{"type": "trojan", "server": "example.com"}]}),
                   "surge": "[Proxy]\nExample = trojan, example.com, 443, password=test-only"}[target]
        (self.root / "subconverter" / collect.subconverter.get_filename(target)).write_text(content, encoding="utf-8")
        return True

    def assert_no_publish(self):
        self.mocks["push.PushToGist"].assert_not_called()
        self.assertFalse((self.root / "data" / "subscribes.txt").exists())

    def test_success_one_payload_all_formats_same_gist(self):
        collect.aggregate(self.args)
        client = self.mocks["push.PushToGist"].return_value
        client.push_to.assert_called_once()
        kwargs = client.push_to.call_args.kwargs
        self.assertEqual(kwargs["item"].gist_id, "aabbcc")
        self.assertEqual(set(kwargs["payload"]["files"]), {"clash.yaml", "v2ray.txt", "singbox.json", "surge.conf", "subscribes.txt"})
        self.assertTrue((self.root / "data" / "subscribes.txt").is_file())

    def test_deduplication_keeps_successful_source_urls(self):
        urls = [f"https://source{i}.example/sub" for i in range(4)]
        self.files["subscribes.txt"] = "\n".join(urls)
        self.mocks["pipeline.execute_tasks"].return_value = [(1, [dict(node(), sub=url) for url in urls])]
        collect.aggregate(self.args)
        payload = self.mocks["push.PushToGist"].return_value.push_to.call_args.kwargs["payload"]
        self.assertEqual(set(payload["files"]["subscribes.txt"]["content"].splitlines()), set(urls))

    @patch("collect.safety.tcp_probe", return_value="unknown")
    def test_advisory_failure_does_not_remove_nodes(self, probe):
        self.args.probe_sample = 2
        collect.aggregate(self.args)
        self.assertEqual(probe.call_count, 2)
        self.mocks["push.PushToGist"].return_value.push_to.assert_called_once()

    def test_unreadable_baseline_aborts_before_collection(self):
        self.mocks["safety.read_gist"].side_effect = safety.PublicationError("baseline unavailable")
        with self.assertRaises(safety.PublicationError):
            collect.aggregate(self.args)
        self.mocks["assign"].assert_not_called()
        self.assert_no_publish()

    def test_partial_conversion_never_publishes(self):
        self.mocks["subconverter.convert"].side_effect = lambda binname, artifact: self.convert(binname, artifact) if artifact == "convert_clash" else False
        with self.assertRaises(safety.PublicationError):
            collect.aggregate(self.args)
        self.assert_no_publish()

    def test_stale_conversion_file_is_not_reused(self):
        (self.root / "subconverter" / "clash.yaml").write_text(artifact())
        self.mocks["subconverter.convert"].side_effect = None
        self.mocks["subconverter.convert"].return_value = True
        with self.assertRaises(safety.PublicationError):
            collect.aggregate(self.args)
        self.assert_no_publish()

    def test_changed_gist_blocks_publish(self):
        self.mocks["safety.read_gist"].side_effect = [("v1", self.files), ("v2", self.files)]
        with self.assertRaises(safety.PublicationError):
            collect.aggregate(self.args)
        self.assert_no_publish()

    def test_large_drop_blocks_publish(self):
        self.files["clash.yaml"] = artifact(20)
        with self.assertRaises(safety.PublicationError):
            collect.aggregate(self.args)
        self.assert_no_publish()

    def test_upload_failure_keeps_local_subscription(self):
        local = self.root / "data" / "subscribes.txt"
        local.write_text("previous-content")
        self.mocks["push.PushToGist"].return_value.push_to.return_value = False
        with self.assertRaises(safety.PublicationError):
            collect.aggregate(self.args)
        self.assertEqual(local.read_text(), "previous-content")

    def test_no_valid_nodes_blocks_publish(self):
        self.mocks["pipeline.execute_tasks"].return_value = [(1, [{"type": "direct"}])]
        with self.assertRaises(SystemExit) as result:
            collect.aggregate(self.args)
        self.assertEqual(result.exception.code, 1)
        self.assert_no_publish()


if __name__ == "__main__":
    unittest.main()
