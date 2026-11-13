"""No network, external binaries or real credentials required."""
import json
from pathlib import Path
import sys
import unittest

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "subscribe"))
from protocol_coverage import CoverageError, reconcile, _surge_names


def make_node(name, kind="vless", **options):
    node = {"name": name, "type": kind, "server": "example.net", "port": 443}
    if kind == "vless":
        node.update(uuid="12345678-1234-1234-1234-123456789abc", tls=True)
    elif kind in ("anytls", "trojan", "hysteria2"):
        node.update(password="test-secret")
    node.update(options)
    return node


class CoverageTests(unittest.TestCase):
    def test_surge_vless_and_anytls_restored_without_secrets_in_diagnostics(self):
        original = "[General]\nloglevel = notify\n[Proxy]\n[Proxy Group]\n🔰 节点选择 = select, DIRECT\n♻️ 自动选择 = url-test, url=http://test, interval=300\n[Rule]\nFINAL,🔰 节点选择\n"
        nodes = [make_node("🇯🇵 日本 001", tls=True, network="ws", **{"ws-opts": {"path": "/ws", "headers": {"Host": "cdn.example"}}}),
                 make_node("🇺🇸 美国 001", "anytls", servername="sni.example")]
        output, counts = reconcile("surge", original, nodes)
        self.assertIn("vless, example.net, 443", output)
        self.assertIn("ws-path=/ws", output)
        self.assertIn("anytls, example.net, 443", output)
        self.assertIn("🇯🇵 日本 001", output.split("[Proxy Group]")[1])
        self.assertEqual(counts["restored"], 2)
        self.assertEqual(counts["found"], 2)
        self.assertEqual(counts["by_protocol"]["vless"], {"expected": 1, "found": 1, "skipped": 0})
        self.assertEqual(len(_surge_names(output)), 2)
        self.assertNotIn("test-secret", repr(counts))

    def test_surge_reality_and_grpc(self):
        node = make_node("VLESS Reality", tls=True, network="grpc",
                         **{"reality-opts": {"public-key": "pubkey", "short-id": "abc"},
                            "grpc-opts": {"grpc-service-name": "api"}})
        out, _ = reconcile("surge", "[Proxy]\n", [node])
        self.assertIn("reality-public-key=pubkey", out)
        self.assertIn("grpc-service-name=api", out)
        self.assertIn("grpc=true", out)

    def test_unrepresentable_known_protocol_is_skipped_individually(self):
        bad = make_node("Bad VLESS", network="xhttp")
        good = make_node("Good Trojan", "trojan")
        output, stats = reconcile("surge", "[Proxy]\n", [bad, good])
        self.assertIn("Good Trojan = trojan", output)
        self.assertNotIn("Bad VLESS =", output)
        self.assertEqual(stats["failed"], {"vless": 1})
        self.assertEqual(stats["skipped"], 1)
        special = make_node("AnyTLS Special", "anytls", **{"shadow-tls-opts": {"host": "abc"}})
        recovered, counts = reconcile("singbox", '{"outbounds": []}', [special, good])
        self.assertEqual(counts["failed"], {"anytls": 1})
        self.assertEqual(counts["skipped"], 1)
        self.assertIn("Good Trojan", recovered)
        self.assertNotIn("AnyTLS Special", recovered)

    def test_explicitly_incompatible_protocol_does_not_fail(self):
        out, stat = reconcile("surge", "[Proxy]\nKnown = trojan, a, 443, password=x\n",
                              [make_node("Known", "trojan"), make_node("SSR", "ssr")])
        self.assertEqual(out.count("Known ="), 1)
        self.assertEqual(stat["unsupported"], {"ssr": 1})
        self.assertEqual(stat["expected"], 2)
        self.assertEqual(stat["skipped"], 1)

    def test_singbox_restore_vless_anytls_and_group(self):
        doc = {"outbounds": [{"type": "selector", "tag": "🔰 节点选择", "outbounds": ["direct"]},
                              {"type": "urltest", "tag": "♻️ 自动选择", "outbounds": []}]}
        recovered, stat = reconcile("singbox", json.dumps(doc),
                                   [make_node("Reality", **{"reality-opts": {"public-key": "key"}}),
                                    make_node("AnyTLS", "anytls")])
        data = json.loads(recovered)
        self.assertEqual(stat["restored"], 2)
        self.assertEqual(data["outbounds"][-2]["tls"]["reality"]["public_key"], "key")
        self.assertEqual(data["outbounds"][-1]["type"], "anytls")
        self.assertIn("AnyTLS", data["outbounds"][0]["outbounds"])
        self.assertIn("Reality", data["outbounds"][1]["outbounds"])

    def test_clash_preserves_existing_routes_and_restores_all_missing(self):
        baseline = {"rules": ["MATCH,🔰 节点选择"],
                    "proxy-groups": [{"name": "🔰 节点选择", "type": "select", "proxies": ["DIRECT"]}],
                    "proxies": [make_node("A", "trojan")]}
        out, stat = reconcile("clash", yaml.safe_dump(baseline, allow_unicode=True),
                              [make_node("A", "trojan"), make_node("B", "anytls")])
        self.assertEqual(stat["restored"], 1)
        parsed = yaml.safe_load(out)
        self.assertEqual(parsed["rules"], baseline["rules"])
        self.assertIn("B", parsed["proxy-groups"][0]["proxies"])
        self.assertEqual(len(parsed["proxies"]), 2)

    def test_lower_previous_node_count_is_not_a_failure(self):
        content = "[Proxy]\nOnly = trojan, example.net, 443, password=x\n"
        out, stats = reconcile("surge", content, [make_node("Only", "trojan")])
        self.assertEqual(out, content)
        self.assertEqual(stats["restored"], 0)

    def test_existing_node_with_wrong_protocol_is_repaired(self):
        output, stats = reconcile("surge", "[Proxy]\nNode = trojan, host, 443, password=x\n",
                                  [make_node("Node", "vless")])
        self.assertNotIn("trojan, host", output)
        self.assertIn("Node = vless", output)
        self.assertEqual(stats["restored"], 1)

    def test_mismatched_unconvertible_node_removed_but_good_nodes_remain(self):
        bad = make_node("Bad", "vless", network="xhttp")
        good = make_node("Good", "trojan")
        profile = ("[Proxy]\nBad = trojan, old.example, 443, password=x\n"
                   "Good = trojan, example.net, 443, password=test-secret\n"
                   "[Proxy Group]\n🔰 节点选择 = select, Bad, Good, DIRECT\n")
        output, stats = reconcile("surge", profile, [bad, good])
        self.assertNotIn("Bad =", output)
        self.assertNotIn("select, Bad,", output)
        self.assertIn("Good = trojan", output)
        self.assertEqual(stats["skipped"], 1)
        self.assertEqual(stats["failed"], {"vless": 1})

    def test_clash_wrong_protocol_is_repaired_with_group_link(self):
        bad = make_node("A", "vless")
        baseline = {"proxies": [make_node("A", "trojan")], "proxy-groups": [
                    {"type": "select", "name": "🔰 节点选择", "proxies": ["DIRECT", "A"]}]}
        output, stats = reconcile("clash", yaml.safe_dump(baseline, allow_unicode=True), [bad])
        parsed = yaml.safe_load(output)
        self.assertEqual(len(parsed["proxies"]), 1)
        self.assertEqual(parsed["proxies"][0]["type"], "vless")
        self.assertEqual(parsed["proxy-groups"][0]["proxies"].count("A"), 1)
        self.assertEqual(stats["skipped"], 0)

    def test_singbox_bad_node_removed_from_groups(self):
        bad = make_node("Bad", "vless", network="xhttp")
        good = make_node("Good", "trojan")
        profile = {"outbounds": [
            {"type": "selector", "tag": "🔰 节点选择", "outbounds": ["Bad", "Good", "direct"]},
            {"type": "trojan", "tag": "Bad", "server": "a", "server_port": 443, "password": "x"},
            {"type": "trojan", "tag": "Good", "server": "b", "server_port": 443, "password": "x"}]}
        output, stats = reconcile("singbox", json.dumps(profile), [bad, good])
        parsed = json.loads(output)
        self.assertNotIn("Bad", parsed["outbounds"][0]["outbounds"])
        self.assertEqual([v["tag"] for v in parsed["outbounds"] if v["type"] == "trojan"], ["Good"])
        self.assertEqual(stats["skipped"], 1)

    def test_surge_external_policy_list_keeps_modern_protocols(self):
        try:
            from surge_provider import proxy_lines_only
            from collect_safety import artifact_count
        except (ImportError, AttributeError):
            self.skipTest("Repository integration modules not present in standalone fixture")
        sample = "[Proxy]\nVLESS = vless, host, 443, username=uuid\nAnyTLS = anytls, host, 443, password=x\nTUIC = tuic-v5, host, 443, uuid=id, password=pwd\n[Proxy Group]\nG = select, VLESS\n"
        data = proxy_lines_only(sample)
        self.assertEqual(artifact_count(data, "surge"), 3)
        self.assertIn("VLESS = vless", data)
        self.assertIn("AnyTLS = anytls", data)
        self.assertIn("TUIC = tuic-v5", data)

    def test_surge_hysteria2_and_tuic_v5_are_preserved(self):
        nodes = [make_node("HY2", "hysteria2", obfs="salamander", **{"obfs-password": "abc"}),
                 make_node("TUIC", "tuic", uuid="12345678-1234-1234-1234-123456789abc", password="pwd")]
        out, status = reconcile("surge", "[Proxy]\n", nodes)
        self.assertIn("salamander-password=abc", out)
        self.assertIn("TUIC = tuic-v5,", out)
        self.assertEqual(status["expected"], 2)

    def test_duplicate_input_names_fail_not_merge(self):
        with self.assertRaisesRegex(CoverageError, "duplicate"):
            reconcile("clash", "proxies: []", [make_node("Duplicate"), make_node("Duplicate", "trojan")])


if __name__ == "__main__":
    unittest.main()
