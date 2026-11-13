"""Persistent proxy pool and staging validation."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "subscribe"))
import yaml
import collect_safety as safety
from node_pool import (POOL_FILE, encode_pool, merge_nodes, merge_rotation,
                       previous_candidates, read_stage, write_stage)


def node(i=0):
    return {"name": f"node-{i}", "type": "trojan", "server": f"node{i}.example.com",
            "port": 443, "password": "test-only"}


class NodePoolTests(unittest.TestCase):
    def test_identity_based_dedup(self):
        nodes = merge_nodes([node(0)], [dict(node(0), name="renamed", sub="https://a.example")])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["name"], "renamed")

    def test_pool_roundtrip_and_corruption(self):
        content = encode_pool([node(0), node(1)])
        self.assertEqual(len(previous_candidates({POOL_FILE: content})), 2)
        with self.assertRaises(safety.PublicationError):
            previous_candidates({POOL_FILE: '{"v":1,"nodes":[{"type":"direct"}]}'})

    def test_bootstrap_confirmed_old_clash_only(self):
        data = yaml.safe_dump({"proxies": [dict(node(0), name="🇭🇰 香港 001"),
                                             dict(node(1), name="unverified")]}, allow_unicode=True)
        self.assertEqual(len(previous_candidates({"clash.yaml": data})), 1)

    def test_stage_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "stage.json")
            write_stage(path, [node(0), dict(node(0), name="again"), node(1)], {"https://a.example"})
            self.assertEqual(len(read_stage(path)["nodes"]), 2)

    def test_rotation_no_rewind_and_same_cycle_union(self):
        from refresh_rotation import RefreshRotation
        old = RefreshRotation(done={"a" * 64}, cycle=4).encode()
        prior = RefreshRotation(done={"b" * 64}, cycle=3).encode()
        self.assertEqual(json.loads(merge_rotation(old, prior))["cycle"], 4)
        same = RefreshRotation(done={"b" * 64}, cycle=4).encode()
        self.assertEqual(set(json.loads(merge_rotation(old, same))["done"]),
                         {"a" * 64, "b" * 64})


if __name__ == "__main__":
    unittest.main()
