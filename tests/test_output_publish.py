"""Platform isolation and protected upstream auto-merge contracts."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "subscribe"))
from output_publish import publication_groups

TARGETS = [
    ("convert_clash", "clash.yaml", "clash"),
    ("convert_v2ray", "v2ray.txt", "v2ray"),
    ("convert_singbox", "singbox.json", "singbox"),
    ("convert_surge", "surge.conf", "surge"),
]


class IndependentPublishTests(unittest.TestCase):
    def test_failed_singbox_cannot_block_others(self):
        records = {n: n for n in ("clash.yaml", "v2ray.txt", "surge.conf", "surge-proxy.conf")}
        self.assertEqual(publication_groups(TARGETS, records), [
            ("clash", ["clash.yaml"]),
            ("v2ray", ["v2ray.txt"]),
            ("surge", ["surge.conf", "surge-proxy.conf"]),
        ])

    def test_surge_is_never_partially_published(self):
        records = {"clash.yaml": "clash", "surge.conf": "surge"}
        self.assertEqual(publication_groups(TARGETS, records), [("clash", ["clash.yaml"])])
        records["surge-proxy.conf"] = "proxy"
        self.assertEqual(publication_groups(TARGETS, records)[-1],
                         ("surge", ["surge.conf", "surge-proxy.conf"]))

    def test_all_formats_are_independent(self):
        records = {x[1]: x[1] for x in TARGETS}
        records["surge-proxy.conf"] = "proxy"
        self.assertEqual(len(publication_groups(TARGETS, records)), 4)

    def test_collect_only_publishes_validated_targets(self):
        code = (ROOT / "subscribe/collect.py").read_text(encoding="utf-8")
        self.assertIn("from output_publish import publication_groups", code)
        self.assertIn("failed_targets[target_name]", code)
        self.assertIn('group=target_name', code)
        self.assertIn('files.update(shared)', code)
        self.assertIn('published_targets.append(target_name)', code)
        self.assertIn('records.pop(t[1], None)', code)

    def test_weekly_keeps_automatic_merge_and_protects_local_logic(self):
        wf = (ROOT / ".github/workflows/collect.yaml").read_text(encoding="utf-8")
        self.assertIn('git merge --no-commit --no-ff "$UPSTREAM"', wf)
        self.assertIn('git push origin HEAD:main', wf)
        for path in ("subscribe/collect.py", "subscribe/profile_layout.py",
                     "subscribe/singbox_layout.py", "subscribe/verified_nodes.py",
                     "subscribe/geo_labels.py", "subconverter/rules/custom",
                     "tests/test_targeted_routing.py", "subscribe/output_publish.py"):
            with self.subTest(path=path):
                self.assertIn(path, wf)
        self.assertIn('python -m unittest discover -s tests -q', wf)

    def test_singbox_remains_in_refresh_targets(self):
        wf = (ROOT / ".github/workflows/refresh.yaml").read_text(encoding="utf-8")
        self.assertIn('-t clash v2ray singbox surge', wf)


if __name__ == "__main__":
    unittest.main()
