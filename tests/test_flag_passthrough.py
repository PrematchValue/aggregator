"""Regression: conversion must not strip country flags from verified egress labels."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'subscribe'))
import subconverter


class FlagPassthroughTests(unittest.TestCase):
    def generate(self, emoji):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp, 'convert.ini')
            result = subconverter.generate_conf(str(path), 'convert_clash', 'proxies.yaml', 'clash.yaml', 'clash', emoji=emoji)
            self.assertTrue(result)
            return path.read_text(encoding='utf8')

    def test_geo_names_are_preserved_without_auto_emoji(self):
        content = self.generate(None)
        self.assertIn('add_emoji=false', content)
        self.assertIn('remove_emoji=false', content)
        self.assertNotIn('\nemoji=false', content)
        self.assertNotIn('\nemoji=true', content)

    def test_normal_conversion_keeps_existing_default(self):
        content = self.generate(True)
        self.assertIn('emoji=true', content)
        self.assertIn('add_emoji=true', content)

    def test_non_geo_explicitly_disabled_keeps_existing_behavior(self):
        content = self.generate(False)
        self.assertIn('emoji=false', content)
        self.assertIn('add_emoji=false', content)

    def test_collect_passes_preserve_mode_for_geo_routing(self):
        root = Path(__file__).resolve().parents[1]
        collect_code = Path(root, 'subscribe', 'collect.py').read_text(encoding='utf8')
        self.assertIn("None if getattr(args, 'geo_rename', False) else True", collect_code)
        self.assertNotIn("not getattr(args, 'geo_rename', False), t[3]", collect_code)


if __name__ == '__main__':
    unittest.main()
