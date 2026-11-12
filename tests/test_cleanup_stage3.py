"""Offline regression tests: no network access, no credential or Gist access."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'subscribe'))

from surge_provider import proxy_lines_only
from node_labels import only_confirmed


class SurgeListTests(unittest.TestCase):
    def test_full_profile_removes_global_direct_and_groups(self):
        source = '''[General]\nfoo = bar\n[Proxy]\n🇭🇰 香港 001 = trojan, h.example, 443, password=xxx\n全球直连 = direct\nDIRECT = direct\nREJECT = reject\n🇯🇵 日本 001 = ss, j.example, 443, encrypt-method=aes-128-gcm, password=test\n[Proxy Group]\n选择 = select, 全球直连, 🇭🇰 香港 001\n[Rule]\nFINAL,选择\n'''
        result = proxy_lines_only(source)
        self.assertEqual(result.splitlines(), [
            '🇭🇰 香港 001 = trojan, h.example, 443, password=xxx',
            '🇯🇵 日本 001 = ss, j.example, 443, encrypt-method=aes-128-gcm, password=test',
        ])

    def test_tuic_v5_is_a_real_proxy(self):
        text = "[Proxy]\n🇸🇬 新加坡 001 = tuic-v5, host, 443, uuid=x, password=y\n全球直连 = direct\n"
        self.assertEqual(proxy_lines_only(text),
                         "🇸🇬 新加坡 001 = tuic-v5, host, 443, uuid=x, password=y\n")

    def test_list_without_section(self):
        source = '# hello\n香港 001 = socks5, host, 1080\n直连 = direct\n'
        self.assertEqual(proxy_lines_only(source), '香港 001 = socks5, host, 1080\n')

    def test_reject_nonproxy_sections_or_empty_list(self):
        for s in ['[Proxy Group]\nx=select,a', '[Proxy]\n全球直连 = direct', '']:
            with self.subTest(s=s), self.assertRaises(ValueError):
                proxy_lines_only(s)

    def test_duplicate_proxy_names_fail_closed(self):
        with self.assertRaises(ValueError):
            proxy_lines_only('HK = ss, a, 80\nhk = ss, b, 80')


class KnownRegionTests(unittest.TestCase):
    def test_unknown_is_removed_and_flags_remain(self):
        source = [{'name':'🇭🇰 香港 001'}, {'name':'🌐 未知地区 001'}, {'name':'🇹🇼 台湾 001'}]
        result, removed = only_confirmed(source)
        self.assertEqual(removed, 1)
        self.assertEqual([x['name'] for x in result], ['🇭🇰 香港 001','🇹🇼 台湾 001'])
        self.assertEqual(len(source), 3)

    def test_cannot_accidentally_keep_bare_unknown(self):
        source = [{'name':'🌐 未知地区 001'}]
        self.assertEqual(only_confirmed(source), ([], 1))


if __name__ == '__main__':
    unittest.main()
