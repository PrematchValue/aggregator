"""Surge policy-path regression tests: only the minimal additive resource.

The original aggregator generates surge.conf; this extension derives the
separate surge-proxy.conf from it without implementing its own converter.
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "subscribe"))
from surge_provider import proxy_lines_only


class SurgePolicyPathTests(unittest.TestCase):
    def test_full_profile_keeps_only_proxy_declarations(self):
        source = (
            '[General]\ndns-server = 223.5.5.5\n'
            '[Proxy]\n'
            '🇭🇰 香港 001 = trojan, h.example, 443, password=secret\n'
            '全球直连 = direct\nDIRECT = direct\nREJECT = reject\n'
            '🇯🇵 日本 001 = ss, j.example, 443, encrypt-method=aes-128-gcm, password=test\n'
            '[Proxy Group]\n选择 = select, 全球直连, 🇭🇰 香港 001\n'
            '[Rule]\nFINAL,选择\n'
        )
        self.assertEqual(proxy_lines_only(source).splitlines(), [
            '🇭🇰 香港 001 = trojan, h.example, 443, password=secret',
            '🇯🇵 日本 001 = ss, j.example, 443, encrypt-method=aes-128-gcm, password=test'
        ])

    def test_tuic_and_bare_list(self):
        self.assertEqual(proxy_lines_only('[Proxy]\n🇸🇬 新加坡 001 = tuic-v5, host, 443, uuid=x, password=y\n'),
                         '🇸🇬 新加坡 001 = tuic-v5, host, 443, uuid=x, password=y\n')
        self.assertEqual(proxy_lines_only('香港 001 = socks5, host, 1080\n直连 = direct\n'),
                         '香港 001 = socks5, host, 1080\n')

    def test_fail_closed_for_empty_or_invalid_list(self):
        for source in ('', '[Proxy Group]\nx=select,a', '[Proxy]\nDIRECT = direct'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                proxy_lines_only(source)

    def test_duplicate_names_rejected(self):
        with self.assertRaises(ValueError):
            proxy_lines_only('HK = ss, a, 80\nhk = ss, b, 80')

    def test_source_has_both_gist_artifacts(self):
        source = (ROOT / 'subscribe/collect.py').read_text(encoding='utf-8')
        self.assertIn("if 'surge.conf' in records:", source)
        self.assertIn("records['surge-proxy.conf'] = provider_path", source)
        self.assertIn("records.pop('surge.conf', None)", source)
        self.assertIn('from surge_provider import proxy_lines_only', source)
        self.assertNotIn('from protocol_coverage import', source)


class SurgeManagedGistTests(unittest.TestCase):
    def test_wrong_localhost_url_is_replaced_but_interval_kept(self):
        from surge_provider import fix_managed_gist_url
        source = ("#!MANAGED-CONFIG http://127.0.0.1:25500/sub?target=surge "
                  "interval=86400 strict=false\n"
                  "[General]\ndns-server = 223.5.5.5\n"
                  "[Proxy]\n🇭🇰 香港 001 = trojan, h.example, 443, password=secret\n")
        result = fix_managed_gist_url(source, "PrematchValue", "0123456789abcdef0123456789abcdef")
        self.assertTrue(result.startswith(
            "#!MANAGED-CONFIG https://gist.githubusercontent.com/PrematchValue/"
            "0123456789abcdef0123456789abcdef/raw/surge.conf interval=86400 strict=false\n"))
        self.assertNotIn("127.0.0.1", result)
        self.assertNotIn("interval=14400", result)
        self.assertIn("dns-server = 223.5.5.5", result)
        self.assertEqual(fix_managed_gist_url(result, "PrematchValue",
                         "0123456789abcdef0123456789abcdef"), result)

    def test_missing_header_defaults_to_surge_native_interval(self):
        from surge_provider import fix_managed_gist_url
        result = fix_managed_gist_url("[General]\nloglevel = notify\n",
                                      "PrematchValue", "0123456789abcdef")
        self.assertTrue(result.startswith(
            "#!MANAGED-CONFIG https://gist.githubusercontent.com/PrematchValue/"
            "0123456789abcdef/raw/surge.conf\n"))
        self.assertNotIn("interval=", result)
        self.assertIn("[General]\nloglevel = notify", result)

    def test_multiple_headers_fail_closed(self):
        from surge_provider import fix_managed_gist_url
        with self.assertRaises(ValueError):
            fix_managed_gist_url(
                "#!MANAGED-CONFIG http://127.0.0.1:25500/a\n"
                "#!MANAGED-CONFIG http://127.0.0.1:25500/b\n[General]\n",
                "PrematchValue", "0123456789abcdef")

    def test_collect_repairs_managed_url_without_changing_pref(self):
        code = (ROOT / "subscribe/collect.py").read_text(encoding="utf-8")
        self.assertIn('from surge_provider import fix_managed_gist_url', code)
        self.assertIn('profile = fix_managed_gist_url(profile, username, gist_id)', code)
        settings = (ROOT / "subconverter/pref.toml").read_text(encoding="utf-8")
        self.assertIn('config_update_interval = 86400', settings)


if __name__ == '__main__':
    unittest.main()
