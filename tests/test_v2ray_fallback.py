"""Offline share-URI fallback tests; no network and no secrets in logs."""
import base64
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'subscribe'))
from v2ray_fallback import build_subscription, make_uri


class V2rayFallbackTests(unittest.TestCase):
    def sample(self, protocol='hysteria2', **changes):
        node = {'name': '🇭🇰 香港 001', 'type': protocol, 'server': 'example.org', 'port': 8443,
                'password': 'pa:ss+word', 'sni': 'cdn.example.org', 'skip-cert-verify': True}
        node.update(changes)
        return node

    def test_hysteria2_official_uri_and_credentials(self):
        uri = make_uri(self.sample(obfs='salamander', **{'obfs-password': 'secret/one'}))
        url = urlsplit(uri)
        self.assertEqual(url.scheme, 'hysteria2')
        self.assertEqual(unquote(url.username), 'pa:ss+word')
        self.assertEqual(url.hostname, 'example.org')
        self.assertEqual(parse_qs(url.query), {'sni': ['cdn.example.org'], 'insecure': ['1'],
                                               'obfs': ['salamander'], 'obfs-password': ['secret/one']})
        self.assertEqual(unquote(url.fragment), '🇭🇰 香港 001')

    def test_hysteria2_multi_port(self):
        uri = make_uri(self.sample(ports='8443,15000-15100'))
        self.assertIn(':8443,15000-15100/', uri)
        with self.assertRaises(ValueError):
            make_uri(self.sample(ports='8443/../../'))

    def test_tuic_uri(self):
        node = self.sample('tuic', uuid='d1d89c83-76fe-4ae9-bff2-27fb61d0e4f6',
                           **{'congestion-controller': 'bbr'})
        uri = make_uri(node)
        self.assertTrue(uri.startswith('tuic://'))
        self.assertIn('congestion_control=bbr', uri)
        self.assertIn('cdn.example.org', uri)

    def test_shadowsocks_sip002(self):
        uri = make_uri(self.sample('ss', cipher='aes-256-gcm'))
        text = uri.split('://', 1)[1].split('@', 1)[0]
        decoded = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4)).decode()
        self.assertEqual(decoded, 'aes-256-gcm:pa:ss+word')
        with self.assertRaises(ValueError):
            make_uri(self.sample('ss', cipher='aes-256-gcm', plugin='obfs'))

    def test_vless_reality(self):
        uri = make_uri(self.sample('vless', uuid='d1d89c83-76fe-4ae9-bff2-27fb61d0e4f6',
                **{'reality-opts': {'public-key': 'pk', 'short-id': 'sid'}, 'client-fingerprint':'chrome'}))
        q = parse_qs(urlsplit(uri).query)
        self.assertEqual(q['security'], ['reality'])
        self.assertEqual(q['pbk'], ['pk'])
        self.assertEqual(q['sid'], ['sid'])

    def test_vmess_json_and_websocket(self):
        uri = make_uri(self.sample('vmess', uuid='d1d89c83-76fe-4ae9-bff2-27fb61d0e4f6',
                tls=True, network='ws', **{'ws-opts': {'path': '/xy', 'headers': {'Host': 'web.example.com'}}}))
        raw = uri.removeprefix('vmess://')
        doc = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))
        self.assertEqual(doc['ps'], '🇭🇰 香港 001')
        self.assertEqual(doc['host'], 'web.example.com')
        self.assertEqual(doc['path'], '/xy')

    def test_invalid_or_unsupported_not_fabricated(self):
        with self.assertRaises(ValueError):
            make_uri(self.sample('ssr'))
        with self.assertRaises(ValueError):
            make_uri(self.sample('hysteria2', password=''))
        with self.assertRaises(ValueError):
            make_uri(self.sample('hysteria2', port=0))
        with self.assertRaises(ValueError):
            build_subscription([self.sample('unsupported')])

    def test_base64_subscription_is_parseable(self):
        output, skipped = build_subscription([self.sample(), self.sample('tuic', uuid='u'),
                        self.sample('unsupported')])
        self.assertEqual(skipped, {'unsupported': 1})
        lines = base64.b64decode(output).decode('utf-8').splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith('hysteria2://'))
        self.assertTrue(lines[1].startswith('tuic://'))

if __name__ == '__main__':
    unittest.main()
