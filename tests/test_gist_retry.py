"""Gist retry must never replace a multi-file PATCH with an empty single file."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'subscribe'))
import push
from config.models import StorageItem


class GistRetryTests(unittest.TestCase):
    def test_retry_preserves_complete_payload(self):
        payload = {"files": {"clash.yaml": {"content": "proxies: []"},
                             "surge.conf": {"content": "[Proxy]"},
                             "node-pool.json": {"content": '{"nodes":[]}'} }}
        item = StorageItem(gist_id="aabbcc", filename="clash.yaml")
        ok_response = Mock()
        ok_response.getcode.return_value = 200
        with patch("push.urllib.request.urlopen", side_effect=[OSError("transient"), ok_response]) as fetch, \
             patch("push.PushToGist._error_handler"):
            self.assertTrue(push.PushToGist("test-only-token").push_to("", item, retry=2, payload=payload))
        self.assertEqual(fetch.call_count, 2)
        for call in fetch.call_args_list:
            request = call.args[0]
            self.assertEqual(json.loads(request.data.decode('utf-8')), payload)


if __name__ == '__main__':
    unittest.main()
