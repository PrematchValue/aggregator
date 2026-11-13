"""Keep the minimal security fix around upstream subscription metadata parsing."""
from pathlib import Path
from unittest.mock import patch
import tempfile
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'subscribe'))
from crawl import helpers


class SubscriptionHeaderTests(unittest.TestCase):
    def test_quota_and_expiration(self):
        self.assertEqual(helpers.is_expired('upload=10;download=20;total=100'), (True, False))
        self.assertEqual(helpers.is_expired('upload=60;download=40;total=100'), (False, False))
        with patch.object(helpers.time, 'time', return_value=1700000000):
            self.assertEqual(helpers.is_expired('upload=1;download=0;total=100;expire=1699999999'), (False, True))

    def test_invalid_metadata_is_not_proof_of_expiry(self):
        for header in ('upload=1/0;total=100', 'total=-100', 'total=10', 'total=abc'):
            with self.subTest(header=header):
                self.assertEqual(helpers.is_expired(header), (True, False))

    def test_untrusted_expression_cannot_execute(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder, 'do-not-create')
            payload = "upload=0;download=0;total=100;expire=__import__('pathlib').Path(%r).touch()" % str(marker)
            self.assertEqual(helpers.is_expired(payload), (True, False))
            self.assertFalse(marker.exists())

if __name__ == '__main__':
    unittest.main()
