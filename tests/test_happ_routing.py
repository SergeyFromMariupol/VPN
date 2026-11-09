import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'bundle/scripts/happ_routing.py'
SPEC = importlib.util.spec_from_file_location('happ_routing', SCRIPT)
HAPP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HAPP)


class HappRoutingTests(unittest.TestCase):
    def setUp(self):
        self.link = HAPP.routing_link()
        self.routing = f'Routing: {self.link}\r\n'.encode('ascii')
        self.enabled = b'routing-enable: true\r\n'

    def test_profile_activates_russian_and_private_rules_with_proxy_default(self):
        encoded = self.link.removeprefix('happ://routing/onadd/')
        profile = json.loads(base64.b64decode(encoded, validate=True))
        self.assertEqual(set(profile['DirectSites']), {
            'geosite:category-ru', 'geosite:private', 'domain:ru',
            'domain:xn--p1ai', 'domain:su',
        })
        self.assertEqual(set(profile['DirectIp']), {'geoip:ru', 'geoip:private'})
        self.assertEqual(profile['GlobalProxy'], 'true')
        self.assertEqual(profile['DomainStrategy'], 'IPIfNonMatch')
        self.assertEqual(profile['RouteOrder'], 'block-direct-proxy')
        self.assertEqual(profile['ProxySites'], [])
        self.assertEqual(profile['ProxyIp'], [])
        self.assertEqual(profile['BlockSites'], [])
        self.assertEqual(profile['BlockIp'], [])

    def test_headers_are_case_insensitive_and_accept_http1_and_http2(self):
        for status in (b'HTTP/1.1 200 OK', b'HTTP/2 200'):
            with self.subTest(status=status):
                self.assertTrue(HAPP.check_headers(status + b'\r\n' + self.enabled +
                                                   self.routing + b'\r\n'))

    def test_missing_disabled_modified_and_duplicate_headers_are_rejected(self):
        for fields in (
                self.enabled, self.routing, self.enabled + self.routing * 2,
                self.enabled * 2 + self.routing,
                self.enabled.replace(b'true', b'false') + self.routing,
                self.enabled + self.routing.replace(b'/onadd/', b'/add/')):
            with self.subTest(fields=fields[:32]):
                self.assertFalse(HAPP.check_headers(b'HTTP/2 200\r\n' + fields + b'\r\n'))
        self.assertFalse(HAPP.check_headers(b'HTTP/2 404\r\n' + self.enabled +
                                            self.routing + b'\r\n'))

    def test_cli_only_emits_fixed_error_when_headers_include_private_metadata(self):
        raw = b'HTTP/2 200\r\nProfile-Web-Page-Url: https://vpn.test/private-fixture\r\n\r\n'
        result = subprocess.run([sys.executable, str(SCRIPT), '--check-headers'],
                                input=raw, capture_output=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr.strip(), b'HAPP_ROUTING_HEADER_MISMATCH')


if __name__ == '__main__':
    unittest.main()
