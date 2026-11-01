"""Run the direct-stage jq generators and independent UTF-8 URI contract."""
import base64
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'bundle/scripts/configure-standalone.sh').read_text(encoding='utf-8')
LABELS = ('Test VPN', '\u0422\u0435\u0441\u0442\u043e\u0432\u044b\u0439 VPN',
          'My "VPN" $HOME `literal` \\ \U0001f1f3\U0001f1f1')
PROFILES = (('reality', 'REALITY'), ('xhttp', 'XHTTP'), ('hysteria2', 'HYSTERIA2'))


def jq_command(kind, values, executable):
    """Extract the production filter and its actual --arg assignments."""
    end = SOURCE.index("' >\"$stage/" + kind + '.json"')
    start = SOURCE.rfind('\njq -n \\\n', 0, end) + 1
    if start == 0:
        raise AssertionError('Production jq generator not found: ' + kind)
    arguments, program = SOURCE[start:end].split(" '\n", 1)
    words = shlex.split(arguments.replace('\\\n', ' '))
    if words[:2] != ['jq', '-n']:
        raise AssertionError('Unexpected jq generator: ' + kind)
    expanded = [re.sub(r'\$([A-Za-z_][A-Za-z_0-9]*)', lambda match: values[match[1]], word)
                for word in words[1:]]
    return [executable, *expanded, program]


def checker_source():
    start = SOURCE.index('SUB_BODY="$stage/subscription.body"')
    start = SOURCE.index("<<'PY'\n", start) + len("<<'PY'\n")
    return SOURCE[start:SOURCE.index('\nPY\n', start)]


def canonical_links(label, endpoint):
    # Expected display fragments come from the user-facing contract, never
    # from the production generator or its verifier's expected_comments list.
    def fragment(protocol):
        return quote(label + ' \u00b7 ' + protocol, safe='')
    return [
        'vless://fixture@' + endpoint + ':443?security=reality&type=grpc&'
        'serviceName=reality-grpc&sni=example.org#' + fragment('REALITY'),
        'vless://fixture@' + endpoint + ':8443?security=tls&type=xhttp&'
        'alpn=h2&mode=packet-up#' + fragment('XHTTP'),
        'hysteria2://fixture@' + endpoint + ':443?sni=' + endpoint +
        '&alpn=h3#' + fragment('HYSTERIA2'),
    ]


class DirectProfileLabels(unittest.TestCase):
    def check_links(self, links, label, endpoint, encoded=False):
        with tempfile.TemporaryDirectory(prefix='vpn-direct-labels-') as temporary:
            body = Path(temporary) / 'subscription.body'
            payload = ('\n'.join(links) + '\n').encode('utf-8')
            body.write_bytes(base64.b64encode(payload) if encoded else payload)
            environment = dict(os.environ, SUB_BODY=str(body), TARGET_LABEL=label,
                               CHECK_PUBLIC_FQDN=endpoint, CHECK_REALITY_TARGET='example.org',
                               CHECK_XHTTP_PORT='8443')
            return subprocess.run([sys.executable, '-'], input=checker_source(),
                                  env=environment, encoding='utf-8', capture_output=True,
                                  timeout=10)

    def test_production_jq_outputs_exact_contract_comments_in_both_address_modes(self):
        jq = os.environ.get('VPN_TEST_JQ') or shutil.which('jq')
        if not jq:
            if os.environ.get('CI'):
                self.fail('Ubuntu CI must execute the real jq label generators')
            self.skipTest('jq is required for actual production generators')
        for mode, endpoint in (('domain', 'vpn.example.org'), ('ip', '8.8.4.4')):
            for label in LABELS:
                values = dict(SERVER_IPV4='8.8.4.4', PUBLIC_FQDN=endpoint,
                              REALITY_TARGET='example.org', VLESS_UUID='fixture-uuid',
                              SUBSCRIPTION_ID='fixture-subscription',
                              REALITY_PRIVATE_KEY='fixture-private-key',
                              REALITY_PUBLIC_KEY='fixture-public-key', REALITY_SHORT_ID='01234567',
                              XHTTP_PRIVATE_PATH='fixture-path', TLS_FULLCHAIN='/fixture/cert.pem',
                              TLS_PRIVATE_KEY='/fixture/key.pem', HYSTERIA2_AUTH='fixture-auth',
                              decoy_root='/fixture/decoy')
                environment = dict(os.environ, TARGET_LABEL=label, TARGET_DEVICE_LIMIT='0',
                                   TARGET_ADDRESS_MODE=mode)
                for kind, protocol in PROFILES:
                    with self.subTest(mode=mode, label=label, protocol=protocol):
                        result = subprocess.run(jq_command(kind, values, jq), env=environment,
                                                encoding='utf-8', capture_output=True, timeout=10)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        inbound = json.loads(result.stdout)
                        client = inbound['settings']['clients'][0]
                        self.assertEqual(client['comment'], label + ' \u00b7 ' + protocol)
                        self.assertEqual(client['limitIp'], 0)
                        self.assertEqual(inbound['shareAddr'], endpoint)

    def test_production_checker_accepts_independently_canonical_utf8_links(self):
        for endpoint in ('vpn.example.org', '8.8.4.4'):
            for label in LABELS:
                for encoded in (False, True):
                    with self.subTest(endpoint=endpoint, label=label, base64=encoded):
                        result = self.check_links(canonical_links(label, endpoint), label,
                                                  endpoint, encoded)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn('SUBSCRIPTION_SHAPE_OK=3', result.stdout)

    def test_production_checker_rejects_corrupted_fragment_for_each_protocol(self):
        label, endpoint = LABELS[1], 'vpn.example.org'
        broken_separator = ''.join(chr(value) for value in (0x0420, 0x2019, 0x0412, 0x00b7))
        for index, (_, protocol) in enumerate(PROFILES):
            with self.subTest(protocol=protocol):
                links = canonical_links(label, endpoint)
                links[index] = links[index].split('#', 1)[0] + '#' + quote(
                    label + ' ' + broken_separator + ' ' + protocol, safe='')
                result = self.check_links(links, label, endpoint)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('subscription display comments are not exact', result.stderr)


if __name__ == '__main__':
    unittest.main()
