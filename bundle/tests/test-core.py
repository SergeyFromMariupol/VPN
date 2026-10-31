#!/usr/bin/env python3
"""Exercise the actual baseline subscription gate without touching a server."""
import ast
import base64
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import quote, urlencode, urlsplit, urlunsplit, parse_qs

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tests/postboot-verify.sh'
CODE = next(code for code in re.findall(r"<<'PY'\n(.*?)\nPY", SCRIPT.read_text(encoding='utf-8'), re.S)
            if 'Reality public parameter mismatch' in code)
CONTRACT_CODE = re.findall(r"<<'PY'\n(.*?)\nPY", (ROOT / 'scripts/target-contract.sh').read_text(encoding='utf-8'), re.S)[0]
CERTIFICATE_FUNCTION = re.search(r'^verify_target_certificate\(\) \{\n.*?^\}',
                                 (ROOT / 'scripts/target-contract.sh').read_text(encoding='utf-8'),
                                 re.M | re.S).group(0)


class BaselineSubscriptionGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.label = '🇳🇱 Нидерланды'
        self.endpoint = 'vpn.example.org'
        self.secrets = {
            'warp-reality.uuid': '11d3f6ca-d1bb-40b7-aa23-8c638dc985ac',
            'warp-xhttp.uuid': '22d3f6ca-d1bb-40b7-aa23-8c638dc985ac',
            'warp-hysteria.auth': 'a' * 64,
            'direct-vless.uuid': '33d3f6ca-d1bb-40b7-aa23-8c638dc985ac',
            'direct-hysteria.auth': 'b' * 64,
            'reality-public.key': 'c' * 43,
            'reality-short.id': 'd' * 16,
            'xhttp.path': 'e' * 48,
            'connector.uuid': '44d3f6ca-d1bb-40b7-aa23-8c638dc985ac',
            'direct-sub.id': 'f' * 64,
        }
        for name, value in self.secrets.items():
            (self.root / name).write_text(value, encoding='utf-8')
        self.links = []
        for kind, key, egress in [
            ('REALITY', 'warp-reality.uuid', '☁️ Cloudflare'),
            ('HYSTERIA2', 'warp-hysteria.auth', '☁️ Cloudflare'),
            ('XHTTP', 'warp-xhttp.uuid', '☁️ Cloudflare'),
            ('REALITY', 'direct-vless.uuid', '🖥️ IP сервера'),
            ('HYSTERIA2', 'direct-hysteria.auth', '🖥️ IP сервера'),
            ('XHTTP', 'direct-vless.uuid', '🖥️ IP сервера'),
        ]:
            query = {'sni': 'vpn.example.org', 'alpn': 'h3'}
            if kind == 'REALITY':
                query = dict(security='reality', sni='max.ru', pbk='c' * 43, sid='d' * 16,
                             type='grpc', serviceName='reality-grpc', fp='chrome')
            elif kind == 'XHTTP':
                query = dict(security='tls', type='xhttp', sni='vpn.example.org', alpn='h2',
                             host='vpn.example.org', path='/' + 'e' * 48, mode='packet-up')
            scheme = 'hysteria2' if kind == 'HYSTERIA2' else 'vless'
            port = 8443 if kind == 'XHTTP' else 443
            self.links.append(f'{scheme}://{self.secrets[key]}@vpn.example.org:{port}?'
                              + urlencode(query) + '#' + quote(f'{self.label} · {egress} · {kind}'))

    def check(self, links, success):
        body = self.root / 'body'
        body.write_bytes(base64.b64encode(('\n'.join(links) + '\n').encode()))
        env = dict(os.environ, SECRET_DIR=str(self.root), SUB_BODY=str(body),
                   CHECK_FQDN=self.endpoint, CHECK_TARGET='max.ru', TARGET_LABEL=self.label)
        result = subprocess.run([sys.executable, '-c', CODE], env=env, capture_output=True)
        self.assertEqual(result.returncode == 0, success, 'gate returned unexpected status')

    def change(self, index, **values):
        parts = urlsplit(self.links[index])
        query = parse_qs(parts.query)
        query.update({key: [value] for key, value in values.items()})
        self.links[index] = urlunsplit(parts._replace(query=urlencode(query, doseq=True)))

    def test_accepts_non_german_label_and_six_profiles(self):
        self.check(self.links, True)

    def test_accepts_ip_endpoint_with_certificate_verification(self):
        self.endpoint = '45.67.89.10'
        self.links = [link.replace('vpn.example.org', self.endpoint) for link in self.links]
        self.check(self.links, True)

    def test_accepts_literal_shell_characters_in_display_prefix(self):
        previous = self.label
        self.label = "Мой VPN \" ' `echo $HOME` ${value} / 😀"
        self.links = [link.replace(quote(previous), quote(self.label)) for link in self.links]
        self.check(self.links, True)

    def test_rejects_missing_profile(self):
        self.check(self.links[:-1], False)

    def test_rejects_duplicate_profile(self):
        self.links[-1] = self.links[0]
        self.check(self.links, False)

    def test_rejects_reality_sni_drift(self):
        self.change(3, sni='wrong.example.org')
        self.check(self.links, False)

    def test_rejects_reality_public_key_drift(self):
        self.change(0, pbk='z' * 43)
        self.check(self.links, False)

    def test_rejects_reality_vision(self):
        self.change(0, flow='xtls-rprx-vision')
        self.check(self.links, False)

    def test_rejects_insecure_hysteria(self):
        self.change(1, insecure='1')
        self.check(self.links, False)

    def test_rejects_xhttp_mode_drift(self):
        self.change(2, mode='auto')
        self.check(self.links, False)

    def test_rejects_xhttp_extra_mode_drift(self):
        self.change(5, extra='{"mode":"stream-one"}')
        self.check(self.links, False)

    def test_rejects_private_connector(self):
        self.change(4, opaque=self.secrets['connector.uuid'])
        self.check(self.links, False)

    def test_rejects_wrong_endpoint(self):
        self.links[0] = self.links[0].replace('@vpn.example.org:', '@wrong.example.org:')
        self.check(self.links, False)

    def test_rejects_wrong_identity(self):
        self.links[4] = self.links[4].replace(self.secrets['direct-hysteria.auth'], 'z' * 64)
        self.check(self.links, False)

    def test_embedded_python_parses(self):
        for file in [*ROOT.glob('scripts/*.sh'), *ROOT.glob('tests/*.sh')]:
            for code in re.findall(r"<<'PY'\n(.*?)\nPY", file.read_text(encoding='utf-8'), re.S):
                ast.parse(code, filename=str(file))


class TargetAddressContract(unittest.TestCase):
    def check(self, success, **changes):
        env = dict(os.environ, TARGET_IPV4='45.67.89.10', TARGET_FQDN='vpn.example.org',
                   TARGET_REALITY_SNI='max.ru', TARGET_ADDRESS_MODE='domain', TARGET_LABEL='Мой VPN')
        env.update(changes)
        result = subprocess.run([sys.executable, '-c', CONTRACT_CODE], env=env, capture_output=True)
        self.assertEqual(result.returncode == 0, success, 'target contract returned unexpected status')

    def test_domain(self):
        self.check(True)

    def test_ip(self):
        self.check(True, TARGET_ADDRESS_MODE='ip', TARGET_FQDN='45.67.89.10')

    def test_ip_must_equal_public_ipv4(self):
        self.check(False, TARGET_ADDRESS_MODE='ip', TARGET_FQDN='45.67.89.11')

    def test_domain_mode_does_not_accept_ip_literal(self):
        self.check(False, TARGET_FQDN='45.67.89.10')

    def test_reality_sni_remains_domain(self):
        self.check(False, TARGET_REALITY_SNI='45.67.89.10')

    def test_label_accepts_shell_characters_as_plain_text(self):
        self.check(True, TARGET_LABEL="Мой VPN \" ' `echo $HOME` ${value} / 😀")

    def test_label_rejects_line_separators_and_controls(self):
        for control in ('\x00', '\x0a', '\x7f', '\x85', '\u2028', '\u2029'):
            if control == '\x00':
                continue  # Process environments cannot represent a NUL byte.
            with self.subTest(control=ord(control)):
                self.check(False, TARGET_LABEL='Мой' + control + 'VPN')


@unittest.skipUnless(shutil.which('openssl') and (shutil.which('bash') or shutil.which('sh')),
                     'OpenSSL and Bash are required for certificate fixtures')
class EndpointCertificateGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.bash = shutil.which('bash') or shutil.which('sh')
        # Synthetic local certificates only: no ACME or network request.
        for name, san in [('ip', 'IP:45.67.89.10'), ('dns', 'DNS:vpn.example.org'),
                          ('ip_as_dns', 'DNS:45.67.89.10')]:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '6',
                            '-subj', '/CN=fixture', '-addext', 'subjectAltName=' + san,
                            '-keyout', str(cls.root / (name + '.key')),
                            '-out', str(cls.root / (name + '.pem'))],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def check(self, mode, name, success):
        env = dict(os.environ, TARGET_ADDRESS_MODE=mode, TARGET_IPV4='45.67.89.10',
                   TARGET_FQDN='45.67.89.10' if mode == 'ip' else 'vpn.example.org')
        result = subprocess.run([self.bash, '-c', CERTIFICATE_FUNCTION + '\nverify_target_certificate "$1"',
                                 'fixture', str(self.root / (name + '.pem'))],
                                env=env, capture_output=True)
        self.assertEqual(result.returncode == 0, success)

    def test_six_day_ip_certificate_is_accepted(self):
        self.check('ip', 'ip', True)

    def test_dns_certificate_is_accepted_for_domain(self):
        self.check('domain', 'dns', True)

    def test_ip_mode_rejects_dns_san_with_ip_text(self):
        self.check('ip', 'ip_as_dns', False)

    def test_ip_mode_rejects_other_domain_certificate(self):
        self.check('ip', 'dns', False)

    def test_domain_mode_rejects_ip_certificate(self):
        self.check('domain', 'ip', False)


if __name__ == '__main__':
    unittest.main()
