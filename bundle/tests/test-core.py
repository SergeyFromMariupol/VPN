#!/usr/bin/env python3
"""Exercise the actual baseline subscription gate without touching a server."""
import ast
import base64
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import quote, urlencode, urlsplit, urlunsplit, parse_qs

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tests/postboot-verify.sh'
CODE = next(code for code in re.findall(r"<<'PY'\n(.*?)\nPY", SCRIPT.read_text(encoding='utf-8'), re.S)
            if 'Reality public parameter mismatch' in code)


class BaselineSubscriptionGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.label = '🇳🇱 Нидерланды'
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
                   CHECK_FQDN='vpn.example.org', CHECK_TARGET='max.ru', TARGET_LABEL=self.label)
        result = subprocess.run([sys.executable, '-c', CODE], env=env, capture_output=True)
        self.assertEqual(result.returncode == 0, success, 'gate returned unexpected status')

    def change(self, index, **values):
        parts = urlsplit(self.links[index])
        query = parse_qs(parts.query)
        query.update({key: [value] for key, value in values.items()})
        self.links[index] = urlunsplit(parts._replace(query=urlencode(query, doseq=True)))

    def test_accepts_non_german_label_and_six_profiles(self):
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


if __name__ == '__main__':
    unittest.main()
