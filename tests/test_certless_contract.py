"""Exercise actual certless API/runtime and panel URL acceptance gates."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
POSTBOOT = ROOT / 'bundle/tests/postboot-certless-verify.sh'
CODE = re.findall(r"<<'PY'\n(.*?)\nPY", POSTBOOT.read_text(encoding='utf-8'), re.S)[0]
PANEL_CODE = re.findall(r"<<'PY'\n(.*?)\nPY", (ROOT / 'bundle/tests/panel-login-acceptance.sh').read_text(encoding='utf-8'), re.S)[0]


class CertificateFreeMainContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.secrets = {'direct-vless.uuid': '1' * 36,
                        'warp-reality.uuid': '2' * 36,
                        'warp-xhttp.uuid': '3' * 36,
                        'public-sub.id': '4' * 64,
                        'direct-sub.id': '5' * 64,
                        'connector.uuid': '6' * 36}
        for name, value in self.secrets.items():
            (self.root / name).write_text(value)
        self.env = dict(os.environ, CONTRACT_STAGE=str(self.root),
                        TARGET_FQDN='vpn.example.org', TARGET_IPV4='198.51.100.42',
                        TARGET_REALITY_SNI='max.ru', TARGET_DEVICE_LIMIT='0')
        self.source = []
        for port, protocol in ((443, 'reality'), (8443, 'xhttp')):
            clients = []
            for warp in (True, False):
                clients.append(dict(email='germany-' + ('warp-' if warp else '') + protocol,
                                    id=self.secrets['warp-' + protocol + '.uuid' if warp else 'direct-vless.uuid'],
                                    subId=self.secrets['public-sub.id' if warp else 'direct-sub.id'],
                                    limitIp=0, flow=''))
            self.source.append(dict(port=port, enable=port == 443, protocol='vless',
                                    shareAddr='vpn.example.org', settings={'clients': clients},
                                    streamSettings={'security': 'reality', 'realitySettings':
                                                    {'target': 'max.ru:443', 'serverNames': ['max.ru']}}))
        self.hosts = [dict(port=port, security='reality', sni='max.ru', isDisabled=False)
                      for port in (443, 8443)]
        self.runtime = dict(inbounds=[copy.deepcopy(self.source[0])],
                            outbounds=[{'tag': 'WARP_CF', 'protocol': 'vless', 'settings': {'vnext':
                                       [{'address': '127.0.0.1', 'port': 24443, 'users':
                                         [{'id': self.secrets['connector.uuid'], 'encryption': 'none'}]}]}}],
                            routing={'rules': [
                                {'inboundTag': ['api'], 'outboundTag': 'api'},
                                {'protocol': ['bittorrent'], 'outboundTag': 'BLOCK'},
                                {'inboundTag': ['dns_cf', 'dns_q9'], 'outboundTag': 'DIRECT'},
                                {'ip': ['geoip:private', '::/0', '198.51.100.42/32'], 'outboundTag': 'BLOCK'},
                                {'domain': ['full:vpn.example.org'], 'outboundTag': 'BLOCK'},
                                {'user': ['germany-warp-reality', 'germany-warp-xhttp'], 'outboundTag': 'WARP_CF'},
                                {'user': ['germany-reality', 'germany-xhttp'], 'outboundTag': 'DIRECT'},
                                {'network': 'tcp,udp', 'outboundTag': 'BLOCK'}]})

    def check(self, accepted):
        for name, value in (('inbounds.json', {'success': True, 'obj': self.source}),
                            ('hosts.json', {'success': True, 'obj': self.hosts}),
                            ('runtime.json', self.runtime)):
            (self.root / name).write_text(json.dumps(value))
        code = CODE.replace("Path('/usr/local/x-ui/bin/config.json')", "(root/'runtime.json')")
        result = subprocess.run([sys.executable, '-c', code], env=self.env,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode == 0, accepted, result.stderr.decode('utf-8', 'replace'))

    def test_accepts_two_protocols_four_clients_and_separate_egress_routes(self):
        self.check(True)

    def test_rejects_return_of_hysteria_or_certificate_transport(self):
        for mutation in ('hysteria', 'tls'):
            with self.subTest(mutation=mutation):
                original = copy.deepcopy(self.runtime)
                if mutation == 'hysteria':
                    self.runtime['inbounds'].append({'protocol': 'hysteria2', 'port': 443})
                else:
                    self.runtime['inbounds'][0]['streamSettings']['security'] = 'tls'
                self.check(False)
                self.runtime = original

    def test_rejects_warp_fallthrough_and_private_route_drift(self):
        for index in (3, 5):
            with self.subTest(index=index):
                original = self.runtime['routing']['rules'][index]['outboundTag']
                self.runtime['routing']['rules'][index]['outboundTag'] = 'DIRECT'
                self.check(False)
                self.runtime['routing']['rules'][index]['outboundTag'] = original

    def test_rejects_changed_source_credentials_and_host_sni(self):
        self.source[0]['settings']['clients'][0]['id'] = 'changed'
        self.check(False)
        self.source[0]['settings']['clients'][0]['id'] = self.secrets['warp-reality.uuid']
        self.hosts[1]['sni'] = 'other.example.org'
        self.check(False)


class PanelURLModeContract(unittest.TestCase):
    def test_http_only_in_explicit_none_mode_and_https_in_default_mode(self):
        for mode, scheme, accepted in (('none', 'http', True), ('none', 'https', False),
                                       ('letsencrypt', 'https', True), ('letsencrypt', 'http', False)):
            with self.subTest(mode=mode, scheme=scheme):
                env = dict(os.environ, TARGET_TLS_MODE=mode, TARGET_FQDN='vpn.example.org',
                           PANEL_BASE=scheme + '://vpn.example.org:2053/private-path/')
                result = subprocess.run([sys.executable, '-c', PANEL_CODE], env=env,
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode == 0, accepted)

    def test_rejects_wrong_public_address_before_sending_credentials(self):
        for url in ('http://other.example.org:2053/private/',
                    'http://vpn.example.org:2096/private/',
                    'http://user:password@vpn.example.org:2053/private/',
                    'http://vpn.example.org:2053/private/?query=1'):
            with self.subTest(url=url):
                env = dict(os.environ, TARGET_TLS_MODE='none', TARGET_FQDN='vpn.example.org', PANEL_BASE=url)
                result = subprocess.run([sys.executable, '-c', PANEL_CODE], env=env,
                                        capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
