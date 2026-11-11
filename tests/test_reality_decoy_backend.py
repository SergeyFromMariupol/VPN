"""Own-certificate target, scan behavior, website reset and PHP safeguards."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'bundle/base' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DECOY = load('backend_decoy', 'reality-decoy.py')
SITE = load('backend_decoy_site', 'reality-decoy-site.py')
PHP = load('backend_decoy_php', 'reality-decoy-php.py')


def target(mode='decoy', address='domain'):
    return {'TARGET_REALITY_MODE': mode, 'TARGET_REALITY_SNI': 'max.ru' if mode == 'decoy' else 'own.example.test',
            'TARGET_TLS_MODE': 'letsencrypt', 'TARGET_ADDRESS_MODE': address,
            'TARGET_FQDN': 'own.example.test' if address == 'domain' else '203.0.113.10',
            'TARGET_IPV4': '203.0.113.10'}


class FakeContext:
    def __init__(self):
        self.check_hostname = True
        self.alpn = []

    def set_alpn_protocols(self, values):
        self.alpn = values


class FakeStream:
    def __init__(self, context, certificate=b'own-leaf'):
        self.context = context
        self.certificate = certificate
        self.response = b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nMy own custom page'

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def version(self):
        return 'TLSv1.3'

    def selected_alpn_protocol(self):
        return self.context.alpn[0]

    def getpeercert(self, binary_form=False):
        return self.certificate

    def sendall(self, _data):
        pass

    def recv(self, _size):
        response, self.response = self.response, b''
        return response


class DecoyRendering(unittest.TestCase):
    def test_decoy_uses_only_own_certificate_and_private_default_listener(self):
        text = DECOY.render(target())
        self.assertIn('listen 127.0.0.1:9443 ssl http2 default_server;', text)
        self.assertIn('/etc/letsencrypt/live/own.example.test/fullchain.pem', text)
        self.assertIn('root /var/www/vpn-decoy/public;', text)
        self.assertNotIn('max.ru', text)
        self.assertNotIn('ssl_reject_handshake', text)
        self.assertNotIn('listen 0.0.0.0', text)
        self.assertIn('location ~* \\.php(?:/|$) { return 404; }', text)

    def test_ip_decoy_can_use_current_short_lived_ip_certificate(self):
        settings = target(address='ip')
        settings['TARGET_CERT_NAME'] = 'vpn-ip-' + 'a' * 24
        text = DECOY.render(settings)
        self.assertIn('/live/vpn-ip-' + 'a' * 24 + '/fullchain.pem', text)
        self.assertNotIn('max.ru', text)

    def test_local_modes_reject_untrusted_or_mismatched_endpoint_contracts(self):
        cases = [dict(TARGET_TLS_MODE='none'), dict(TARGET_REALITY_MODE='external'),
                 dict(TARGET_FQDN='host.test;return 200'), dict(TARGET_REALITY_SNI='1.2.3.4'),
                 dict(TARGET_CERT_NAME='../../private')]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                DECOY.render({**target(), **changes})
        with self.assertRaises(ValueError):
            DECOY.render(target('self-steal', 'ip'))
        with self.assertRaises(ValueError):
            DECOY.render({**target('self-steal'), 'TARGET_REALITY_SNI': 'max.ru'})

    def test_php_executes_only_existing_scripts_and_never_leaks_other_php_source(self):
        text = DECOY.render(target(), php_enabled=True)
        self.assertIn('index index.php index.html;', text)
        self.assertIn('try_files $uri =404;', text)
        self.assertIn('fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;', text)
        self.assertIn('fastcgi_pass unix:/run/php/vpn-decoy.sock;', text)
        self.assertIn('location ~* \\.php(?:/|$) { return 404; }', text)
        self.assertLess(text.index('location ~ /\\.'), text.index('location ~ \\.php$'))


class DecoyProbes(unittest.TestCase):
    def probe(self, env, *, bad_name=None, page=True):
        context = FakeContext()
        calls = []

        def connection(ctx, name):
            calls.append((name, ctx.check_hostname, tuple(ctx.alpn)))
            return FakeStream(ctx, b'foreign-leaf' if bad_name is not None and bad_name == name else b'own-leaf')

        with patch.object(DECOY.ssl, 'create_default_context', return_value=context), \
                patch.object(DECOY, 'connection', side_effect=connection), \
                patch.object(DECOY, 'expected_leaf', return_value=hashlib.sha256(b'own-leaf').digest()):
            DECOY.probe(env, check_page=page)
        return context, calls

    def test_only_own_identity_counts_as_hostname_validation(self):
        context, calls = self.probe(target())
        self.assertEqual(calls, [('own.example.test', True, ('h2',)), ('max.ru', False, ('h2',)),
                                 ('probe.invalid', False, ('h2',)), (None, False, ('h2',)),
                                 ('own.example.test', True, ('http/1.1',))])
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(context.maximum_version, ssl.TLSVersion.TLSv1_3)

    def test_ip_identity_is_checked_as_an_ip_and_not_as_the_external_sni(self):
        _, calls = self.probe(target(address='ip'))
        self.assertEqual(calls[0], ('203.0.113.10', True, ('h2',)))
        self.assertEqual(calls[1], ('max.ru', False, ('h2',)))

    def test_scanner_getting_a_foreign_certificate_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SCANNER_CERTIFICATE'):
            self.probe(target(), bad_name='max.ru')

    def test_tls_only_probe_does_not_require_a_working_index_to_repair_a_page(self):
        _, calls = self.probe(target(), page=False)
        self.assertEqual(len(calls), 4)


class PhpOrigins(unittest.TestCase):
    PACKAGE = '''php8.3-fpm:
  Installed: (none)
  Candidate: 8.3.6-0ubuntu0.24.04.5
  Version table:
     8.3.6-0ubuntu0.24.04.5 500
        500 http://archive.ubuntu.com/ubuntu noble-updates/universe amd64 Packages
'''
    REPOSITORY = '''Package files:
 500 http://archive.ubuntu.com/ubuntu noble-updates/universe amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-updates,n=noble,l=Ubuntu,c=universe,b=amd64
'''

    def test_accepts_candidate_with_authenticated_ubuntu_origin(self):
        PHP.check_ubuntu_source(self.PACKAGE, self.REPOSITORY)

    def test_rejects_unknown_or_foreign_candidate_origin(self):
        for repositories in ('', self.REPOSITORY.replace('o=Ubuntu', 'o=Foreign')):
            with self.subTest(repositories=repositories), self.assertRaises(ValueError):
                PHP.check_ubuntu_source(self.PACKAGE, repositories)

    def test_php_pool_has_a_separate_uid_and_no_public_socket(self):
        self.assertIn('user = vpnsite\ngroup = vpnsite', PHP.POOL)
        self.assertIn('listen = /run/php/vpn-decoy.sock', PHP.POOL)
        self.assertIn('listen.mode = 0660', PHP.POOL)
        self.assertIn('clear_env = yes', PHP.POOL)
        self.assertIn('security.limit_extensions = .php', PHP.POOL)
        self.assertIn('open_basedir] = /var/www/vpn-decoy/public:/var/lib/vpn-decoy/tmp', PHP.POOL)


@unittest.skipUnless(os.name == 'posix', 'POSIX no-follow and owner metadata are required')
class PageReset(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpn-page-reset-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.page = self.root / 'index.html'
        self.php = self.root / 'index.php'
        self.backups = self.root / 'backups'; self.backups.mkdir()
        self.asset = self.root / 'asset.css'; self.asset.write_text('keep me')
        self.page.write_text('old HTML')
        self.php.write_text('<?php echo "old PHP";')

    def test_resets_both_entrypoints_with_private_snapshots_and_preserves_assets(self):
        SITE.reset(self.page, backup_root=self.backups, verify=lambda: None)
        self.assertEqual(self.page.read_text(), SITE.CORE.BODY)
        self.assertFalse(self.php.exists())
        self.assertEqual(self.asset.read_text(), 'keep me')
        backup, = self.backups.iterdir()
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        self.assertEqual((backup / 'index.html').read_text(), 'old HTML')
        self.assertEqual((backup / 'index.php').read_text(), '<?php echo "old PHP";')
        self.assertTrue((backup / 'COMMITTED').is_file())

    def test_failed_payload_check_restores_both_original_entrypoints(self):
        with self.assertRaisesRegex(ValueError, 'payload'):
            SITE.reset(self.page, backup_root=self.backups, verify=lambda: (_ for _ in ()).throw(ValueError('payload')))
        self.assertEqual(self.page.read_text(), 'old HTML')
        self.assertEqual(self.php.read_text(), '<?php echo "old PHP";')
        self.assertEqual(self.asset.read_text(), 'keep me')

    def test_symlink_index_is_not_followed_or_overwritten(self):
        self.page.unlink(); self.page.symlink_to(self.asset)
        with self.assertRaises(OSError):
            SITE.reset(self.page, backup_root=self.backups)
        self.assertEqual(self.asset.read_text(), 'keep me')
        self.assertTrue(self.page.is_symlink())


if __name__ == '__main__':
    unittest.main()
