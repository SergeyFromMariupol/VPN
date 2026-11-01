"""Exercise both certificate modes without a CA, packages or host services."""
import base64
import copy
from contextlib import closing
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import ssl
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import quote, unquote, urlencode, urlsplit


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('certificate_mode_finalizer',
    ROOT / 'bundle/scripts/finalize-xhttp.py')
FINAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FINAL)
NETWORK_SPEC = importlib.util.spec_from_file_location('certificate_mode_network',
    ROOT / 'bundle/scripts/network-contract.py')
NETWORK = importlib.util.module_from_spec(NETWORK_SPEC)
NETWORK_SPEC.loader.exec_module(NETWORK)

DIRECT = '33333333-3333-4333-8333-333333333333'
WARP_REALITY = '11111111-1111-4111-8111-111111111111'
WARP_XHTTP = '22222222-2222-4222-8222-222222222222'
PUBLIC_KEY = 'B' * 43
SHORT_ID = '0123456789abcdef'
SECRET = {'VLESS_UUID': DIRECT, 'REALITY_PUBLIC_KEY': PUBLIC_KEY,
          'REALITY_SHORT_ID': SHORT_ID, 'XHTTP_PRIVATE_PATH': 'fixture-private-path',
          'WARP_REALITY_UUID': WARP_REALITY, 'WARP_XHTTP_UUID': WARP_XHTTP,
          'SUBSCRIPTION_PATH': 'fixture-subscription', 'SUBSCRIPTION_ID': 'fixture-id'}


def target(mode=None):
    value = {'TARGET_IPV4': '203.0.113.123', 'TARGET_FQDN': 'vpn.example.test',
             'TARGET_ADDRESS_MODE': 'domain', 'TARGET_REALITY_SNI': 'max.ru',
             'TARGET_LABEL': 'Тест', 'TARGET_INTERFACE': 'ens3', 'TARGET_SSH_PORT': '2222'}
    if mode is not None:
        value['TARGET_TLS_MODE'] = mode
    return value


def links(settings, dual=True):
    """Independent fixture feeds with the published order, not production names."""
    tls = settings.get('TARGET_TLS_MODE', 'letsencrypt') == 'letsencrypt'
    protocols = ('REALITY', 'HYSTERIA2', 'XHTTP') if tls else ('REALITY', 'XHTTP')
    result = []
    for role in (('warp', 'direct') if dual else ('direct',)):
        for protocol in protocols:
            identity = DIRECT
            if role == 'warp':
                identity = WARP_XHTTP if protocol == 'XHTTP' else WARP_REALITY
            values = {'security': 'reality', 'sni': settings['TARGET_REALITY_SNI'],
                      'pbk': PUBLIC_KEY, 'sid': SHORT_ID, 'fp': 'chrome'}
            scheme, port = 'vless', 443
            if protocol == 'REALITY':
                values.update(type='grpc', serviceName='reality-grpc')
            elif protocol == 'HYSTERIA2':
                scheme, identity = 'hysteria2', role + '-fixture-auth'
                values = {'sni': settings['TARGET_FQDN'], 'alpn': 'h3', 'insecure': '0'}
            else:
                port = 8443
                values.update(type='xhttp', host=settings['TARGET_FQDN'],
                              path='/' + SECRET['XHTTP_PRIVATE_PATH'], mode='packet-up')
                if tls:
                    values = {'security': 'tls', 'sni': settings['TARGET_FQDN'], 'alpn': 'h2',
                              'type': 'xhttp', 'host': settings['TARGET_FQDN'],
                              'path': '/' + SECRET['XHTTP_PRIVATE_PATH'], 'mode': 'packet-up'}
            prefix = settings['TARGET_LABEL']
            if dual:
                prefix += ' · ' + ('☁️ Cloudflare' if role == 'warp' else '🖥️ IP сервера')
            result.append(f'{scheme}://{identity}@{settings["TARGET_FQDN"]}:{port}?'
                          + urlencode(values) + '#' + quote(prefix + ' · ' + protocol))
    return result


def main_config():
    return {
        'dns': {'servers': [{'address': '1.1.1.1', 'tag': 'dns_cf'}]},
        'inbounds': [{'port': 8443, 'settings': {'clients': [
            {'id': DIRECT, 'email': 'germany-xhttp', 'flow': ''},
            {'id': WARP_XHTTP, 'email': 'germany-warp-xhttp', 'flow': ''}]}}],
        'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom'},
                      {'tag': 'BLOCK', 'protocol': 'blackhole'},
                      {'tag': 'WARP_CF', 'protocol': 'vless', 'settings': {'vnext': [
                          {'address': '127.0.0.1', 'port': 24443,
                           'users': [{'id': '44444444-4444-4444-8444-444444444444'}]}]}}]}


def create_database(path, settings):
    count = 4 if settings.get('TARGET_TLS_MODE') == 'none' else 6
    feed = links(settings)
    direct = feed[count // 2:]
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript('CREATE TABLE clients(id INTEGER); '
                         'CREATE TABLE client_inbounds(client_id INTEGER); '
                         'CREATE TABLE client_external_links(id INTEGER,sort_index INTEGER,value TEXT,remark TEXT); '
                         'CREATE TABLE inbounds(id INTEGER,port INTEGER,enable INTEGER);')
        db.executemany('INSERT INTO clients VALUES(?)', [(index,) for index in range(count)])
        db.executemany('INSERT INTO client_inbounds VALUES(?)', [(index,) for index in range(count)])
        db.executemany('INSERT INTO client_external_links VALUES(?,?,?,?)',
                       [(index + 1, index, uri, unquote(urlsplit(uri).fragment))
                        for index, uri in enumerate(direct)])
        ports = (443, 8443) if count == 4 else (443, 443, 8443)
        db.executemany('INSERT INTO inbounds VALUES(?,?,1)', enumerate(ports, start=1))


class CertificateModeFinalizer(unittest.TestCase):
    def test_none_has_four_exact_ordered_names_and_legacy_defaults_to_six(self):
        none = ['Тест · ☁️ Cloudflare · REALITY', 'Тест · ☁️ Cloudflare · XHTTP',
                'Тест · 🖥️ IP сервера · REALITY', 'Тест · 🖥️ IP сервера · XHTTP']
        self.assertEqual(FINAL.profile_names(target('none')), none)
        self.assertEqual(FINAL.profile_count(target('none')), 4)
        self.assertEqual(FINAL.profile_names(target()), FINAL.profile_names(target('letsencrypt')))
        self.assertEqual(FINAL.profile_count(target()), 6)
        for bad in ('', 'selfsigned', 'http', 'unknown'):
            with self.subTest(mode=bad), self.assertRaisesRegex(RuntimeError, 'TLS_MODE'):
                FINAL.profile_names(target(bad))

    def test_none_legacy_feed_uses_reality_for_both_transports_without_hysteria_secret(self):
        settings = target('none')
        feed = links(settings, dual=False)
        FINAL.validate_legacy_feed(feed, settings, SECRET)
        for uri in feed:
            client = FINAL.client_config(uri, 11223)['outbounds'][0]
            self.assertEqual(client['streamSettings']['security'], 'reality')
            self.assertNotIn('tlsSettings', client['streamSettings'])
        with self.assertRaisesRegex(RuntimeError, 'LEGACY_XHTTP_URI'):
            FINAL.validate_legacy_feed([feed[0], feed[1].replace('security=reality', 'security=tls')],
                                       settings, SECRET)
        with self.assertRaisesRegex(RuntimeError, 'LEGACY_HYSTERIA_DISABLED'):
            FINAL.validate_legacy_feed([feed[0], 'hysteria2://fixture@vpn.example.test:443?sni=vpn.example.test'],
                                       settings, SECRET)

    def test_letsencrypt_legacy_keeps_three_transports_and_verified_tls(self):
        settings = target('letsencrypt')
        secret = {**SECRET, 'HYSTERIA2_AUTH': 'direct-fixture-auth'}
        feed = links(settings, dual=False)
        FINAL.validate_legacy_feed(feed, settings, secret)
        for uri in feed[1:]:
            tls = FINAL.client_config(uri, 11223)['outbounds'][0]['streamSettings']['tlsSettings']
            self.assertFalse(tls['allowInsecure'])
        with self.assertRaisesRegex(RuntimeError, 'LEGACY_FEED_COUNT'):
            FINAL.validate_legacy_feed(feed[:2], settings, secret)

    def test_promoted_feed_replaces_only_the_two_xhttp_uris_in_either_mode(self):
        for mode, indexes in (('none', (1, 3)), ('letsencrypt', (2, 5))):
            with self.subTest(mode=mode):
                settings = target(mode)
                before = links(settings)
                configs = FINAL.build(main_config(), settings, 'A' * 43, SHORT_ID, '/promoted-path')
                saved = copy.deepcopy(before)
                after = FINAL.promoted_feed(before, settings, configs, 'C' * 43)
                self.assertEqual(before, saved)
                self.assertEqual([index for index in range(len(before)) if before[index] != after[index]], list(indexes))
                self.assertEqual([urlsplit(after[index]).port for index in indexes], [8443, 8444])
                self.assertEqual([unquote(urlsplit(uri).fragment) for uri in after], FINAL.profile_names(settings))
                for index in indexes:
                    stream = FINAL.client_config(after[index], 11223)['outbounds'][0]['streamSettings']
                    self.assertEqual(stream['security'], 'reality')
                    self.assertNotIn('tlsSettings', stream)

    def test_real_sqlite_client_counts_reject_cross_mode_state(self):
        for mode, count in (('none', 4), ('letsencrypt', 6)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'panel.db'
                create_database(path, target(mode))
                original = path.read_bytes()
                with patch.object(FINAL, 'DB', path):
                    rows, inbounds = FINAL.database(target(mode))
                    self.assertEqual(len(rows), count // 2)
                    self.assertEqual(len(inbounds), count // 2)
                    other = 'letsencrypt' if mode == 'none' else 'none'
                    with self.assertRaisesRegex(RuntimeError, 'DB_CLIENT_COUNT'):
                        FINAL.database(target(other))
                self.assertEqual(path.read_bytes(), original)

    def test_published_none_feed_matches_exact_runtime_and_rejects_hysteria_or_tls(self):
        settings = target('none')
        main = main_config()
        configs = FINAL.build(main, settings, 'A' * 43, SHORT_ID, '/promoted-path')
        feed = FINAL.promoted_feed(links(settings), settings, configs, PUBLIC_KEY)
        secret = {**SECRET, 'DIRECT_SUBSCRIPTION_ID': 'private-direct-subscription'}
        with patch.object(FINAL, 'public_key', return_value=PUBLIC_KEY):
            FINAL.verify_published_profiles(feed, settings, secret, configs, main)
            for altered in (
                    [feed[0].replace('max.ru', 'wrong.example.test'), *feed[1:]],
                    [feed[0], feed[1].replace('security=reality', 'security=tls'), *feed[2:]],
                    [feed[0], 'hysteria2://fixture@vpn.example.test:443?sni=vpn.example.test', *feed[2:]],
                    [feed[2], feed[1], feed[0], feed[3]],
                    feed + [feed[0]],
                    [feed[0].replace('#', '&opaque=private-direct-subscription#'), *feed[1:]]):
                with self.subTest(altered=altered), self.assertRaises(RuntimeError):
                    FINAL.verify_published_profiles(altered, settings, secret, configs, main)

    def test_none_fetches_all_three_user_agents_over_actual_http_without_tls(self):
        settings = target('none')
        body = base64.b64encode(('\n'.join(links(settings)) + '\n').encode())
        observed = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                observed.append((self.path, self.headers.get('User-Agent')))
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        original_connection = http.client.HTTPConnection
        requests = []

        def connect(host, port, **kwargs):
            requests.append((host, port))
            return original_connection('127.0.0.1', server.server_port, **kwargs)

        try:
            with patch.object(FINAL.http.client, 'HTTPConnection', side_effect=connect), \
                 patch.object(FINAL.http.client, 'HTTPSConnection', side_effect=AssertionError('unexpected TLS')), \
                 patch.object(FINAL.ssl, 'create_default_context', side_effect=AssertionError('unexpected CA read')):
                self.assertEqual(FINAL.native(settings, SECRET), links(settings))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)
        self.assertEqual(requests, [('vpn.example.test', 2096)] * 3)
        self.assertEqual(observed, [('/fixture-subscription/fixture-id', name)
                                    for name in ('v2RayTun', 'Happ', 'Karing')])

    def test_default_mode_fetches_six_over_https_with_hostname_and_chain_validation(self):
        response = Mock(status=200)
        response.read.return_value = base64.b64encode('\n'.join(links(target())).encode())
        connection = Mock()
        connection.getresponse.return_value = response
        with patch.object(FINAL.http.client, 'HTTPConnection', side_effect=AssertionError('unexpected HTTP')), \
             patch.object(FINAL.http.client, 'HTTPSConnection', return_value=connection) as create:
            self.assertEqual(FINAL.native(target(), SECRET), links(target()))
        self.assertEqual(create.call_count, 3)
        for call in create.call_args_list:
            context = call.kwargs['context']
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_none_failed_promotion_requires_four_independent_payload_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, binary = root / 'runtime.json', root / 'xray'
            runtime.write_bytes(b'{"inbounds":[]}')
            binary.write_bytes(b'fixture-binary')
            settings = target('none')
            feed = links(settings)
            payload = Mock()
            with patch.object(FINAL, 'RUNTIME', runtime), patch.object(FINAL, 'SOURCE_XRAY', binary), \
                 patch.object(FINAL, 'XRAY_SHA', FINAL.sha(binary.read_bytes())), \
                 patch.object(FINAL, 'UNIT_PATHS', (root / 'unit1', root / 'unit2')), \
                 patch.object(FINAL, 'ROOT', root / 'direct'), patch.object(FINAL, 'CFROOT', root / 'warp'), \
                 patch.object(FINAL, 'EXECROOT', root / 'exec'), \
                 patch.object(FINAL, 'run', return_value=Mock(stdout=b'')), \
                 patch.object(FINAL, 'database', return_value=([], [])), \
                 patch.object(FINAL, 'routes', return_value={}), patch.object(FINAL, 'native', return_value=feed), \
                 patch.object(FINAL, 'payload', payload), \
                 patch.object(FINAL.subprocess, 'run', return_value=Mock(returncode=3)):
                FINAL.verify_xhttp_rollback(settings, {}, runtime.read_bytes(), [], [], feed, {})
                self.assertEqual([call.args[1] for call in payload.call_args_list], [True, True, False, False])
                self.assertEqual([call.args[0] for call in payload.call_args_list], feed)
                payload.reset_mock()
                payload.side_effect = [None, None, None, RuntimeError('PAYLOAD_EGRESS')]
                with self.assertRaisesRegex(RuntimeError, 'PAYLOAD_EGRESS'):
                    FINAL.verify_xhttp_rollback(settings, {}, runtime.read_bytes(), [], [], feed, {})
                self.assertEqual(payload.call_count, 4)

    def test_real_pre_mutation_promotion_omits_certificate_snapshot_only_in_none_mode(self):
        class SnapshotReached(Exception):
            pass

        for mode in ('none', 'letsencrypt'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                settings = target(mode)
                db, runtime, binary = root / 'panel.db', root / 'runtime.json', root / 'xray'
                create_database(db, settings)
                runtime.write_text(json.dumps(main_config()))
                binary.write_bytes(b'fixture-xray')
                backup = root / 'backup'
                calls = []

                def mkbackup(**kwargs):
                    self.assertEqual(kwargs['dir'], '/var/backups')
                    backup.mkdir()
                    return str(backup)

                def save(path, raw, **kwargs):
                    self.assertTrue(path.is_relative_to(root))
                    path.write_bytes(raw)

                def command(args, **kwargs):
                    calls.append(args)
                    if args[0] == 'tar':
                        raise SnapshotReached()
                    self.assertEqual(args, [str(binary), 'x25519'])
                    return Mock(stdout=b'PrivateKey: ' + b'A' * 43 + b'\nPublicKey: ' + b'B' * 43 + b'\n')

                fake_pwd = types.SimpleNamespace(getpwnam=Mock(side_effect=KeyError('fixture user missing')))
                with patch.dict(sys.modules, {'pwd': fake_pwd}), \
                     patch.dict(os.environ, {'CONFIRM_FRESH_XHTTP': 'FINALIZE-FRESH-XHTTP'}), \
                     patch.object(FINAL, 'DB', db), patch.object(FINAL, 'RUNTIME', runtime), \
                     patch.object(FINAL, 'SOURCE_XRAY', binary), patch.object(FINAL, 'XRAY_SHA', FINAL.sha(binary.read_bytes())), \
                     patch.object(FINAL, 'ROOT', root / 'direct'), patch.object(FINAL, 'CFROOT', root / 'warp'), \
                     patch.object(FINAL, 'EXECROOT', root / 'exec'), \
                     patch.object(FINAL, 'UNIT_PATHS', (root / 'unit1', root / 'unit2')), \
                     patch.object(FINAL, 'native', return_value=links(settings)), \
                     patch.object(FINAL, 'routes', return_value={}), patch.object(FINAL, 'save', side_effect=save), \
                     patch.object(FINAL, 'run', side_effect=command), \
                     patch.object(FINAL.tempfile, 'mkdtemp', side_effect=mkbackup), \
                     self.assertRaises(SnapshotReached):
                    FINAL.finalize(settings, {})
                archive = next(args for args in calls if args[0] == 'tar')
                self.assertEqual('etc/letsencrypt' in archive, mode == 'letsencrypt')
                self.assertIn('etc/x-ui', archive)
                self.assertTrue((backup / 'x-ui.db').is_file())
                self.assertFalse((root / 'direct').exists())


class CertificateModeNetwork(unittest.TestCase):
    def listeners(self, promoted, hysteria):
        ports = [2222, 443, 2053, 2096, 8443] + ([8444] if promoted else [])
        listeners = [NETWORK.Listener('tcp', '203.0.113.123', port, None, ()) for port in ports]
        if hysteria:
            listeners.append(NETWORK.Listener('udp', '203.0.113.123', 443, None, ()))
        return listeners

    def firewall(self, promoted, certificate):
        text = ('Status: active\n'
                'Default: deny (incoming), allow (outgoing), deny (routed)\n\n'
                'To                         Action      From\n'
                '--                         ------      ----\n')
        ports = [(2222, 'tcp'), (443, 'tcp'), (2096, 'tcp'), (8443, 'tcp')]
        if certificate:
            ports += [(80, 'tcp'), (443, 'udp')]
        for port, transport in ports:
            for suffix in ('', ' (v6)'):
                text += f'{str(port) + "/" + transport + suffix:<40} ALLOW IN    Anywhere{suffix}\n'
        for port in [2053] + ([8444] if promoted else []):
            text += f'{"203.0.113.123 " + str(port) + "/tcp on ens3":<40} ALLOW IN    Anywhere\n'
        return text

    def test_none_rejects_public_hysteria_udp_while_legacy_mode_requires_it(self):
        for promoted in (False, True):
            with self.subTest(promoted=promoted):
                plain = self.listeners(promoted, hysteria=False)
                secure = self.listeners(promoted, hysteria=True)
                NETWORK.validate_listeners(plain, '203.0.113.123', 'ens3', 2222, promoted, tls_mode='none')
                with self.assertRaises(ValueError):
                    NETWORK.validate_listeners(secure, '203.0.113.123', 'ens3', 2222, promoted, tls_mode='none')
                NETWORK.validate_listeners(secure, '203.0.113.123', 'ens3', 2222, promoted)
                with self.assertRaises(ValueError):
                    NETWORK.validate_listeners(plain, '203.0.113.123', 'ens3', 2222, promoted)

    def test_none_firewall_omits_acme_and_udp443_and_cannot_accept_tls_rules(self):
        defaults = 'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_FORWARD_POLICY="DROP"\n'
        for promoted in (False, True):
            with self.subTest(promoted=promoted):
                none = self.firewall(promoted, certificate=False)
                secure = self.firewall(promoted, certificate=True)
                NETWORK.validate_ufw(none, '203.0.113.123', 'ens3', 2222, promoted, defaults, tls_mode='none')
                with self.assertRaises(ValueError):
                    NETWORK.validate_ufw(secure, '203.0.113.123', 'ens3', 2222, promoted, defaults, tls_mode='none')
                NETWORK.validate_ufw(secure, '203.0.113.123', 'ens3', 2222, promoted, defaults)
                with self.assertRaises(ValueError):
                    NETWORK.validate_ufw(none, '203.0.113.123', 'ens3', 2222, promoted, defaults)


if __name__ == '__main__':
    unittest.main()
