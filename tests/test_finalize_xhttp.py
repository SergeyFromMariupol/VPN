"""Offline regression tests for the fresh XHTTP transition and SQL ownership."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('finalize_xhttp', ROOT / 'bundle/scripts/finalize-xhttp.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalizerTests(unittest.TestCase):
    def setUp(self):
        self.target = {'TARGET_IPV4': '203.0.113.123', 'TARGET_FQDN': 'vpn.example.test',
                       'TARGET_REALITY_SNI': 'camouflage.example.test', 'TARGET_LABEL': 'Тест'}
        self.main = {
            'dns': {'servers': [{'address': '1.1.1.1', 'tag': 'dns_cf'},
                                {'address': '9.9.9.9', 'tag': 'dns_q9'}]},
            'inbounds': [{'port': 8443, 'settings': {'clients': [
                {'id': 'direct-fixture', 'email': 'germany-xhttp', 'flow': ''},
                {'id': 'warp-fixture', 'email': 'germany-warp-xhttp', 'flow': ''}]}}],
            'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom'},
                          {'tag': 'BLOCK', 'protocol': 'blackhole'},
                          {'tag': 'WARP_CF', 'protocol': 'vless', 'settings': {'vnext': [
                              {'address': '127.0.0.1', 'port': 24443, 'users': [{'id': 'connector-fixture'}]}]}}]}

    def configs(self):
        return module.build(self.main, self.target, 'A' * 43, '0123456789abcdef', '/fixture-private-path')

    def test_singleton_isolation_and_fail_closed(self):
        before = copy.deepcopy(self.main)
        direct, warp = self.configs()
        self.assertEqual(self.main, before)
        self.assertEqual([c['inbounds'][0]['port'] for c in (direct, warp)], [8444, 8443])
        self.assertEqual([len(c['inbounds'][0]['settings']['clients']) for c in (direct, warp)], [1, 1])
        self.assertEqual(direct['inbounds'][0]['streamSettings'], warp['inbounds'][0]['streamSettings'])
        for config, role in ((direct, 'DIRECT'), (warp, 'WARP_CF')):
            self.assertEqual(config['routing']['rules'][-2]['outboundTag'], role)
            self.assertEqual(config['routing']['rules'][-1]['outboundTag'], 'BLOCK')
            self.assertFalse(any('user' in rule for rule in config['routing']['rules']))
            self.assertEqual(config['inbounds'][0]['streamSettings']['sockopt'], {'tcpMaxSeg': 1200})
        self.assertEqual([o['tag'] for o in direct['outbounds']], ['DIRECT', 'BLOCK'])
        self.assertEqual([o['tag'] for o in warp['outbounds']], ['DIRECT', 'BLOCK', 'WARP_CF'])
        self.assertEqual(warp['outbounds'][-1], self.main['outbounds'][-1])

    def test_uri_roundtrip_preserves_exact_endpoint_and_security(self):
        config = self.configs()[1]
        uri = module.uri_for(config, 'B' * 43, 'Тест · ☁️ Cloudflare · XHTTP')
        parsed, query = module.query(uri)
        self.assertEqual(parsed.hostname, self.target['TARGET_FQDN'])
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(query['sni'], self.target['TARGET_REALITY_SNI'])
        self.assertEqual(query['mode'], 'stream-one')
        self.assertEqual(json.loads(query['extra']), {'mode': 'stream-one'})
        client = module.client_config(uri, 11223)['outbounds'][0]
        self.assertEqual(client['settings']['vnext'][0]['address'], parsed.hostname)
        self.assertEqual(client['settings']['vnext'][0]['port'], parsed.port)
        self.assertEqual(client['streamSettings']['realitySettings']['publicKey'], query['pbk'])
        self.assertEqual(client['streamSettings']['xhttpSettings']['path'], query['path'])
        self.assertEqual(client['streamSettings']['xhttpSettings']['extra'], {'mode': 'stream-one'})
        self.assertNotIn('tlsSettings', client['streamSettings'])

    def test_hysteria_native_client_contract(self):
        conf = module.client_config('hysteria2://fixture-auth@vpn.example.test:443?sni=vpn.example.test&alpn=h3&fp=chrome', 11223)
        out = conf['outbounds'][0]
        self.assertEqual(out['settings'], {'version': 2, 'address': 'vpn.example.test', 'port': 443})
        self.assertEqual(out['streamSettings']['hysteriaSettings']['auth'], 'fixture-auth')
        self.assertFalse(out['streamSettings']['tlsSettings']['allowInsecure'])
        with self.assertRaisesRegex(RuntimeError, 'CLIENT_HY2'):
            module.client_config('hysteria2://fixture-auth@vpn.example.test:443?insecure=1', 11223)

    def test_parser_refuses_duplicate_fields_and_partial_feeds(self):
        with self.assertRaisesRegex(RuntimeError, 'DUP_URI_QUERY'):
            module.query('vless://fixture@vpn.example.test:443?type=grpc&type=xhttp')
        with self.assertRaisesRegex(RuntimeError, 'DUP_JSON_KEY'):
            module.strict_json('{"mode":"auto","mode":"stream-one"}')
        with self.assertRaisesRegex(RuntimeError, 'NATIVE_SIX_COUNT'):
            module.decode_feed(b'vless://only-one@vpn.example.test:443')
        rows = ['vless://fixture' + str(i) + '@vpn.example.test:443' for i in range(6)]
        self.assertEqual(module.decode_feed(base64.b64encode('\n'.join(rows).encode())), rows)

    def test_refuses_unexpected_connector_or_clients(self):
        self.main['outbounds'][-1]['settings']['vnext'][0]['address'] = '198.51.100.1'
        with self.assertRaisesRegex(RuntimeError, 'PRIVATE_CONNECTOR'):
            self.configs()
        self.main['outbounds'][-1]['settings']['vnext'][0]['address'] = '127.0.0.1'
        self.main['inbounds'][0]['settings']['clients'][0]['email'] = 'foreign-client'
        with self.assertRaisesRegex(RuntimeError, 'XHTTP_ROLES'):
            self.configs()

    def test_unit_uses_root_credentials_and_pinned_public_binary(self):
        raw = module.unit_bytes(module.WARP_CONF).decode()
        self.assertIn('LoadCredential=config.json:' + str(module.WARP_CONF), raw)
        self.assertIn('User=xhttp-test\n', raw)
        self.assertIn('Environment=GODEBUG=multipathtcp=0\n', raw)
        self.assertNotIn('SupplementaryGroups=xui', raw)
        self.assertIn('NoNewPrivileges=true', raw)
        self.assertIn('ProtectSystem=strict', raw)

    def test_marker_requires_commit_and_detects_drift(self):
        direct, warp, main = b'{"a":1}', b'{"b":2}', b'{"z":1,"a":2}'
        marker = {'version': 2, 'target': self.target['TARGET_IPV4'],
                  'operation_id': 'a' * 32, 'status': 'pending',
                  'direct_config_sha256': module.sha(direct),
                  'warp_config_sha256': module.sha(warp),
                  'main_runtime_sha256': module.sha(module.canonical(json.loads(main)))}
        with self.assertRaisesRegex(RuntimeError, 'MARKER_SHAPE'):
            module.validate_marker(marker, self.target, direct, warp, main)
        module.validate_marker(marker, self.target, direct, warp, main, allow_pending=True)
        marker['status'] = 'committed'
        module.validate_marker(marker, self.target, direct, warp, b'{ "a": 2, "z":1 }')
        with self.assertRaisesRegex(RuntimeError, 'MARKER_CONFIG_HASH'):
            module.validate_marker(marker, self.target, direct, warp + b' ', main)
        marker['foreign'] = True
        with self.assertRaisesRegex(RuntimeError, 'MARKER_SHAPE'):
            module.validate_marker(marker, self.target, direct, warp, main)

    def test_sql_apply_inverse_and_foreign_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.db'
            db = sqlite3.connect(path)
            db.executescript('CREATE TABLE inbounds(id INTEGER PRIMARY KEY,port INTEGER,enable INTEGER);'
                             'CREATE TABLE client_external_links(id INTEGER PRIMARY KEY,client_id INTEGER,kind TEXT,value TEXT,remark TEXT,enable INTEGER,sort_index INTEGER);'
                             "INSERT INTO inbounds VALUES(1,8443,1);"
                             "INSERT INTO client_external_links VALUES(1,1,'link','r','R',1,0);"
                             "INSERT INTO client_external_links VALUES(2,1,'link','h','H',1,1);"
                             "INSERT INTO client_external_links VALUES(3,1,'link','old-x','X',1,2);")
            db.commit()
            def rows():
                cols = [r[1] for r in db.execute('PRAGMA table_info(client_external_links)')]
                return [dict(zip(cols, r)) for r in db.execute('SELECT * FROM client_external_links ORDER BY sort_index,id')]
            before = rows()
            draft = {'client_id': 1, 'kind': 'link', 'value': 'cf-x', 'remark': 'CF X', 'enable': 1, 'sort_index': -1}
            payload = {'db': path.as_posix(), 'action': 'apply', 'expected_rows': before,
                       'expected_enable': 1, 'wanted_enable': 0, 'inbound': 1, 'direct_id': 3,
                       'direct_uri': 'new-x', 'direct_label': 'X', 'cf_row': draft}
            result = subprocess.run([sys.executable, '-c', module.SQL_CHILD], input=json.dumps(payload).encode(), capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            after = rows()
            self.assertEqual([r['sort_index'] for r in after], [-1, 0, 1, 2])
            self.assertEqual(db.execute('SELECT enable FROM inbounds').fetchone(), (0,))
            # A repeated request with an unknown previous reply cannot mutate again.
            repeat = subprocess.run([sys.executable, '-c', module.SQL_CHILD], input=json.dumps(payload).encode(), capture_output=True)
            self.assertNotEqual(repeat.returncode, 0)
            self.assertEqual(rows(), after)
            inverse = {'db': path.as_posix(), 'action': 'rollback', 'expected_rows': after,
                       'expected_enable': 0, 'wanted_enable': 1, 'inbound': 1,
                       'cf_id': after[0]['id'], 'old_direct': before[2]}
            result = subprocess.run([sys.executable, '-c', module.SQL_CHILD], input=json.dumps(inverse).encode(), capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(rows(), before)
            self.assertEqual(db.execute('SELECT enable FROM inbounds').fetchone(), (1,))
            db.execute("UPDATE client_external_links SET remark='foreign' WHERE id=1")
            db.commit()
            drift = subprocess.run([sys.executable, '-c', module.SQL_CHILD], input=json.dumps(payload).encode(), capture_output=True)
            self.assertNotEqual(drift.returncode, 0)
            self.assertEqual(db.execute('SELECT enable FROM inbounds').fetchone(), (1,))
            db.close()


if __name__ == '__main__':
    unittest.main()
