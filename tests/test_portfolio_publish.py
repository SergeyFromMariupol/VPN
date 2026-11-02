"""Offline subscription selection and SQLite CAS transaction fixtures."""
import importlib.util
import base64
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
SPEC = importlib.util.spec_from_file_location('portfolio_publish', ROOT / 'tools/portfolio_publish.py')
PUBLISH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISH)


def fixture(certless=False, egress='both'):
    protocols = ('REALITY', 'XHTTP') if certless else ('REALITY', 'HYSTERIA2', 'XHTTP')
    target = {'TARGET_TLS_MODE': 'none' if certless else 'letsencrypt',
              'TARGET_EGRESS_MODE': egress, 'TARGET_PROFILE_SET': 'basic',
              'TARGET_LABEL': 'Personal VPN'}
    emails = ([f'germany-{item.lower()}' for item in protocols] if egress == 'direct' else
              [f'germany-warp-{item.lower()}' for item in protocols] +
              [f'germany-{item.lower()}' for item in protocols])
    clients = [{'id': index + 1, 'email': email} for index, email in enumerate(emails)]
    joins = [{'client_id': index + 1, 'inbound_id': index % len(protocols) + 1,
              'flow_override': '', 'created_at': 1000 + index}
             for index in range(len(emails))]
    external_profiles = ([('🖥️ IP сервера', 'XHTTP')] if egress == 'direct' else
                         [('☁️ Cloudflare', 'XHTTP')] +
                         [('🖥️ IP сервера', protocol) for protocol in protocols])
    external = [{'id': index + 1, 'client_id': 1, 'kind': 'link',
                 'value': f'vless://fixture@vpn.example.com:{8443 + index}#{index}',
                 'remark': target['TARGET_LABEL'] + ' · ' + row_egress + ' · ' + protocol,
                 'enable': 1, 'expiry_time': 0, 'name_prefix': '',
                 'sort_index': index if egress == 'direct' else index - 1,
                 'created_at': index + 1000}
                for index, (row_egress, protocol) in enumerate(external_profiles)]
    names = PUBLISH.baseline_names(target)
    initial = [f'vless://fixture@vpn.example.com:{443 + index}#{name}'
               for index, name in enumerate(names)]
    return target, {'clients': clients, 'joins': joins, 'external': external}, initial


def create_db(path, data):
    with closing(sqlite3.connect(path)) as db:
        db.executescript('''
CREATE TABLE clients(id INTEGER PRIMARY KEY,email TEXT NOT NULL);
CREATE TABLE client_inbounds(client_id INTEGER NOT NULL,inbound_id INTEGER NOT NULL,
 flow_override TEXT NOT NULL,created_at INTEGER NOT NULL,
 PRIMARY KEY(client_id,inbound_id));
CREATE TABLE client_external_links(
 id INTEGER PRIMARY KEY,client_id INTEGER NOT NULL,kind TEXT NOT NULL,
 value TEXT NOT NULL,remark TEXT NOT NULL,enable INTEGER NOT NULL,
 expiry_time INTEGER NOT NULL,name_prefix TEXT NOT NULL,
 last_fetch_at INTEGER NOT NULL,last_fetch_error TEXT NOT NULL,
 sort_index INTEGER NOT NULL,created_at INTEGER NOT NULL);
''')
        db.executemany('INSERT INTO clients(id,email) VALUES (:id,:email)', data['clients'])
        db.executemany('INSERT INTO client_inbounds(client_id,inbound_id,flow_override,created_at) '
                       'VALUES (:client_id,:inbound_id,:flow_override,:created_at)', data['joins'])
        for row in data['external']:
            db.execute('INSERT INTO client_external_links VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                       (row['id'], row['client_id'], row['kind'], row['value'], row['remark'],
                        row['enable'], row['expiry_time'], row['name_prefix'], 0, '',
                        row['sort_index'], row['created_at']))
        db.commit()


def worker(path, op, payload=None):
    code = PUBLISH.WORKER.replace("DB='/etc/x-ui/x-ui.db'", 'DB=' + repr(str(path)))
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code, op],
                            input=None if payload is None else PUBLISH.canonical(payload),
                            capture_output=True)
    return result


class PortfolioPublication(unittest.TestCase):
    def test_native_runtime_removes_unselected_egress(self):
        target, _, _ = fixture()
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / 'config.json'
            config = {'inbounds': [
                {'tag': 'in-443-tcp', 'settings': {'clients': [
                    {'email': 'germany-warp-reality'}]}},
                {'tag': 'in-443-udp', 'settings': {'clients': [
                    {'email': 'germany-warp-hysteria2'}]}}]}
            runtime.write_text(json.dumps(config))
            target['TARGET_EGRESS_MODE'] = 'warp'
            with patch.object(PUBLISH, 'XRAY_RUNTIME', runtime):
                PUBLISH.verify_native_runtime(target)
                config['inbounds'][0]['settings']['clients'].append(
                    {'email': 'germany-reality'})
                runtime.write_text(json.dumps(config))
                with self.assertRaisesRegex(RuntimeError, 'RUNTIME_CLIENTS'):
                    PUBLISH.verify_native_runtime(target)
                certless, _, _ = fixture(certless=True)
                certless['TARGET_EGRESS_MODE'] = 'direct'
                runtime.write_text(json.dumps({'inbounds': [
                    {'tag': 'in-443-tcp', 'settings': {'clients': [
                        {'email': 'germany-reality'}]}}]}))
                PUBLISH.verify_native_runtime(certless)

    def test_public_feed_retries_transient_backend_error_only(self):
        with patch.object(PUBLISH, 'feed_one', side_effect=[
                RuntimeError('PUBLIC_TRANSIENT_HTTP'), ['one'], ['one'], ['one']]) as fetch, \
                patch.object(PUBLISH.time, 'sleep'):
            self.assertEqual(PUBLISH.feeds(None, ready_timeout=2), ['one'])
            self.assertEqual(fetch.call_count, 4)
        with patch.object(PUBLISH, 'feed_one', side_effect=RuntimeError('PUBLIC_HTTP')) as fetch:
            with self.assertRaisesRegex(RuntimeError, 'PUBLIC_HTTP'):
                PUBLISH.feeds(None, ready_timeout=2)
            self.assertEqual(fetch.call_count, 1)

    def test_expanded_manifest_matches_catalog_and_selected_egress(self):
        target = {'TARGET_TLS_MODE': 'letsencrypt', 'TARGET_EGRESS_MODE': 'direct',
                  'TARGET_PROFILE_SET': 'dpi', 'TARGET_LABEL': 'Personal VPN',
                  'TARGET_IPV4': '8.8.4.4', 'TARGET_FQDN': 'vpn.example.com'}
        selected = PUBLISH.selected_recipe(target)
        self.assertEqual(len(selected), 46)
        entries = []
        for row in selected:
            port = 30000 + row['port_offset']
            if row['protocol'] == 'vmess':
                raw = json.dumps({'add': target['TARGET_FQDN'], 'port': str(port),
                                  'ps': row['name']}, ensure_ascii=False).encode()
                uri = 'vmess://' + base64.b64encode(raw).decode()
            else:
                uri = (row['protocol'] + '://fixture@' + target['TARGET_FQDN'] + ':' +
                       str(port) + '#' + quote(row['name'], safe=''))
            entries.append({'id': row['id'], 'remark': row['name'], 'uri': uri,
                            'port': port, 'egress': 'DIRECT'})
        raw = PUBLISH.canonical({'version': 1, 'target': target['TARGET_IPV4'],
                                 'entries': entries})
        with patch.object(PUBLISH, 'private_dir'), patch.object(PUBLISH, 'private', return_value=raw):
            actual, sha = PUBLISH.read_extras(target, selected)
            self.assertEqual(actual, entries)
            self.assertEqual(sha, PUBLISH.digest(raw))
            entries[0]['remark'] = 'wrong'
            invalid = PUBLISH.canonical({'version': 1, 'target': target['TARGET_IPV4'],
                                         'entries': entries})
            with patch.object(PUBLISH, 'private', return_value=invalid):
                with self.assertRaises(RuntimeError):
                    PUBLISH.read_extras(target, selected)

    def test_3xui_remark_reencoding_does_not_change_uri_identity(self):
        first = 'vless://fixture@vpn.example.com:30000?type=grpc#Personal%20VPN'
        renamed = 'vless://fixture@vpn.example.com:30000?type=grpc#Personal VPN'
        changed = 'vless://fixture@vpn.example.com:30001?type=grpc#Personal VPN'
        self.assertEqual(PUBLISH.uri_signature(first), PUBLISH.uri_signature(renamed))
        self.assertNotEqual(PUBLISH.uri_signature(first), PUBLISH.uri_signature(changed))
        vmess = {'add': 'vpn.example.com', 'port': '30000', 'ps': 'Personal VPN',
                 'id': 'fixture'}
        vmess_one = 'vmess://' + base64.b64encode(json.dumps(vmess).encode()).decode()
        vmess_two = 'vmess://' + base64.urlsafe_b64encode(
            json.dumps(vmess, sort_keys=True, separators=(',', ':')).encode()).decode().rstrip('=')
        self.assertEqual(PUBLISH.uri_signature(vmess_one), PUBLISH.uri_signature(vmess_two))

    def test_baseline_egress_filter_and_owner_retention(self):
        for certless in (False, True):
            for egress in ('warp', 'direct', 'both'):
                with self.subTest(certless=certless, egress=egress):
                    target, data, initial = fixture(certless, egress)
                    result = PUBLISH.plan(data, target, [], initial)
                    count = 2 if certless else 3
                    expected = count * (2 if egress == 'both' else 1)
                    self.assertEqual(len(result['uri_hashes']), expected)
                    self.assertEqual(len(result['names']), expected)
                    self.assertEqual(len(result['after']['joins']), count if egress != 'both' else count * 2)
                    self.assertEqual(len(result['after']['external']),
                                     count + 1 if egress == 'both' else 1)
                    self.assertEqual(len(result['delete_joins']), count if egress == 'warp' else 0)
                    self.assertEqual(len(result['delete_external']), count if egress == 'warp' else 0)
                    self.assertIn(1, [row['id'] for row in data['clients']])

    def test_append_order_and_cas_restore(self):
        target, data, initial = fixture(egress='direct')
        extras = [{'id': 'trial-one', 'remark': 'Personal VPN · IP · Variant One',
                   'uri': 'vless://fixture@vpn.example.com:30000#VariantOne'},
                  {'id': 'trial-two', 'remark': 'Personal VPN · IP · Variant Two',
                   'uri': 'vless://fixture@vpn.example.com:30001#VariantTwo'}]
        plan = PUBLISH.plan(data, target, extras, initial)
        self.assertEqual([row['sort_index'] for row in plan['insert_external']], [3, 4])
        self.assertEqual(len(plan['after']['external']), 3)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'x-ui.db'
            create_db(path, data)
            payload = {'expected': plan['before'], 'intended': plan['after'],
                       'delete_joins': plan['delete_joins'],
                       'delete_external': plan['delete_external'],
                       'insert_external': plan['insert_external']}
            bad = dict(payload, expected={'joins': [], 'external': []})
            self.assertNotEqual(worker(path, 'apply', bad).returncode, 0)
            before = worker(path, 'read')
            self.assertEqual(before.returncode, 0, before.stderr.decode())
            self.assertEqual(json.loads(before.stdout)['external'], data['external'])
            applied = worker(path, 'apply', payload)
            self.assertEqual(applied.returncode, 0, applied.stderr.decode())
            self.assertEqual(json.loads(worker(path, 'read').stdout)['external'], plan['after']['external'])
            removed_joins = plan['delete_joins']
            removed_ext_ids = set(plan['delete_external'])
            # Original rows are the exact backup image in this fixture.
            restore_joins = [row for row in data['joins']
                             if {'client_id': row['client_id'], 'inbound_id': row['inbound_id']}
                             in removed_joins]
            restore_ext = [{**row, 'last_fetch_at': 0, 'last_fetch_error': ''}
                           for row in data['external'] if row['id'] in removed_ext_ids]
            restored = worker(path, 'restore', {
                'expected': plan['after'], 'intended': plan['before'],
                'inserted_external_ids': [row['id'] for row in plan['insert_external']],
                'restore_joins': restore_joins, 'restore_external': restore_ext})
            self.assertEqual(restored.returncode, 0, restored.stderr.decode())
            self.assertEqual(json.loads(worker(path, 'read').stdout)['external'], data['external'])
            self.assertEqual(json.loads(worker(path, 'read').stdout)['joins'], data['joins'])

    def test_direct_only_expanded_counts_keep_one_subscription_owner(self):
        for profile_set, expected in (('dpi', 49), ('all', 73)):
            with self.subTest(profile_set=profile_set):
                target, data, initial = fixture(egress='direct')
                target['TARGET_PROFILE_SET'] = profile_set
                extras = [
                    {'id': row['id'], 'remark': row['name'],
                     'uri': ('vless://fixture@vpn.example.com:' +
                             str(30000 + row['port_offset']) + '#' +
                             quote(row['name'], safe=''))}
                    for row in PUBLISH.selected_recipe(target)]
                intended = PUBLISH.plan(data, target, extras, initial)
                self.assertEqual(len(intended['names']), expected)
                self.assertEqual(intended['names'][:len(initial)],
                                 PUBLISH.baseline_names(target))
                self.assertFalse(intended['delete_joins'])
                self.assertFalse(intended['delete_external'])
                self.assertEqual(len(intended['after']['external']), 1 + len(extras))
                self.assertEqual({row['client_id'] for row in intended['after']['external']},
                                 {data['clients'][0]['id']})


if __name__ == '__main__':
    unittest.main()
