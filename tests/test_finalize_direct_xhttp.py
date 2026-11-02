"""Offline direct-only promotion contracts; no VPS, UFW or network calls."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import closing
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'finalize_direct_xhttp', ROOT / 'bundle/scripts/finalize-direct-xhttp.py')
MODULE = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {'pwd': sys.modules.get('pwd', types.ModuleType('pwd'))}):
    SPEC.loader.exec_module(MODULE)

TARGET = {
    'TARGET_TLS_MODE': 'letsencrypt', 'TARGET_EGRESS_MODE': 'direct',
    'TARGET_LABEL': 'Personal VPN', 'TARGET_ADDRESS_MODE': 'domain',
    'TARGET_FQDN': 'vpn.example.com', 'TARGET_IPV4': '45.67.89.10',
    'TARGET_REALITY_SNI': 'example.org', 'TARGET_INTERFACE': 'ens3',
}
SECRET = {
    'SUBSCRIPTION_ID': 'a' * 64, 'VLESS_UUID': '11111111-2222-3333-4444-555555555555',
    'HYSTERIA2_AUTH': 'z' * 48,
}


def baseline(certless=False):
    target = dict(TARGET, TARGET_TLS_MODE='none' if certless else 'letsencrypt')
    protocols = ('REALITY', 'XHTTP') if certless else ('REALITY', 'HYSTERIA2', 'XHTTP')
    clients = []
    joins = []
    inbounds = []
    for ident, protocol in enumerate(protocols, 1):
        clients.append({
            'id': ident, 'email': 'germany-' + protocol.lower(),
            'sub_id': SECRET['SUBSCRIPTION_ID'],
            'comment': MODULE.names(target)[ident - 1],
            'uuid': SECRET['VLESS_UUID'] if protocol != 'HYSTERIA2' else '',
            'auth': SECRET['HYSTERIA2_AUTH'] if protocol == 'HYSTERIA2' else '',
            'enable': 1,
        })
        inbounds.append({'id': ident, 'port': 8443 if protocol == 'XHTTP' else 443,
                         'enable': 1, 'sub_sort_index': ident})
        joins.append({'client_id': ident, 'inbound_id': ident, 'flow_override': ''})
    return target, {'clients': clients, 'joins': joins, 'inbounds': inbounds,
                    'external': []}


class DirectPromotionTests(unittest.TestCase):
    def test_baseline_db_accepts_direct_two_and_three_only(self):
        for certless in (False, True):
            with self.subTest(certless=certless):
                target, db = baseline(certless)
                old, owner = MODULE.baseline_db(db, target, SECRET)
                self.assertEqual(old['port'], 8443)
                self.assertEqual(owner['email'], 'germany-reality')
                db['external'].append({'kind': 'link'})
                with self.assertRaisesRegex(RuntimeError, 'BASELINE_INBOUNDS'):
                    MODULE.baseline_db(db, target, SECRET)

    def test_direct_config_is_singleton_with_no_warp_outbound(self):
        main = {
            'dns': {'servers': [{'tag': 'dns_cf', 'address': '1.1.1.1'}]},
            'inbounds': [{'port': 8443, 'settings': {'clients': [
                {'id': SECRET['VLESS_UUID'], 'email': 'germany-xhttp', 'flow': ''}
            ]}}],
            'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom'},
                          {'tag': 'BLOCK', 'protocol': 'blackhole'}],
        }
        config = MODULE.build_direct(main, TARGET, 'p' * 43, 'abcdef0123456789', '/private')
        self.assertEqual(config['inbounds'][0]['port'], 8444)
        self.assertEqual(config['inbounds'][0]['streamSettings']['network'], 'xhttp')
        self.assertEqual(config['inbounds'][0]['streamSettings']['security'], 'reality')
        self.assertEqual([out['tag'] for out in config['outbounds']], ['DIRECT', 'BLOCK'])
        self.assertEqual(config['routing']['rules'][-1]['outboundTag'], 'BLOCK')
        main['outbounds'].append({'tag': 'WARP_CF', 'protocol': 'vless'})
        with self.assertRaisesRegex(RuntimeError, 'DIRECT_ONLY_OUTBOUNDS'):
            MODULE.build_direct(main, TARGET, 'p' * 43, 'abcdef0123456789', '/private')

    def test_firewall_requires_owned_transition(self):
        old = "ufw allow 8443/tcp comment 'VLESS XHTTP TLS H2'\n"
        new = ("ufw allow in on ens3 to 45.67.89.10 port 8444 "
               "proto tcp comment 'vpn-xhttp-direct'\n")
        with patch.object(MODULE.x, 'run', return_value=types.SimpleNamespace(stdout=old.encode())):
            MODULE.firewall(TARGET, promoted=False)
            with self.assertRaisesRegex(RuntimeError, 'PROMOTED_UFW'):
                MODULE.firewall(TARGET, promoted=True)
        with patch.object(MODULE.x, 'run', return_value=types.SimpleNamespace(stdout=new.encode())):
            MODULE.firewall(TARGET, promoted=True)

    def test_sql_cas_apply_and_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'x-ui.db'
            with closing(sqlite3.connect(path)) as db, db:
                db.executescript('''
CREATE TABLE inbounds(id INTEGER PRIMARY KEY,port INTEGER,enable INTEGER,
 sub_sort_index INTEGER);
CREATE TABLE clients(id INTEGER PRIMARY KEY,email TEXT,sub_id TEXT,comment TEXT,
 uuid TEXT,auth TEXT,enable INTEGER);
CREATE TABLE client_inbounds(client_id INTEGER,inbound_id INTEGER,flow_override TEXT);
CREATE TABLE client_external_links(id INTEGER PRIMARY KEY,client_id INTEGER,kind TEXT,
 value TEXT,remark TEXT,enable INTEGER,expiry_time INTEGER,name_prefix TEXT,
 sort_index INTEGER,created_at INTEGER,last_fetch_at INTEGER,last_fetch_error TEXT);
INSERT INTO inbounds VALUES(1,443,1,1);
INSERT INTO inbounds VALUES(2,8443,1,2);
INSERT INTO clients VALUES(1,'germany-reality','sub','REALITY','uuid','',1);
INSERT INTO clients VALUES(2,'germany-xhttp','sub','XHTTP','uuid','',1);
INSERT INTO client_inbounds VALUES(1,1,'');
INSERT INTO client_inbounds VALUES(2,2,'');
''')
            before = [{'id': 1, 'port': 443, 'enable': 1, 'sub_sort_index': 1},
                      {'id': 2, 'port': 8443, 'enable': 1, 'sub_sort_index': 2}]
            clients = [{'id': 1, 'email': 'germany-reality', 'sub_id': 'sub',
                        'comment': 'REALITY', 'uuid': 'uuid', 'auth': '', 'enable': 1},
                       {'id': 2, 'email': 'germany-xhttp', 'sub_id': 'sub',
                        'comment': 'XHTTP', 'uuid': 'uuid', 'auth': '', 'enable': 1}]
            joins = [{'client_id': 1, 'inbound_id': 1, 'flow_override': ''},
                     {'client_id': 2, 'inbound_id': 2, 'flow_override': ''}]
            row = {'client_id': 1, 'kind': 'link', 'value': 'vless://test',
                   'remark': 'Personal VPN · 🖥️ IP сервера · XHTTP', 'enable': 1,
                   'expiry_time': 0, 'name_prefix': '', 'sort_index': 0,
                   'created_at': 1234, 'last_fetch_at': 0, 'last_fetch_error': ''}
            apply = {'db': str(path), 'action': 'apply', 'expected_inbounds': before,
                     'expected_external': [], 'expected_clients': clients,
                     'expected_joins': joins, 'old_id': 2, 'new_row': row}
            result = subprocess.run([sys.executable, '-c', MODULE.SQL_CHILD],
                                    input=json.dumps(apply), text=True,
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT enable FROM inbounds WHERE id=2').fetchone(), (0,))
                new_id = db.execute('SELECT id FROM client_external_links').fetchone()[0]
            result = subprocess.run([sys.executable, '-c', MODULE.SQL_CHILD],
                                    input=json.dumps(apply), text=True,
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            changed = [dict(item, enable=0) if item['id'] == 2 else item for item in before]
            rollback = {'db': str(path), 'action': 'rollback', 'expected_inbounds': changed,
                        'expected_external': [dict(row, id=new_id)],
                        'expected_clients': clients, 'expected_joins': joins,
                        'old_id': 2, 'new_id': new_id}
            result = subprocess.run([sys.executable, '-c', MODULE.SQL_CHILD],
                                    input=json.dumps(rollback), text=True,
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT enable FROM inbounds WHERE id=2').fetchone(), (1,))
                self.assertEqual(db.execute('SELECT count(*) FROM client_external_links').fetchone(), (0,))


if __name__ == '__main__':
    unittest.main()
