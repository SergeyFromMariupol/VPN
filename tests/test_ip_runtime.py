import base64
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, quote_plus, urlsplit


BUNDLE = Path(__file__).resolve().parents[1] / 'bundle'
sys.path.insert(0, str(BUNDLE / 'base'))
import ip_runtime as runtime

OLD = '8.8.4.4'
NEW = '9.9.9.9'
ALIAS = '1.0.0.1'
SNI = 'example.com'


def test_config(address):
    return {
        'inbounds': [{
            'listen': address, 'port': 8443,
            'streamSettings': {
                'xhttpSettings': {'host': address, 'path': '/' + OLD},
                'realitySettings': {'target': SNI + ':443', 'serverNames': [SNI]},
            },
        }],
        'outbounds': [{
            'tag': 'DIRECT', 'protocol': 'freedom',
            'settings': {'finalRules': [{'action': 'block',
                                         'ip': ['geoip:private', '::/0']},
                                        {'action': 'allow'}]},
        }],
        'routing': {'rules': [
            {'outboundTag': 'BLOCK', 'ip': ['geoip:private', '::/0', address + '/32']},
            {'outboundTag': 'BLOCK', 'domain': ['full:' + address]},
            {'outboundTag': 'DIRECT', 'user': ['owner-' + OLD]},
        ]},
    }


def share_uri(address):
    return (f'vless://example%40password@{address}:8443?security=reality'
            f'&type=xhttp&host={address}&sni={SNI}&path=%2F{OLD}#test%20{OLD}')


class RewriteTest(unittest.TestCase):
    def test_migration_preserves_reality_sni_and_opaque_fields(self):
        original = share_uri(OLD)
        migrated = runtime.rewrite_uri(original, OLD, NEW)
        self.assertEqual(migrated, share_uri(NEW))
        self.assertEqual(runtime.rewrite_uri(migrated, NEW, OLD), original)

    def test_alias_rewrites_only_destination(self):
        result = runtime.rewrite_uri(share_uri(OLD), OLD, ALIAS, endpoint_only=True)
        parsed = urlsplit(result)
        self.assertEqual(parsed.hostname, ALIAS)
        self.assertEqual(parse_qs(parsed.query)['host'], [OLD])
        self.assertEqual(parse_qs(parsed.query)['sni'], [SNI])

    def test_tls_authority_and_encoded_xhttp_extra(self):
        extra = {'headers': {'Host': OLD + ':8443'}, 'path': '/' + OLD}
        old = ('hysteria2://pass@' + OLD + ':443?sni=' + OLD + '&extra=' +
               quote_plus(runtime.canonical(extra).decode()))
        parsed = parse_qs(urlsplit(runtime.rewrite_uri(old, OLD, NEW)).query)
        self.assertEqual(parsed['sni'], [NEW])
        self.assertEqual(json.loads(parsed['extra'][0]), {
            'headers': {'Host': NEW + ':8443'}, 'path': '/' + OLD})

    def test_vmess_and_external_endpoint(self):
        payload = {'add': OLD, 'ps': OLD, 'sni': OLD, 'host': OLD, 'id': 'fixture'}
        link = 'vmess://' + base64.b64encode(runtime.canonical(payload)).decode()
        changed = runtime.vmess(runtime.rewrite_uri(link, OLD, NEW))
        self.assertEqual(changed, dict(payload, add=NEW, sni=NEW, host=NEW))
        unchanged = runtime.vmess(runtime.rewrite_uri(link, OLD, NEW, endpoint_only=True))
        self.assertEqual(unchanged, dict(payload, add=NEW))
        foreign = share_uri('2.2.2.2')
        self.assertEqual(runtime.rewrite_uri(foreign, OLD, NEW), foreign)

    def test_private_guards_remove_only_previous_managed_aliases(self):
        config = test_config(OLD)
        config['routing']['rules'][0]['ip'] += [ALIAS + '/32', '4.4.4.4/32']
        updated = runtime.rewrite_xray(config, OLD, NEW, [OLD, ALIAS], [NEW])
        self.assertEqual(updated['routing']['rules'][0]['ip'],
                         ['geoip:private', '::/0', '4.4.4.4/32', NEW + '/32'])
        self.assertEqual(updated['inbounds'][0]['streamSettings']['xhttpSettings'],
                         {'host': NEW, 'path': '/' + OLD})


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory()
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name).resolve()
        self.db = self.root / runtime.DB
        self.db.parent.mkdir(parents=True)
        self.config = runtime.canonical(test_config(OLD))
        self.populate_database()
        self.write(runtime.MAIN, self.config)
        self.write(runtime.DIRECT, self.config)
        self.write(runtime.DIRECT_BASELINE, runtime.canonical({'links': [share_uri(OLD)]}))
        self.write_promotion(3, direct_config_sha256=runtime.sha(self.config),
                             baseline_sha256=runtime.sha(self.read(runtime.DIRECT_BASELINE)))

    def populate_database(self):
        with closing(sqlite3.connect(self.db)) as database:
            database.executescript('''
                CREATE TABLE settings(id INTEGER PRIMARY KEY, key TEXT, value TEXT);
                CREATE TABLE inbounds(id INTEGER PRIMARY KEY, listen TEXT, share_addr TEXT,
                                      stream_settings TEXT, node_id INTEGER, port INTEGER);
                CREATE TABLE hosts(id INTEGER PRIMARY KEY, inbound_id INTEGER, address TEXT,
                                   sni TEXT, host_header TEXT, verify_peer_cert_by_name TEXT);
                CREATE TABLE client_external_links(id INTEGER PRIMARY KEY, kind TEXT, value TEXT);
            ''')
            settings = {'subListen': OLD, 'subDomain': OLD, 'subURI': f'https://{OLD}:2096',
                        'xrayTemplateConfig': self.config.decode()}
            database.executemany('INSERT INTO settings(key, value) VALUES (?, ?)',
                                 settings.items())
            for port, sni in ((443, OLD), (443, SNI), (8443, SNI)):
                stream = json.dumps({'xhttpSettings': {'host': OLD, 'path': '/' + OLD}})
                inbound_id = database.execute(
                    'INSERT INTO inbounds(listen, share_addr, stream_settings, port) '
                    'VALUES (?, ?, ?, ?)', (OLD, OLD, stream, port)).lastrowid
                database.execute('INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?)',
                                 (inbound_id, inbound_id, OLD, sni, OLD, ''))
            database.execute('INSERT INTO client_external_links VALUES (1, ?, ?)',
                             ('link', share_uri(OLD)))
            database.execute('INSERT INTO client_external_links VALUES (2, ?, ?)',
                             ('subscription', f'https://{OLD}:2096/remote'))
            database.commit()

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def read(self, relative):
        return (self.root / relative).read_bytes()

    def write_promotion(self, version, **fields):
        marker = {'target': OLD, 'status': 'committed', 'version': version,
                  'main_runtime_sha256': runtime.sha(self.config), **fields}
        self.write(runtime.PROMOTION, runtime.canonical(marker))

    def plan(self, **kwargs):
        return runtime.plan_runtime(self.root, OLD, NEW, [NEW, ALIAS],
                                    'ens3', 'ens3', **kwargs)

    def test_plans_without_mutation_and_replays_database_transaction(self):
        plan = self.plan()
        self.assertEqual(self.read(runtime.MAIN), self.config)
        self.assertEqual(json.loads(plan.main_config)['inbounds'][0]['listen'], NEW)
        self.assertEqual(json.loads(plan.files[self.root / runtime.DIRECT_BASELINE])['links'],
                         [share_uri(NEW)])
        files = plan.final_files(plan.main_config, [share_uri(NEW)])
        self.assertEqual(json.loads(files[self.root / runtime.PROMOTION])['target'], NEW)
        with closing(sqlite3.connect(self.db)) as database:
            database.execute('BEGIN IMMEDIATE')
            plan.apply_database(database)
            self.assertEqual(database.execute('SELECT value FROM client_external_links WHERE id=1')
                             .fetchone(), (share_uri(NEW),))
            self.assertEqual(database.execute('SELECT value FROM client_external_links WHERE id=2')
                             .fetchone(), (f'https://{OLD}:2096/remote',))
            self.assertEqual(database.execute('SELECT DISTINCT listen FROM inbounds').fetchall(),
                             [(NEW,)])
            plan.restore_database(database)
            plan.restore_database(database)
            self.assertEqual(database.execute('SELECT DISTINCT listen FROM inbounds').fetchall(),
                             [(OLD,)])
            database.rollback()

    def test_readback_rejects_foreign_runtime_and_database(self):
        plan = self.plan()
        with self.assertRaisesRegex(ValueError, 'IP_MAIN_RUNTIME_READBACK'):
            plan.final_files(self.config, [share_uri(NEW)])
        with closing(sqlite3.connect(self.db)) as database:
            database.execute('BEGIN IMMEDIATE')
            database.execute("UPDATE settings SET value='foreign' WHERE key='subDomain'")
            with self.assertRaisesRegex(ValueError, 'IP_DB_CAS'):
                plan.apply_database(database)
            database.rollback()

    def test_warp_recovery_without_old_run_config(self):
        self.write_promotion(2, direct_config_sha256=runtime.sha(self.config),
                             warp_config_sha256=runtime.sha(self.config))
        self.write(runtime.WARP, self.config)
        self.write(runtime.WARP_ENV, (
            f'NL_PUBLIC_IPV4={OLD}\n'
            'WARP_EGRESS_NL_CLIENT_ID=00000000-0000-0000-0000-000000000001\n'
            'WARP_EGRESS_BRIDGE_CLIENT_ID=00000000-0000-0000-0000-000000000002\n'
        ).encode())
        common = (BUNDLE / 'warp-egress/scripts/common.sh').read_bytes().replace(
            b'@TARGET_IPV4@', OLD.encode())
        self.write(runtime.WARP_COMMON, common)
        template = BUNDLE / 'warp-egress/config/xray-warp-egress.template.json'
        self.write(runtime.WARP_TEMPLATE, template.read_bytes())
        self.assertFalse((self.root / runtime.WARP_RUNTIME).exists())
        plan = self.plan()
        self.assertIn(f'NL_PUBLIC_IPV4={NEW}\n'.encode(),
                      plan.files[self.root / runtime.WARP_ENV])
        self.assertIn(f'$NL_PUBLIC_IPV4" == {NEW} ]]'.encode(),
                      plan.files[self.root / runtime.WARP_COMMON])
        config = json.loads(plan.xray_configs[self.root / runtime.WARP_RUNTIME])
        self.assertEqual(config['routing']['rules'][0]['ip'],
                         ['geoip:private', NEW + '/32', ALIAS + '/32'])
        self.assertNotIn(self.root / runtime.WARP_RUNTIME, plan.files)

    def test_portfolio_receipts_are_rebound_after_exact_feed_readback(self):
        self.write(runtime.PORTFOLIO, self.config)
        manifest = {'version': 1, 'target': OLD, 'entries': [{'uri': share_uri(OLD)}]}
        self.write(runtime.PORTFOLIO_LINKS, runtime.canonical(manifest))
        hook = f'#!/bin/bash\nlineage=/etc/letsencrypt/live/{OLD}\n'.encode()
        self.write(runtime.PORTFOLIO_HOOK, hook)
        self.write(runtime.PORTFOLIO_STATE, runtime.canonical({
            'target': OLD, 'phase': 'committed', 'config_sha256': runtime.sha(self.config),
            'links_sha256': runtime.sha(runtime.canonical(manifest)),
            'hook_sha256': runtime.sha(hook),
        }))
        row = {'kind': 'link', 'value': share_uri(OLD)}
        old_hash = runtime.sha(runtime.canonical(runtime.signature(share_uri(OLD))))
        self.write(runtime.PUBLICATION, runtime.canonical({
            'target': OLD, 'status': 'committed', 'before': {'external': [row]},
            'after': {'external': [row]}, 'insert_external': [row],
            'uri_hashes': [old_hash], 'manifest_sha256': runtime.sha(runtime.canonical(manifest)),
        }))
        plan = self.plan(lineage='/etc/letsencrypt/live/vpn-v4-rotation')
        with self.assertRaisesRegex(ValueError, 'IP_PUBLICATION_URI_DRIFT'):
            plan.final_files(plan.main_config, [share_uri(NEW).replace('password', 'modified')])
        final = plan.final_files(plan.main_config, [share_uri(NEW)])
        publication = json.loads(final[self.root / runtime.PUBLICATION])
        self.assertEqual(publication['after']['external'][0]['value'], share_uri(NEW))
        self.assertNotEqual(publication['uri_hashes'], [old_hash])
        self.assertIn(b'lineage=/etc/letsencrypt/live/vpn-v4-rotation\n',
                      plan.files[self.root / runtime.PORTFOLIO_HOOK])


if __name__ == '__main__':
    unittest.main()
