"""All-set ordering uses native export visibility without changing tunnel keys."""
import base64
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('priority_publication_fixture',
                                            ROOT / 'tests/test_portfolio_publish.py')
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)
P = FIXTURE.PUBLISH


def fixture(mode='both', profile_set='basic', ids='', certless=False):
    target, data, initial = FIXTURE.fixture(certless, mode)
    target.update(TARGET_PROFILE_ORDER='priority', TARGET_PROFILE_SET=profile_set,
                  TARGET_PROFILE_IDS=ids)
    data['visibility'] = [{'id': 1, 'port': 443, 'protocol': 'vless',
                           'enable': 1, 'exclude_from_sub': 0}]
    if not certless:
        data['visibility'].append({'id': 2, 'port': 443, 'protocol': 'hysteria',
                                   'enable': 1, 'exclude_from_sub': 0})
    data['visibility'].append({'id': 2 if certless else 3, 'port': 8443,
                               'protocol': 'vless', 'enable': 0, 'exclude_from_sub': 0})
    baseline = dict(zip(P.baseline_names(target), initial, strict=True))
    for row in data['external']:
        if row['remark'].endswith('HYSTERIA2'):
            row['value'] = row['value'].replace('vless://', 'hysteria2://')
        baseline[row['remark']] = row['value'].partition('#')[0] + '#' + quote(row['remark'])
    initial = [baseline[name].replace('vless://', 'hysteria2://')
               if name.endswith('HYSTERIA2') else baseline[name]
               for name in P.baseline_names(target)]
    rows = P.priority_rows(target)
    extras = []
    for row in rows:
        if row['baseline_reuse']:
            continue
        port = 30000 + row['port_offset']
        if row['protocol'] == 'vmess':
            uri = 'vmess://' + base64.b64encode(json.dumps({
                'add': 'vpn.example.com', 'port': str(port), 'id': 'fixture',
                'ps': row['name']}).encode()).decode()
        else:
            uri = f"{row['protocol']}://fixture@vpn.example.com:{port}#{quote(row['name'])}"
        extras.append({'id': row['id'], 'remark': row['name'], 'uri': uri})
    return target, data, initial, rows, extras


def create_db(path, data):
    FIXTURE.create_db(path, data)
    with closing(sqlite3.connect(path)) as db:
        db.execute('CREATE TABLE inbounds(id INTEGER PRIMARY KEY, port INTEGER, protocol TEXT, '
                   'enable INTEGER, exclude_from_sub INTEGER, settings TEXT, metadata TEXT)')
        db.executemany('INSERT INTO inbounds VALUES (:id,:port,:protocol,:enable,'
                       ':exclude_from_sub,\'unchanged auth settings\',\'retained metadata\')',
                       data['visibility'])
        db.execute("UPDATE client_external_links SET last_fetch_at=1234,last_fetch_error='keep'")
        db.commit()


def tables(path):
    with closing(sqlite3.connect(path)) as db:
        db.row_factory = sqlite3.Row
        return {name: [dict(row) for row in db.execute('SELECT * FROM ' + name + ' ORDER BY 1,2')]
                for name in ('clients', 'client_inbounds', 'client_external_links', 'inbounds')}


def worker(path, op, payload=None):
    result = FIXTURE.worker(path, op, payload)
    if result.returncode:
        raise RuntimeError('TEST_WORKER: ' + result.stderr.decode())
    return result.stdout


def apply(path, intent):
    return FIXTURE.worker(path, 'apply', {
        **intent, 'expected': intent['before'], 'intended': intent['after'],
        **P.visibility_payload(intent)})


class PriorityPublication(unittest.TestCase):
    def test_public_readback_checks_order_and_native_visibility_for_basic(self):
        target, data, initial, rows, extras = fixture()
        intent = P.plan(data, target, extras, initial)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'x-ui.db'
            create_db(path, data)
            self.assertEqual(apply(path, intent).returncode, 0)
            feed = [row['value'].partition('#')[0] + '#' + quote(row['remark'])
                    for row in intent['after']['external']]
            receipt = {**intent, 'manifest_sha256': None}
            with (patch.object(P, 'db_read', side_effect=lambda: json.loads(worker(path, 'read'))),
                  patch.object(P, 'db_visibility', side_effect=lambda: json.loads(worker(path, 'visibility'))),
                  patch.object(P, 'wait_native_runtime') as runtime,
                  patch.object(P, 'feeds', return_value=feed) as fetch):
                P.verify_public(receipt, target, None)
                runtime.assert_called_once_with(target)
                fetch.return_value = list(reversed(feed))
                with self.assertRaisesRegex(RuntimeError, 'PUBLISHED_FEED'):
                    P.verify_public(receipt, target, None)
                fetch.return_value = feed
                with closing(sqlite3.connect(path)) as db:
                    db.execute('UPDATE inbounds SET exclude_from_sub=0 WHERE id=1')
                    db.commit()
                with self.assertRaisesRegex(RuntimeError, 'PUBLISHED_VISIBILITY'):
                    P.verify_public(receipt, target, None)

    def test_public_verification_failure_rolls_back_through_production_apply(self):
        target, data, initial, _, extras = fixture('both', 'dpi')
        target['TARGET_IPV4'] = '8.8.4.4'
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'x-ui.db'
            create_db(path, data)
            before = tables(path)
            with (patch.object(P, 'state_read', return_value=None),
                  patch.object(P, 'db_read', side_effect=lambda: json.loads(worker(path, 'read'))),
                  patch.object(P, 'db_visibility', side_effect=lambda: json.loads(worker(path, 'visibility'))),
                  patch.object(P, 'db_worker', side_effect=lambda op, payload=None: worker(path, op, payload)),
                  patch.object(P, 'feeds', return_value=initial),
                  patch.object(P, 'read_extras', return_value=(extras, 'fixture-manifest')),
                  patch.object(P, 'snapshot', return_value=(Path(d), 'fixture-snapshot')),
                  patch.object(P, 'backup_rows', return_value=(before['client_inbounds'],
                                                              before['client_external_links'])),
                  patch.object(P, 'restart_xui'), patch.object(P, 'wait_native_runtime'),
                  patch.object(P, 'verify_public', side_effect=RuntimeError('PUBLISHED_FEED')),
                  patch.object(P, 'state_write') as save):
                with self.assertRaisesRegex(RuntimeError, '^PUBLISHED_FEED$'):
                    P.apply(target, None)
                prepared, rolled_back = [call.args[0] for call in save.call_args_list]
                self.assertEqual(prepared['profile_order'], 'priority')
                self.assertEqual(rolled_back['status'], 'rolled_back')
                self.assertTrue(P.state_matches_target(prepared, target))
                self.assertFalse(P.state_matches_target(
                    prepared, {**target, 'TARGET_PROFILE_ORDER': 'legacy'}))
                self.assertEqual(tables(path), before)

    def test_protected_snapshot_validates_native_visibility_baseline(self):
        target, data, initial, _, extras = fixture()
        intent = P.plan(data, target, extras, initial)
        with tempfile.TemporaryDirectory() as d:
            backups = Path(d)
            folder = backups / '20261112T120000Z-0123456789ab'
            folder.mkdir()
            path = folder / 'x-ui.db'
            create_db(path, data)
            receipt = {**intent, 'backup': str(folder),
                       'backup_sha256': P.digest(path.read_bytes())}
            with (patch.object(P, 'BACKUPS', backups), patch.object(P, 'private_dir'),
                  patch.object(P, 'private', side_effect=lambda p: p.read_bytes())):
                joins, external = P.backup_rows(receipt)
                self.assertEqual(joins, data['joins'])
                self.assertEqual(len(external), len(data['external']))
                with closing(sqlite3.connect(path)) as db:
                    db.execute('UPDATE inbounds SET exclude_from_sub=1 WHERE id=1')
                    db.commit()
                receipt['backup_sha256'] = P.digest(path.read_bytes())
                with self.assertRaisesRegex(RuntimeError, 'SNAPSHOT_VISIBILITY'):
                    P.backup_rows(receipt)

    def test_every_preset_and_exit_has_exact_order_without_tunnel_identity_changes(self):
        for profile_set, single_count in (('basic', 3), ('dpi', 49), ('all', 73), ('top10', 10)):
            for mode in ('warp', 'direct', 'both'):
                with self.subTest(profile_set=profile_set, mode=mode), tempfile.TemporaryDirectory() as d:
                    if profile_set == 'top10':
                        chosen = P._CATALOG.select_top10(mode, 'Personal VPN', profile_order='priority')
                        values = fixture(mode, 'custom', ','.join(row['id'] for row in chosen))
                    else:
                        values = fixture(mode, profile_set)
                    target, data, initial, rows, extras = values
                    intent = P.plan(data, target, extras, initial)
                    path = Path(d) / 'x-ui.db'
                    create_db(path, data)
                    original = tables(path)
                    result = apply(path, intent)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    after = tables(path)
                    expected_count = single_count * (2 if mode == 'both' else 1)
                    self.assertEqual(len(intent['names']), expected_count)
                    ordered = sorted(after['client_external_links'], key=lambda row: row['sort_index'])
                    self.assertEqual([row['remark'] for row in ordered], [row['name'] for row in rows])
                    self.assertEqual([row['sort_index'] for row in ordered], list(range(expected_count)))
                    for offset in range(0, expected_count, single_count):
                        self.assertEqual(rows[offset]['protocol'], 'hysteria2')
                        self.assertEqual(rows[offset + 1]['security'], 'reality')
                    self.assertEqual([P.digest(P.canonical(P.uri_signature(
                        row['value'].partition('#')[0] + '#' + quote(row['remark']))))
                        if not row['value'].startswith('vmess://') else
                        P.digest(P.canonical(P.uri_signature(row['value']))) for row in ordered],
                        intent['uri_hashes'])
                    self.assertEqual(after['clients'], original['clients'])
                    for before, current in zip(original['inbounds'], after['inbounds'], strict=True):
                        self.assertEqual(current, {**before,
                            'exclude_from_sub': 1 if before['port'] == 443 else 0})
                    for before in original['client_external_links']:
                        current = next((row for row in ordered if row['id'] == before['id']), None)
                        if current is not None:
                            self.assertEqual(current, {**before, 'sort_index': current['sort_index']})
                    self.assertEqual(after['client_inbounds'], intent['after']['joins'])

    def test_production_recovery_restores_all_tables_and_is_idempotent(self):
        target, data, initial, _, extras = fixture('both', 'all')
        intent = P.plan(data, target, extras, initial)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'x-ui.db'
            create_db(path, data)
            before = tables(path)
            self.assertEqual(apply(path, intent).returncode, 0)
            with (patch.object(P, 'db_read', side_effect=lambda: json.loads(worker(path, 'read'))),
                  patch.object(P, 'db_visibility', side_effect=lambda: json.loads(worker(path, 'visibility'))),
                  patch.object(P, 'db_worker', side_effect=lambda op, payload=None: worker(path, op, payload)),
                  patch.object(P, 'backup_rows', return_value=(before['client_inbounds'],
                                                              before['client_external_links'])),
                  patch.object(P, 'restart_xui'), patch.object(P, 'wait_native_runtime'),
                  patch.object(P, 'state_write') as save):
                P.restore_prepared(intent, target)
                self.assertEqual(tables(path), before)
                self.assertEqual(save.call_args.args[0]['status'], 'rolled_back')
                P.restore_prepared(intent, target)
                self.assertEqual(tables(path), before)

    def test_atomic_visibility_and_sort_cas_failure_and_foreign_drift(self):
        target, data, initial, _, extras = fixture()
        intent = P.plan(data, target, extras, initial)
        for key in ('visibility', 'sort'):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as d:
                path = Path(d) / 'x-ui.db'
                create_db(path, data)
                before = tables(path)
                broken = dict(intent)
                field = 'update_visibility' if key == 'visibility' else 'update_sorts'
                broken[field] = [{**row, 'before': 123} for row in intent[field]]
                self.assertNotEqual(apply(path, broken).returncode, 0)
                self.assertEqual(tables(path), before)
                with closing(sqlite3.connect(path)) as db:
                    db.execute('UPDATE inbounds SET exclude_from_sub=1 WHERE id=1')
                    db.commit()
                drift = tables(path)
                self.assertNotEqual(apply(path, intent).returncode, 0)
                self.assertEqual(tables(path), drift)

    def test_manual_native_only_and_extra_only_and_certificate_free(self):
        cases = [fixture('direct', 'custom', 'hysteria2-tls-hysteria-direct'),
                 fixture('both', 'custom', 'vless-reality-grpc-direct,vless-tls-tcp-warp'),
                 fixture('direct', 'custom', 'vless-tls-tcp-direct')]
        cases.extend(fixture(mode, certless=True) for mode in ('warp', 'direct', 'both'))
        for target, data, initial, rows, extras in cases:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as d:
                intent = P.plan(data, target, extras, initial)
                path = Path(d) / 'x-ui.db'
                create_db(path, data)
                result = apply(path, intent)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(intent['names'], [row['name'] for row in rows])
                self.assertEqual([row['remark'] for row in intent['after']['external']], intent['names'])
                selected_baseline = {row['name'] for row in rows if row['baseline_reuse']}
                by_id = {row['id']: row['email'] for row in data['clients']}
                self.assertEqual({P.baseline_client_names(target)[by_id[row['client_id']]]
                                  for row in intent['after']['joins']}, selected_baseline)
                if target['TARGET_TLS_MODE'] == 'none':
                    self.assertFalse(any(row['protocol'] == 'hysteria2' for row in rows))

    def test_missing_or_foreign_native_schema_fails_closed(self):
        target, data, initial, _, extras = fixture()
        for visibility in (None, [], [{**row, 'exclude_from_sub': 1} for row in data['visibility']],
                           data['visibility'] + [{'id': 99, 'port': 9000, 'protocol': 'vless',
                                                  'enable': 1, 'exclude_from_sub': 0}]):
            with self.subTest(visibility=visibility), self.assertRaises(RuntimeError):
                P.plan(dict(data, visibility=visibility), target, extras, initial)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'x-ui.db'
            FIXTURE.create_db(path, data)
            self.assertNotEqual(FIXTURE.worker(path, 'visibility').returncode, 0)


if __name__ == '__main__':
    unittest.main()
