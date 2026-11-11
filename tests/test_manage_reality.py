"""SNI management candidates, credential preservation, CAS and rollback faults."""
import copy
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit


SPEC = importlib.util.spec_from_file_location(
    'manage_reality_tests', Path(__file__).resolve().parents[1] / 'bundle/scripts/manage-reality.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
TARGET = {'TARGET_FQDN': 'vpn.example.test', 'TARGET_IPV4': '45.67.89.10',
          'TARGET_ADDRESS_MODE': 'domain', 'TARGET_TLS_MODE': 'letsencrypt',
          'TARGET_REALITY_SNI': 'max.ru', 'TARGET_LABEL': 'Test'}
UUID = '11111111-2222-3333-4444-555555555555'
URI = ('vless://' + UUID + '@vpn.example.test:443?security=reality&type=grpc&'
       'serviceName=reality-grpc&sni=max.ru&pbk=public&sid=01234567#Test%20Reality')
TLS_URI = 'vless://' + UUID + '@vpn.example.test:30443?security=tls&sni=vpn.example.test#TLS'


def stream(sni='max.ru', destination='max.ru:443'):
    return {'security': 'reality', 'network': 'grpc',
            'grpcSettings': {'serviceName': 'reality-grpc'},
            'realitySettings': {'target': destination, 'serverNames': [sni], 'xver': 0,
                                'privateKey': 'private-key-fixture', 'shortIds': ['01234567']}}


def configuration(port):
    return {'inbounds': [{'listen': TARGET['TARGET_IPV4'], 'port': port,
                         'settings': {'clients': [{'id': UUID, 'email': 'fixture', 'flow': ''}]},
                         'streamSettings': stream()}],
            'routing': {'rules': [{'outboundTag': 'BLOCK'}]},
            'outbounds': [{'tag': 'BLOCK', 'protocol': 'blackhole'}]}


def create_db(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.executescript('''
CREATE TABLE inbounds(id INTEGER PRIMARY KEY,node_id INTEGER,stream_settings TEXT);
CREATE TABLE hosts(id INTEGER PRIMARY KEY,inbound_id INTEGER,security TEXT,sni TEXT);
CREATE TABLE client_external_links(id INTEGER PRIMARY KEY,kind TEXT,value TEXT);
CREATE TABLE clients(id INTEGER PRIMARY KEY,uuid TEXT,auth TEXT,sub_id TEXT);
INSERT INTO clients VALUES(1,'retained-uuid','retained-auth','retained-subscription');
''')
    connection.execute('INSERT INTO inbounds VALUES(1,NULL,?)', (json.dumps(stream()),))
    connection.execute('INSERT INTO inbounds VALUES(2,NULL,?)',
                       (json.dumps({'security': 'tls', 'tlsSettings': {'serverName': TARGET['TARGET_FQDN']}}),))
    connection.execute('INSERT INTO hosts VALUES(1,1,?,?)', ('reality', 'max.ru'))
    connection.execute('INSERT INTO hosts VALUES(2,2,?,?)', ('tls', TARGET['TARGET_FQDN']))
    connection.execute('INSERT INTO client_external_links VALUES(1,?,?)', ('link', URI))
    connection.execute('INSERT INTO client_external_links VALUES(2,?,?)', ('link', TLS_URI))
    connection.commit()
    return connection


class ManagementPlanTests(unittest.TestCase):
    def test_request_modes_are_explicit_and_self_steal_uses_own_domain(self):
        own = MODULE.request_target(TARGET, {'mode': 'self-steal'})
        self.assertEqual(own['TARGET_REALITY_SNI'], TARGET['TARGET_FQDN'])
        self.assertEqual(MODULE.x.reality_destination(own), '127.0.0.1:9443')
        decoy = MODULE.request_target(TARGET, {'mode': 'decoy', 'sni': 'max.ru'})
        self.assertEqual(decoy['TARGET_REALITY_SNI'], 'max.ru')
        for request in ({'mode': 'external'}, {'mode': 'self-steal', 'sni': 'max.ru'},
                        {'mode': 'decoy', 'sni': 'max.ru', 'password': 'unwanted'}):
            with self.subTest(request=request), self.assertRaises((ValueError, RuntimeError)):
                MODULE.request_target(TARGET, request)

    def test_uri_rewrite_preserves_every_non_sni_byte_and_all_credentials(self):
        target = MODULE.request_target(TARGET, {'mode': 'self-steal'})
        changed = MODULE.rewrite_uri(URI, TARGET, target)
        self.assertEqual(changed, URI.replace('sni=max.ru', 'sni=vpn.example.test'))
        self.assertEqual(MODULE.rewrite_uri(TLS_URI, TARGET, target), TLS_URI)
        for malformed in (URI.replace('#', '&sni=max.ru#'), URI.replace('sni=max.ru', 'sni=wrong.example.test'),
                          URI.replace('@vpn.example.test:', '@other.example.test:')):
            with self.subTest(malformed=malformed), self.assertRaises(RuntimeError):
                MODULE.rewrite_uri(malformed, TARGET, target)

    def test_stream_switches_preserve_keys_transport_and_client_identity(self):
        cases = [
            (TARGET, {'mode': 'external', 'sni': 'mask.example.test'}, 'mask.example.test:443'),
            (TARGET, {'mode': 'decoy', 'sni': 'max.ru'}, '127.0.0.1:9443'),
            (dict(TARGET, TARGET_REALITY_MODE='self-steal', TARGET_REALITY_SNI=TARGET['TARGET_FQDN']),
             {'mode': 'decoy', 'sni': 'max.ru'}, '127.0.0.1:9443'),
        ]
        for before, request, destination in cases:
            with self.subTest(mode=request['mode'], before=before.get('TARGET_REALITY_MODE')):
                source = stream(before['TARGET_REALITY_SNI'], MODULE.x.reality_destination(before))
                original = copy.deepcopy(source)
                after = MODULE.request_target(before, request)
                changed = MODULE.rewrite_stream(source, before, after)
                self.assertEqual(source, original)
                self.assertEqual(changed['grpcSettings'], source['grpcSettings'])
                self.assertEqual(changed['realitySettings']['privateKey'], 'private-key-fixture')
                self.assertEqual(changed['realitySettings']['shortIds'], ['01234567'])
                self.assertEqual(changed['realitySettings']['serverNames'], [after['TARGET_REALITY_SNI']])
                self.assertEqual(changed['realitySettings']['target'], destination)

    def test_database_cas_changes_only_owned_cells_and_keeps_client_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            connection = create_db(Path(directory) / 'x-ui.db')
            try:
                target = MODULE.request_target(TARGET, {'mode': 'self-steal'})
                edits = MODULE.db_edits(connection, TARGET, target)
                before = connection.execute('SELECT * FROM clients').fetchone()
                with connection:
                    MODULE.edit_database(connection, edits)
                self.assertEqual(tuple(connection.execute('SELECT * FROM clients').fetchone()), tuple(before))
                self.assertEqual(connection.execute('SELECT sni FROM hosts WHERE id=1').fetchone()[0],
                                 TARGET['TARGET_FQDN'])
                self.assertEqual(connection.execute('SELECT sni FROM hosts WHERE id=2').fetchone()[0],
                                 TARGET['TARGET_FQDN'])
                raw = connection.execute('SELECT stream_settings FROM inbounds WHERE id=1').fetchone()[0]
                settings = json.loads(raw)['realitySettings']
                self.assertEqual(settings['target'], '127.0.0.1:9443')
                self.assertEqual(settings['privateKey'], 'private-key-fixture')
                with connection:
                    MODULE.edit_database(connection, edits, restore=True)
                    MODULE.edit_database(connection, edits, restore=True)  # Failed SQL apply is safe to recover.
                self.assertEqual(connection.execute('SELECT sni FROM hosts WHERE id=1').fetchone()[0], 'max.ru')
                connection.execute("UPDATE hosts SET sni='foreign.example.test' WHERE id=1")
                connection.commit()
                with self.assertRaisesRegex(RuntimeError, 'DATABASE_CONCURRENT_WRITE'):
                    with connection:
                        MODULE.edit_database(connection, edits)
                self.assertEqual(connection.execute('SELECT stream_settings FROM inbounds WHERE id=1').fetchone()[0],
                                 json.dumps(stream()))
            finally:
                connection.close()

    def test_worker_sql_transaction_rejects_partial_apply_and_foreign_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'x-ui.db'
            with closing(create_db(path)) as connection, connection:
                edits = MODULE.db_edits(connection, TARGET,
                    MODULE.request_target(TARGET, {'mode': 'decoy', 'sni': 'mask.example.test'}))
            worker = MODULE.WORKER.replace('file:/etc/x-ui/x-ui.db', 'file:' + path.as_posix())
            bad = copy.deepcopy(edits)
            bad[-1][3] = 'foreign-before-value'
            result = subprocess.run([sys.executable, '-c', worker],
                                    input=json.dumps({'edits': bad, 'restore': False}),
                                    text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute('SELECT sni FROM hosts WHERE id=1').fetchone(), ('max.ru',))
            result = subprocess.run([sys.executable, '-c', worker],
                                    input=json.dumps({'edits': edits, 'restore': True}),
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def make_tree(self, root, *, direct=False, portfolio=True):
        def save(path, value):
            location = root / path.as_posix().lstrip('/')
            location.parent.mkdir(parents=True, exist_ok=True)
            raw = MODULE.x.canonical(value)
            location.write_bytes(raw)
            return raw
        with closing(create_db(root / MODULE.DB.as_posix().lstrip('/'))):
            pass
        main = save(MODULE.MAIN, configuration(443))
        side = save(MODULE.DIRECT, configuration(8444))
        marker = {'version': 3 if direct else 2, 'status': 'committed', 'target': TARGET['TARGET_IPV4'],
                  'main_runtime_sha256': MODULE.x.sha(main), 'direct_config_sha256': MODULE.x.sha(side)}
        if direct:
            baseline = save(MODULE.BASELINE, {'links': [URI]})
            marker['baseline_sha256'] = MODULE.x.sha(baseline)
        else:
            warp = save(MODULE.WARP, configuration(8443))
            marker['warp_config_sha256'] = MODULE.x.sha(warp)
        save(MODULE.PROMOTION, marker)
        initial = [URI, TLS_URI]
        if portfolio:
            raw = save(MODULE.PORTFOLIO, configuration(30000))
            extra_uri = URI.replace(':443?', ':30000?')
            links = save(MODULE.LINKS, {'version': 1, 'target': TARGET['TARGET_IPV4'],
                                      'entries': [{'uri': extra_uri, 'egress': 'WARP_CF'}]})
            save(MODULE.PORTFOLIO_STATE, {'phase': 'committed', 'target': TARGET['TARGET_IPV4'],
                                         'config_sha256': MODULE.x.sha(raw), 'links_sha256': MODULE.x.sha(links)})
            initial.append(extra_uri)
            save(MODULE.PUBLICATION, {'status': 'committed', 'target': TARGET['TARGET_IPV4'],
                                     'uri_hashes': MODULE.uri_hashes(initial),
                                     'manifest_sha256': MODULE.x.sha(links),
                                     'after': {'external': [{'kind': 'link', 'value': URI}]},
                                     'before': {'external': [{'kind': 'link', 'value': URI}]}})
        return initial

    def test_complete_candidate_updates_all_live_hashes_and_preserves_history(self):
        for direct in (True, False):
            with self.subTest(direct=direct), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                initial = self.make_tree(root, direct=direct)
                target = MODULE.request_target(TARGET, {'mode': 'self-steal'})
                plan = MODULE.Plan(TARGET, target, initial).build(root)
                for raw in plan.configs.values():
                    config = json.loads(raw)
                    inbound = config['inbounds'][0]
                    self.assertEqual(inbound['settings']['clients'][0]['id'], UUID)
                    reality = inbound['streamSettings']['realitySettings']
                    self.assertEqual(reality['target'], '127.0.0.1:9443')
                    self.assertEqual(reality['serverNames'], [TARGET['TARGET_FQDN']])
                    self.assertEqual(reality['privateKey'], 'private-key-fixture')
                marker = json.loads(plan.files[MODULE.PROMOTION])
                self.assertEqual(marker['main_runtime_sha256'], MODULE.x.sha(plan.main))
                self.assertEqual(marker['direct_config_sha256'], MODULE.x.sha(plan.files[MODULE.DIRECT]))
                state = json.loads(plan.files[MODULE.PORTFOLIO_STATE])
                self.assertEqual(state['config_sha256'], MODULE.x.sha(plan.files[MODULE.PORTFOLIO]))
                self.assertEqual(state['links_sha256'], MODULE.x.sha(plan.files[MODULE.LINKS]))
                publication = json.loads(plan.files[MODULE.PUBLICATION])
                self.assertEqual(publication['uri_hashes'], MODULE.uri_hashes(plan.expected))
                self.assertEqual(publication['manifest_sha256'], MODULE.x.sha(plan.files[MODULE.LINKS]))
                self.assertEqual(publication['before']['external'][0]['value'], URI)
                self.assertEqual(publication['after']['external'][0]['value'], plan.expected[0])
                self.assertEqual(plan.expected_before(), initial)
                self.assertNotIn(b'TARGET_REALITY_DEST=', plan.files[MODULE.TARGET])

    def test_journal_rollback_restores_owned_files_and_refuses_foreign_data(self):
        path = Path('/fixture/file')
        before = {'data': 'b2xk', 'uid': 0, 'gid': 0, 'mode': 0o600}
        states = {path: copy.deepcopy(before)}
        journal = MODULE.Journal(Path('/fixture'), {'files': []})
        journal.save = Mock()
        def read(file):
            return copy.deepcopy(states.get(file))
        def write(file, value):
            states[file] = copy.deepcopy(value)
        with patch.object(MODULE, 'file_state', side_effect=read), \
             patch.object(MODULE, 'publish', side_effect=write):
            journal.change(path, b'new')
            self.assertEqual(states[path]['data'], 'bmV3')
            journal.rollback()
            self.assertEqual(states[path], before)
            journal.rollback()
            states[path] = dict(before, data='Zm9yZWlnbg==')
            with self.assertRaisesRegex(RuntimeError, 'ROLLBACK_FOREIGN_FILE'):
                journal.rollback()
            self.assertEqual(states[path]['data'], 'Zm9yZWlnbg==')

    def test_new_backend_website_is_retained_privately_and_retry_path_is_cleared(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            website, marker, backup = root / 'website', root / 'marker', root / 'backup'
            (website / 'public').mkdir(parents=True)
            (website / 'public/index.html').write_bytes(b'website bytes retained')
            marker.mkdir()
            (marker / 'snapshot').write_bytes(b'backend snapshot reference')
            backup.mkdir()
            identities = {path: [path.stat().st_dev, path.stat().st_ino] for path in (website, marker)}
            record = {'files': [], 'database_applied': False, 'runtime_touched': False,
                      'units': [], 'before_target': TARGET, 'before_feed': [URI],
                      'paused_timers': [], 'backend_created_dirs':
                      [[str(path), identity] for path, identity in identities.items()]}
            journal = MODULE.Journal(backup, record)
            journal.save = Mock()
            with patch.object(MODULE, 'DECOY_DIRS', (website, marker)), \
                 patch.object(MODULE, 'directory_state', side_effect=lambda path: identities[path]), \
                 patch.object(MODULE, 'command', return_value=b''), patch.object(MODULE, 'start'), \
                 patch.object(MODULE, 'PENDING', root / 'pending'), \
                 patch.object(MODULE.x, 'native', return_value=[URI]):
                MODULE.rollback(journal, {})
            self.assertFalse(website.exists())
            self.assertFalse(marker.exists())
            self.assertEqual((backup / 'backend-failed-website/public/index.html').read_bytes(),
                             b'website bytes retained')
            self.assertEqual((backup / 'backend-failed-marker/snapshot').read_bytes(),
                             b'backend snapshot reference')

    def test_backend_commit_is_adopted_but_unverified_partial_write_is_held(self):
        path = Path('/fixture/backend.conf')
        after = {'data': 'Y29uZmln', 'uid': 0, 'gid': 0, 'mode': 0o600}
        record = {'files': [], 'backend_dirs_before': {}}
        journal = MODULE.Journal(Path('/fixture'), record)
        journal.save = Mock()
        with patch.object(MODULE, 'DECOY_DIRS', ()), \
             patch.object(MODULE, 'file_state', return_value=after), \
             patch.object(MODULE, 'command', side_effect=RuntimeError('backend partial')):
            with self.assertRaisesRegex(RuntimeError, 'backend partial'):
                MODULE.adopt_backend(journal, {path: None})
        self.assertTrue(record['backend_unverified'])
        self.assertEqual(record['files'], [])
        with self.assertRaisesRegex(RuntimeError, 'BACKEND_RECOVERY_REQUIRED'):
            MODULE.rollback(journal, {})
        with patch.object(MODULE, 'DECOY_DIRS', ()), \
             patch.object(MODULE, 'file_state', return_value=after), \
             patch.object(MODULE, 'command', return_value=b''):
            MODULE.adopt_backend(journal, {path: None})
        self.assertFalse(record['backend_unverified'])
        self.assertEqual(record['files'], [[str(path), None, after]])

    def test_timed_out_shell_is_terminated_and_reaped_before_rollback_can_begin(self):
        process = Mock()
        process.pid = 1234
        process.poll.return_value = None
        process.communicate.side_effect = [subprocess.TimeoutExpired('fixture', 1), (b'', b'')]
        with patch.object(MODULE.subprocess, 'Popen', return_value=process), \
             patch.object(MODULE.os, 'name', 'posix'), \
             patch.object(MODULE.os, 'killpg', create=True) as kill:
            with self.assertRaisesRegex(RuntimeError, '^MANAGE_REALITY_COMMAND$'):
                MODULE.command(['fixture'], timeout=1, data=b'private input')
            kill.assert_called_once_with(1234, MODULE.signal.SIGTERM)
        self.assertEqual(process.communicate.call_count, 2)

    def test_parent_exit_does_not_exempt_descendants_holding_output_pipes(self):
        process = Mock()
        process.pid = 1234
        process.poll.return_value = 0
        process.communicate.side_effect = [subprocess.TimeoutExpired('fixture', 1), (b'', b'')]
        with patch.object(MODULE.subprocess, 'Popen', return_value=process), \
             patch.object(MODULE.os, 'name', 'posix'), \
             patch.object(MODULE.os, 'killpg', create=True) as kill:
            with self.assertRaisesRegex(RuntimeError, '^MANAGE_REALITY_COMMAND$'):
                MODULE.command(['fixture'], timeout=1)
            kill.assert_called_once_with(1234, MODULE.signal.SIGTERM)
        self.assertEqual(process.communicate.call_count, 2)

    def test_quiescence_rejects_activating_or_queued_certificate_jobs(self):
        for state, pid, job, accepted in (('inactive', '0', '', True), ('failed', '0', '0', True),
                                         ('activating', '0', '', False), ('active', '12', '', False),
                                         ('inactive', '0', '23', False)):
            proof = f'LoadState=loaded\nActiveState={state}\nMainPID={pid}\nJob={job}\n'.encode()
            with self.subTest(state=state, pid=pid, job=job), \
                 patch.object(MODULE, 'command', return_value=proof):
                self.assertEqual(MODULE.quiescent('fixture.service'), accepted)

    def test_post_restart_feed_failure_rolls_back_database_files_and_services(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'managed-before.tar').write_bytes(b'fixture')
            journal = types.SimpleNamespace(directory=root,
                record={'database_applied': False, 'files': [], 'paused_timers': [],
                        'units': ['x-ui.service', 'germanyvpn-xhttp-test.service'],
                        'before_target': TARGET}, save=Mock(),
                change=Mock(), rollback=Mock())
            plan = types.SimpleNamespace(before=TARGET,
                after=dict(TARGET, TARGET_REALITY_MODE='external', TARGET_REALITY_SNI='example.org'),
                expected=[URI], files={MODULE.TARGET: b'fixture'}, configs={},
                main=b'{}', database=[['hosts', 1, 'sni', 'max.ru', 'example.org']])
            journal.record['database'] = plan.database
            db = Mock()
            stopped, started = Mock(), Mock()
            with patch.object(MODULE, 'snapshot', return_value=journal), \
                 patch.object(MODULE, 'validate_candidates'), patch.object(MODULE, 'atomic'), \
                 patch.object(MODULE, 'PENDING', root / 'pending'), \
                 patch.object(MODULE, 'running', side_effect=lambda unit: unit not in
                              ('certbot.service', 'vpn-cert-reconcile.service')), \
                 patch.object(MODULE, 'stop', stopped), patch.object(MODULE, 'start', started), \
                 patch.object(MODULE, 'database', db), patch.object(MODULE, 'command', return_value=b''), \
                 patch.object(MODULE, 'verify_runtime'), \
                 patch.object(MODULE, 'quiescent', return_value=True), \
                 patch.object(MODULE.x, 'native', side_effect=[RuntimeError('feed failed'), [URI]]):
                with self.assertRaisesRegex(RuntimeError, 'feed failed'):
                    MODULE.apply(plan, [URI], {})
            self.assertEqual(db.call_count, 2)
            self.assertEqual(db.call_args.kwargs, {'restore': True})
            journal.rollback.assert_called_once()
            self.assertEqual(journal.record['status'], 'rolled_back')
            self.assertEqual(started.call_count, 3)
            self.assertEqual(stopped.call_count, 2)


if __name__ == '__main__':
    unittest.main()
