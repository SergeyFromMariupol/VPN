"""Display-name transactions preserve every client identity and transport."""
import base64
from contextlib import closing, ExitStack
import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('manage_profile_name_tests',
                                             ROOT / 'bundle/scripts/manage-profile-name.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
CAT_SPEC = importlib.util.spec_from_file_location('profile_name_catalog', ROOT / 'bundle/portfolio/portfolio_catalog.py')
CAT = importlib.util.module_from_spec(CAT_SPEC)
CAT_SPEC.loader.exec_module(CAT)
TARGET = dict(TARGET_LABEL='🇳🇱 Старое имя', TARGET_IPV4='45.67.89.10',
              TARGET_FQDN='vpn.example.test', TARGET_ADDRESS_MODE='domain',
              TARGET_TLS_MODE='letsencrypt', TARGET_EGRESS_MODE='both', TARGET_PROFILE_SET='basic',
              TARGET_REALITY_MODE='decoy', TARGET_REALITY_SNI='max.ru', TARGET_INTERFACE='eth0')


def uri(name, number, *, vmess=False):
    if vmess:
        raw = json.dumps({'v': '2', 'ps': name, 'add': TARGET['TARGET_FQDN'], 'port': str(30000 + number),
                          'id': 'identity-' + str(number), 'aid': '0', 'net': 'ws', 'host': 'host.example',
                          'path': '/retained-path', 'tls': 'tls', 'sni': TARGET['TARGET_FQDN']}, ensure_ascii=False)
        return 'vmess://' + base64.b64encode(raw.encode()).decode()
    return ('vless://identity-' + str(number) + '@vpn.example.test:' + str(30000 + number) +
            '?security=reality&type=grpc&sni=max.ru&pbk=retained-key&sid=0123456789abcdef&extra=%2f%2F#' + quote(name, safe=''))


def fixture(root, egress='both', profile_set='basic', ip=False, label=TARGET['TARGET_LABEL']):
    target = dict(TARGET, TARGET_EGRESS_MODE=egress, TARGET_PROFILE_SET=profile_set, TARGET_LABEL=label)
    if ip:
        target.update(TARGET_ADDRESS_MODE='ip', TARGET_FQDN=TARGET['TARGET_IPV4'])
    rows = CAT.select_profiles(profile_set, egress, target['TARGET_LABEL'])
    initial = [uri(row['name'], index, vmess=row['protocol'] == 'vmess') for index, row in enumerate(rows)]

    def save(path, value, raw=False):
        location = root / path.as_posix().lstrip('/')
        location.parent.mkdir(parents=True, exist_ok=True)
        data = value if raw else M.x.canonical(value)
        location.write_bytes(data)
        return data

    config = {'inbounds': [{'tag': 'retained', 'settings': {'clients': [{'id': 'uuid-retained', 'email': 'stable'}]},
                           'streamSettings': {'security': 'reality', 'network': 'grpc',
                                              'realitySettings': {'target': '127.0.0.1:9443', 'serverNames': ['max.ru'],
                                                                  'privateKey': 'private-retained', 'shortIds': ['0123456789abcdef']}}}],
              'routing': {'rules': [{'type': 'field', 'network': 'udp', 'outboundTag': 'DIRECT'}]},
              'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom'}]}
    main = save(M.tx.MAIN, config)
    direct = save(M.tx.DIRECT, config)
    marker = {'version': 3 if egress == 'direct' else 2, 'status': 'committed', 'target': target['TARGET_IPV4'],
              'direct_config_sha256': M.x.sha(direct), 'main_runtime_sha256': M.x.sha(main)}
    baseline = [link for row, link in zip(rows, initial) if row['baseline_reuse']]
    if egress == 'direct':
        # A selected portfolio retains the complete direct baseline receipt.
        baseline = [uri(row['name'], 200 + index) for index, row in enumerate(
            CAT.select_profiles('basic', 'direct', target['TARGET_LABEL']))]
        marker['baseline_sha256'] = M.x.sha(save(M.tx.BASELINE, {'links': baseline}))
    else:
        marker['warp_config_sha256'] = M.x.sha(save(M.tx.WARP, config))
    save(M.tx.PROMOTION, marker)
    entries = [{'id': row['id'], 'remark': row['name'], 'uri': link, 'egress': row['egress'], 'port': 30000 + index}
               for index, (row, link) in enumerate(zip(rows, initial)) if not row['baseline_reuse']]
    manifest_sha = None
    if entries:
        portfolio = save(M.tx.PORTFOLIO, config)
        links = save(M.tx.LINKS, {'version': 1, 'target': target['TARGET_IPV4'], 'entries': entries})
        manifest_sha = M.x.sha(links)
        save(M.tx.PORTFOLIO_STATE, {'phase': 'committed', 'target': target['TARGET_IPV4'],
                                  'config_sha256': M.x.sha(portfolio), 'links_sha256': manifest_sha})
    save(M.tx.TARGET, M.tx.serialize(target), True)
    save(M.ACCESS, b"SUBSCRIPTION_URL='https://retained-url/private-token'\n", True)
    save(M.tx.SERVER_ENV, b"RETAINED_UUID='retained-secret'\n", True)
    save(M.ALIASES, b'# Alias headers come from the primary subscription.\n', True)
    save(M.NGINX, ('# retained assets and secret path\nmap $ua $routing {\n"INCY" "' +
                  M.happ.routing_link(target['TARGET_LABEL']) + '";\n"v2raytun" "' +
                  M.happ.v2raytun_header(target['TARGET_LABEL']) + '";\n}\n').encode(), True)
    db_path = root / M.tx.DB.as_posix().lstrip('/')
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path)) as db, db:
        db.executescript('''
CREATE TABLE clients(id INTEGER PRIMARY KEY,email TEXT,comment TEXT,uuid TEXT,auth TEXT,sub_id TEXT,enable INTEGER);
CREATE TABLE client_inbounds(client_id INTEGER,inbound_id INTEGER,flow_override TEXT);
CREATE TABLE inbounds(id INTEGER PRIMARY KEY,node_id INTEGER,stream_settings TEXT,settings TEXT,port INTEGER,up INTEGER,down INTEGER);
CREATE TABLE hosts(id INTEGER PRIMARY KEY,inbound_id INTEGER,sni TEXT,security TEXT);
CREATE TABLE settings(id INTEGER PRIMARY KEY,key TEXT,value TEXT);
CREATE TABLE client_external_links(id INTEGER PRIMARY KEY,kind TEXT,value TEXT,remark TEXT,enable INTEGER,sort_index INTEGER,last_fetch_at INTEGER);
''')
        for index, (email, name) in enumerate(M.client_names(target).items(), 1):
            db.execute('INSERT INTO clients VALUES(?,?,?,?,?,?,1)',
                       (index, email, name, 'uuid-' + str(index), 'auth-' + str(index), 'subscription-id'))
            db.execute('INSERT INTO client_inbounds VALUES(?,1,?)', (index, ''))
        db.execute('INSERT INTO inbounds VALUES(1,NULL,?,?,443,100,200)',
                   (json.dumps(config['inbounds'][0]['streamSettings']), '{"untouched":"settings"}'))
        db.execute("INSERT INTO hosts VALUES(1,1,'max.ru','reality')")
        db.execute('INSERT INTO settings VALUES(1,?,?)', ('subRoutingRules', M.happ.routing_link(target['TARGET_LABEL'])))
        db.execute('INSERT INTO settings VALUES(2,?,?)', ('xrayTemplateConfig', json.dumps(config)))
        for index, (row, link) in enumerate(zip(rows, initial), 1):
            db.execute('INSERT INTO client_external_links VALUES(?,?,?,?,1,?,0)',
                       (index, 'link', link, row['name'], index))
        external = [dict(zip(('id', 'kind', 'value', 'remark', 'enable', 'sort_index'), row)) for row in db.execute(
            'SELECT id,kind,value,remark,enable,sort_index FROM client_external_links ORDER BY id')]
    save(M.tx.PUBLICATION, {'status': 'committed', 'target': target['TARGET_IPV4'],
                           'names': [row['name'] for row in rows], 'uri_hashes': M.tx.uri_hashes(initial),
                           'manifest_sha256': manifest_sha, 'after': {'external': external},
                           'before': {'external': copy.deepcopy(external)},
                           'insert_external': copy.deepcopy(external)})
    return target, initial, db_path


class ProfileNameTests(unittest.TestCase):
    def test_basic_both_without_publication_receipt_has_six_profiles_and_selected_receipts_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before, initial, _ = fixture(root)
            (root / M.tx.PUBLICATION.as_posix().lstrip('/')).unlink()
            plan = M.Plan(before, M.request_target(before, {'label': 'After'}), initial).build(root)
            self.assertEqual(M.feed_count(before, None), 6)
            self.assertNotIn(M.tx.PUBLICATION, plan.files)
        for mode, profile_set in (('direct', 'basic'), ('warp', 'basic'), ('both', 'all')):
            with self.subTest(mode=mode, profile_set=profile_set), self.assertRaisesRegex(RuntimeError, 'PUBLICATION_REQUIRED'):
                M.feed_count(dict(TARGET, TARGET_EGRESS_MODE=mode, TARGET_PROFILE_SET=profile_set), None)

    def test_protocol_word_prefix_and_shell_characters_never_replace_config_or_credential_text(self):
        for label in ('REALITY', 'IP'):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                before, initial, path = fixture(root, profile_set='all', label=label)
                after = M.request_target(before, {'label': 'После "кавычек" $() \\ путь 🚀'})
                plan = M.Plan(before, after, initial).build(root)
                for absolute, raw in plan.configs.items():
                    self.assertEqual(raw, (root / absolute.as_posix().lstrip('/')).read_bytes())
                    self.assertNotIn(absolute, plan.files)
                saved = M.x.parse_env(plan.files[M.tx.TARGET])
                self.assertEqual(saved['TARGET_LABEL'], after['TARGET_LABEL'])
                self.assertEqual({k: v for k, v in saved.items() if k != 'TARGET_LABEL'},
                                 {k: v for k, v in before.items() if k != 'TARGET_LABEL'})
                self.assertEqual([line for line in plan.files[M.tx.TARGET].splitlines() if not line.startswith(b'TARGET_LABEL=')],
                                 [line for line in plan.originals[M.tx.TARGET].splitlines() if not line.startswith(b'TARGET_LABEL=')])
                with closing(sqlite3.connect(path)) as db:
                    fingerprint = M.database_fingerprint(db)
                    with db:
                        M.tx.edit_database(db, plan.database)
                    self.assertEqual(fingerprint, M.database_fingerprint(db))
                self.assertEqual([M.uri_identity(uri) for uri in initial],
                                 [M.uri_identity(uri) for uri in plan.expected])

    def test_label_validation_preserves_every_other_input_and_refuses_legacy_http(self):
        target = M.request_target(TARGET, {'label': 'Новое имя · Европа 🚀'})
        self.assertEqual({k: v for k, v in target.items() if k != 'TARGET_LABEL'},
                         {k: v for k, v in TARGET.items() if k != 'TARGET_LABEL'})
        for value in ('', '   ', 'a' * 81, 'bad\nname', 'bad\u2028name', 42):
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, 'LABEL'):
                M.request_target(TARGET, {'label': value})
        with self.assertRaisesRegex(RuntimeError, 'HTTPS_REQUIRED'):
            M.request_target(dict(TARGET, TARGET_TLS_MODE='none'), {'label': 'New'})

    def test_uri_rewrite_changes_only_fragment_or_vmess_ps_json_bytes(self):
        target = M.request_target(TARGET, {'label': 'После "смены" 🚀'})
        for is_vmess in (False, True):
            old = uri(TARGET['TARGET_LABEL'] + ' · Custom', 8, vmess=is_vmess)
            new = M.rewrite_uri(old, TARGET, target)
            self.assertEqual(M.uri_identity(old), M.uri_identity(new))
            self.assertEqual(M.uri_name(new), target['TARGET_LABEL'] + ' · Custom')
            if is_vmess:
                old_raw, new_raw = M.vmess(old)[1], M.vmess(new)[1]
                old_ps = json.dumps(M.uri_name(old), ensure_ascii=False)
                new_ps = json.dumps(M.uri_name(new), ensure_ascii=False)
                self.assertEqual(old_raw.replace(old_ps, '"<name>"'), new_raw.replace(new_ps, '"<name>"'))
            else:
                self.assertEqual(old.partition('#')[0], new.partition('#')[0])
        with self.assertRaisesRegex(RuntimeError, 'NAME_BEFORE'):
            M.rewrite_uri(uri('Foreign · Custom', 1), TARGET, target)

    def test_complete_basic6_direct3_ip_dpi49_and_full146_plans_preserve_identity(self):
        for egress, profile_set, ip, count in (('both', 'basic', False, 6), ('direct', 'basic', False, 3),
                                             ('direct', 'dpi', True, 49), ('both', 'all', False, 146)):
            with self.subTest(egress=egress, profile_set=profile_set, ip=ip), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                before, initial, db_path = fixture(root, egress, profile_set, ip)
                after = M.request_target(before, {'label': 'Новое · имя 🚀'})
                plan = M.Plan(before, after, initial).build(root)
                self.assertEqual(len(initial), count)
                self.assertEqual(plan.expected_before(), initial)
                self.assertEqual([M.uri_identity(uri) for uri in initial], [M.uri_identity(uri) for uri in plan.expected])
                self.assertTrue(all(M.uri_name(uri).startswith(after['TARGET_LABEL'] + ' · ') for uri in plan.expected))
                self.assertNotIn(M.tx.MAIN, plan.files)
                self.assertNotIn(M.tx.PORTFOLIO, plan.files)
                self.assertNotIn(M.ACCESS, plan.files)
                self.assertNotIn(M.ALIASES, plan.files)
                for path, raw in plan.configs.items():
                    self.assertEqual(raw, (root / path.as_posix().lstrip('/')).read_bytes())
                publication = json.loads(plan.files[M.tx.PUBLICATION])
                original = json.loads(plan.originals[M.tx.PUBLICATION])
                self.assertEqual(publication['before'], original['before'])
                self.assertEqual(publication['insert_external'], original['insert_external'])
                self.assertEqual(publication['names'], [M.uri_name(uri) for uri in plan.expected])
                self.assertEqual(publication['uri_hashes'], M.tx.uri_hashes(plan.expected))
                if profile_set != 'basic':
                    state = json.loads(plan.files[M.tx.PORTFOLIO_STATE])
                    self.assertEqual(state['config_sha256'], json.loads(plan.originals[M.tx.PORTFOLIO_STATE])['config_sha256'])
                    self.assertEqual(state['links_sha256'], M.x.sha(plan.files[M.tx.LINKS]))
                    self.assertEqual(publication['manifest_sha256'], state['links_sha256'])
                if egress == 'direct':
                    marker = json.loads(plan.files[M.tx.PROMOTION])
                    self.assertEqual(marker['baseline_sha256'], M.x.sha(plan.files[M.tx.BASELINE]))
                with closing(sqlite3.connect(db_path)) as db:
                    identity = M.database_fingerprint(db)
                    with db:
                        M.tx.edit_database(db, plan.database)
                    self.assertEqual(identity, M.database_fingerprint(db))
                    self.assertEqual(dict(db.execute('SELECT email,comment FROM clients')), M.client_names(after))
                    with db:
                        M.tx.edit_database(db, plan.database, restore=True)
                        M.tx.edit_database(db, plan.database, restore=True)
                    self.assertEqual(dict(db.execute('SELECT email,comment FROM clients')), M.client_names(before))

    def test_sql_worker_real_transaction_cas_rolls_back_all_cells_and_recovery_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            before, initial, path = fixture(Path(directory))
            after = M.request_target(before, {'label': 'After'})
            with closing(sqlite3.connect(path)) as db:
                edits = M.db_edits(db, before, after)
            worker = M.tx.WORKER.replace('file:/etc/x-ui/x-ui.db?mode=rw', path.as_uri() + '?mode=rw')
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE settings SET value='foreign' WHERE id=1")
            result = subprocess.run([sys.executable, '-c', worker],
                                    input=M.x.canonical({'edits': edits, 'restore': False}), capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            with closing(sqlite3.connect(path)) as db, db:
                self.assertEqual(db.execute('SELECT comment FROM clients ORDER BY id LIMIT 1').fetchone()[0],
                                 next(iter(M.client_names(before).values())))
                db.execute('UPDATE settings SET value=? WHERE id=1', (M.happ.routing_link(before['TARGET_LABEL']),))
            for restore in (False, True, True):
                result = subprocess.run([sys.executable, '-c', worker],
                                        input=M.x.canonical({'edits': edits, 'restore': restore}), capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_nginx_rewrite_preserves_assets_and_rejects_missing_or_duplicate_owned_metadata(self):
        after = M.request_target(TARGET, {'label': 'After'})
        prefix = b'# unchanged assets and credential-bearing paths\n'
        original = prefix + M.happ.routing_link(TARGET['TARGET_LABEL']).encode() + b'\n' + M.happ.v2raytun_header(TARGET['TARGET_LABEL']).encode()
        changed = M.rewrite_nginx(original, TARGET, after)
        self.assertTrue(changed.startswith(prefix))
        self.assertEqual(M.rewrite_nginx(changed, after, TARGET), original)
        for malformed in (prefix, original + M.happ.routing_link(TARGET['TARGET_LABEL']).encode()):
            with self.assertRaisesRegex(RuntimeError, 'NGINX_METADATA_BEFORE'):
                M.rewrite_nginx(malformed, TARGET, after)

    def test_credential_sni_routing_and_enable_drift_are_never_masked_as_renames(self):
        with tempfile.TemporaryDirectory() as directory:
            _, _, path = fixture(Path(directory))
            with closing(sqlite3.connect(path)) as db:
                original = M.database_fingerprint(db)
                for table, column, value in (('clients', 'uuid', 'foreign-uuid'), ('clients', 'enable', 0),
                                              ('hosts', 'sni', 'foreign.example'), ('inbounds', 'settings', '{}'),
                                              ('settings', 'value', 'foreign-template')):
                    with self.subTest(table=table, column=column):
                        db.execute('SAVEPOINT fixture')
                        db.execute(f'UPDATE {table} SET {column}=? WHERE id=?', (value, 2 if table == 'settings' else 1))
                        self.assertNotEqual(M.database_fingerprint(db), original)
                        db.execute('ROLLBACK TO fixture')
                db.execute('UPDATE inbounds SET up=up+100,down=down+200')
                self.assertEqual(M.database_fingerprint(db), original)

    def test_restart_readback_failure_restores_database_files_nginx_and_leaves_no_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            pending = Path(directory) / 'pending'
            pending.write_bytes(b'private snapshot')
            journal = types.SimpleNamespace(directory=Path(directory),
                record={'database_applied': False, 'paused_timers': [], 'units': ['x-ui.service']},
                save=Mock(), change=Mock(), rollback=Mock())
            plan = types.SimpleNamespace(before=TARGET, after=dict(TARGET, TARGET_LABEL='After'), expected=[],
                database=[['clients', 1, 'comment', 'Before', 'After']], fingerprint='retained',
                main=b'{}', originals={}, files={}, configs={})
            journal.record['database'] = plan.database
            with patch.object(M.tx, 'running', return_value=True), patch.object(M.tx, 'snapshot', return_value=journal), \
                 patch.object(M.tx, 'validate_candidates'), patch.object(M.tx, 'atomic'), \
                 patch.object(M.tx, 'quiescent', return_value=True), patch.object(M.tx, 'stop') as stop, \
                 patch.object(M.tx, 'start') as start, patch.object(M.tx, 'database') as database, \
                 patch.object(M, 'command', return_value=b''), patch.object(M, 'PENDING', pending), \
                 patch.object(M, 'check_database'), patch.object(M, 'verify_record', side_effect=[
                     RuntimeError('MANAGE_PROFILE_NAME_PUBLIC_FEED_TIMEOUT'), None]):
                with self.assertRaisesRegex(RuntimeError, 'PUBLIC_FEED_TIMEOUT'):
                    M.apply(plan, {})
            self.assertEqual(database.call_count, 2)
            self.assertEqual(database.call_args.kwargs, {'restore': True})
            self.assertEqual(stop.call_count, 2)
            self.assertGreaterEqual(start.call_count, 3)
            journal.rollback.assert_called_once()
            self.assertEqual(journal.record['status'], 'rolled_back')
            self.assertEqual(journal.record['primary_failure']['code'], 'MANAGE_PROFILE_NAME_PUBLIC_FEED_TIMEOUT')
            self.assertFalse(pending.exists())

    def test_disk_full_metadata_does_not_prevent_restore_or_clear_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            pending = Path(directory) / 'pending'
            pending.write_bytes(b'private snapshot')
            journal = types.SimpleNamespace(directory=Path(directory), record={'database_applied': 'intent',
                'database': [['clients', 1, 'comment', 'Before', 'After']], 'units': ['x-ui.service'],
                'runtime_touched': True, 'paused_timers': []}, save=Mock(side_effect=OSError(28, 'disk full')), rollback=Mock())
            with patch.object(M.tx, 'stop'), patch.object(M.tx, 'start'), patch.object(M.tx, 'quiescent', return_value=True), \
                 patch.object(M.tx, 'database') as database, patch.object(M, 'command'), \
                 patch.object(M, 'verify_record'), patch.object(M, 'PENDING', pending):
                with self.assertRaisesRegex(RuntimeError, 'ROLLBACK_METADATA_PENDING'):
                    M.rollback(journal, {})
            database.assert_called_once_with(journal.record['database'], restore=True)
            journal.rollback.assert_called_once()
            self.assertTrue(pending.exists())

    def test_commit_boundary_never_undoes_durable_commit_or_leaves_committed_partial_rollback(self):
        for fault in ('cleanup', 'signal', 'commit-save', 'ambiguous-commit-save'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                pending = Path(directory) / 'pending'
                pending.write_bytes(b'private snapshot')
                journal = types.SimpleNamespace(directory=Path(directory),
                    record={'database_applied': False, 'paused_timers': [], 'units': ['x-ui.service'], 'status': 'prepared'},
                    change=Mock(), rollback=Mock(side_effect=InterruptedError('partial rollback interrupted')))
                persisted = []
                def save():
                    phase = journal.record.get('phase')
                    if phase == 'COMMITTED' and fault in ('commit-save', 'ambiguous-commit-save'):
                        if fault == 'ambiguous-commit-save':
                            persisted.append(copy.deepcopy(journal.record))
                        raise OSError(28, 'private commit metadata failure')
                    if phase == 'ROLLBACK_INTENT' and fault == 'ambiguous-commit-save':
                        raise OSError(28, 'private rollback metadata failure')
                    persisted.append(copy.deepcopy(journal.record))
                journal.save = Mock(side_effect=save)
                plan = types.SimpleNamespace(before=TARGET, after=dict(TARGET, TARGET_LABEL='After'), expected=[],
                    database=[['clients', 1, 'comment', 'Before', 'After']], fingerprint='retained',
                    main=b'{}', originals={}, files={}, configs={})
                journal.record['database'] = plan.database
                for owner, name, value in ((M.tx, 'running', Mock(side_effect=lambda unit: not unit.endswith('.timer'))),
                        (M.tx, 'snapshot', Mock(return_value=journal)), (M.tx, 'validate_candidates', Mock()),
                        (M.tx, 'atomic', Mock()), (M.tx, 'quiescent', Mock(return_value=True)),
                        (M.tx, 'stop', Mock()), (M.tx, 'start', Mock()), (M.tx, 'database', Mock()),
                        (M, 'command', Mock(return_value=b'')), (M, 'check_database', Mock()),
                        (M, 'verify_record', Mock()), (M, 'PENDING', pending)):
                    stack.enter_context(patch.object(owner, name, value))
                if fault in ('cleanup', 'signal'):
                    stack.enter_context(patch.object(M.Path, 'unlink', side_effect=(
                        OSError(13, 'private unlink error') if fault == 'cleanup' else InterruptedError('signal'))))
                    code = 'COMMITTED_RECOVERY_REQUIRED'
                else:
                    code = 'COMMIT_METADATA_PENDING' if fault == 'ambiguous-commit-save' else 'ROLLBACK_REQUIRED'
                with self.assertRaisesRegex(RuntimeError, code):
                    M.apply(plan, {})
                self.assertTrue(pending.exists())
                if fault in ('cleanup', 'signal', 'ambiguous-commit-save'):
                    journal.rollback.assert_not_called()
                    self.assertEqual(M.tx.database.call_count, 1)
                    self.assertEqual(persisted[-1]['status'], 'committed')
                else:
                    journal.rollback.assert_called_once()
                    self.assertEqual(M.tx.database.call_count, 2)
                    self.assertEqual(M.tx.database.call_args.kwargs, {'restore': True})
                    self.assertEqual(persisted[-1]['status'], 'prepared')
                    self.assertEqual(persisted[-1]['phase'], 'ROLLBACK_FILES')

    def test_readiness_retries_transient_502_but_never_tls_or_wrong_names(self):
        expected = [uri(TARGET['TARGET_LABEL'] + ' · REALITY', 1)]
        with patch.object(M.tx.x, 'native', side_effect=[ConnectionRefusedError(), M.x.SubscriptionHTTPError(502), expected]), \
             patch.object(M.tx.time, 'sleep'):
            self.assertEqual(M.tx.wait_published(TARGET, {}, expected), expected)
        for result in (ssl.SSLCertVerificationError(1, 'hidden'), [uri('Foreign · REALITY', 1)]):
            with patch.object(M.tx.x, 'native', side_effect=result if isinstance(result, Exception) else None,
                              return_value=result) as native:
                with self.assertRaises((RuntimeError, ssl.SSLError)):
                    M.tx.wait_published(TARGET, {}, expected)
                native.assert_called_once()

    def test_recovery_repeats_owned_rollback_after_interruption_and_reverifies_committed_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            backups = Path(temporary)
            directory = backups / 'change-fixture'
            pending = backups / 'pending'
            resources = {directory / name: name.encode() for name in
                         ('x-ui.db', 'managed-before.tar', 'nft-before.txt', 'ufw-before.txt')}
            resources[directory / 'manifest.json'] = M.x.canonical({path.name: M.x.sha(raw)
                for path, raw in resources.items()})
            resources[pending] = str(directory).encode()
            resources[M.tx.SERVER_ENV] = b"SUBSCRIPTION_ID='retained'\n"
            record = {'kind': 'profile-name', 'version': 1, 'status': 'prepared', 'units': ['x-ui.service'],
                      'runtime_touched': True, 'database_applied': 'intent', 'database': [], 'files': [],
                      'paused_timers': [], 'before_target': TARGET, 'before_feed': []}
            with patch.object(M, 'BACKUPS', backups), patch.object(M, 'PENDING', pending), \
                 patch.object(M.tx, 'private', side_effect=lambda path: resources[path]), \
                 patch.object(M.Path, 'lstat', return_value=types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700)), \
                 patch.object(M.tx.Journal, 'save'), patch.object(M.tx.Journal, 'rollback') as files, \
                 patch.object(M.tx, 'database') as database, patch.object(M.tx, 'stop'), patch.object(M.tx, 'start'), \
                 patch.object(M.tx, 'quiescent', return_value=True), patch.object(M.tx, 'running', return_value=False), \
                 patch.object(M, 'command'), patch.object(M, 'verify_record') as verify:
                for status in ('prepared', 'prepared', 'committed'):
                    resources[directory / 'journal.json'] = M.x.canonical(dict(record, status=status))
                    pending.write_bytes(b'pending')
                    M.recover()
                    self.assertFalse(pending.exists())
                self.assertEqual(files.call_count, 2)
                self.assertEqual(database.call_count, 2)
                self.assertEqual([call.kwargs for call in database.call_args_list], [{'restore': True}] * 2)
                self.assertEqual(verify.call_count, 3)
                self.assertEqual([call.kwargs for call in verify.call_args_list], [{'restore': True}, {'restore': True}, {}])

    def test_update_or_reality_pending_blocks_even_name_recovery_before_any_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            foreign = Path(temporary) / 'foreign.pending'
            foreign.write_bytes(b'foreign transaction')
            fcntl = types.SimpleNamespace(flock=Mock(), LOCK_EX=1, LOCK_NB=4)
            with patch.dict(sys.modules, {'fcntl': fcntl}), \
                 patch.object(M.os, 'geteuid', return_value=0, create=True), patch.object(M.os, 'umask'), \
                 patch.object(M.os, 'O_NOFOLLOW', 0, create=True), \
                 patch.object(M.os, 'open', return_value=10), patch.object(M.os, 'close'), \
                 patch.object(M.os, 'fstat', return_value=types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o600, st_nlink=1)), \
                 patch.object(M, 'OTHER_PENDING', (foreign,)), patch.object(M, 'recover') as recover:
                with self.assertRaisesRegex(RuntimeError, 'OTHER_PENDING_RECOVERY_REQUIRED'):
                    M.main(['--recover'])
                recover.assert_not_called()


if __name__ == '__main__':
    unittest.main()
