"""Source-only upgrades in private trees: preserve data, rollback and recover."""
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import shutil
import shlex
import signal
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('vpn_source_update', ROOT / 'tools/update.py')
U = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(U)
RENDER_SPEC = importlib.util.spec_from_file_location('update_fixture_render', ROOT / 'tools/render.py')
R = importlib.util.module_from_spec(RENDER_SPEC)
RENDER_SPEC.loader.exec_module(R)


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash') and shutil.which('tar'), 'Linux rename/fsync tools required')
class SourceUpdate(unittest.TestCase):
    def setUp(self):
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        self.temp = tempfile.TemporaryDirectory(prefix='vpn-source-update-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.layout = U.Layout(self.root)
        self.events = []
        self.units = {name: {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'enabled'} for name in U.TIMERS}
        self.units.update({name: {'LoadState': 'loaded', 'ActiveState': 'inactive', 'MainPID': '0', 'Job': ''} for name in U.JOBS})
        for name in ('opt', 'var/backups', 'var/lib/vpn-installer', 'etc/x-ui', 'etc/krysyuk-standalone',
                     'usr/local/x-ui/bin', 'etc/germanyvpn-xhttp-test', 'etc/nginx', 'etc/letsencrypt',
                     'etc/systemd/system', 'etc/ufw', 'var/www/vpn-decoy/public', 'opt/krysyuk-warp-egress/tests'):
            (self.root / name).mkdir(parents=True, exist_ok=True, mode=0o700)
        self.layout.state.chmod(0o700)
        self.patch_uid = patch.object(U, 'ADMIN_UID', os.getuid()); self.patch_uid.start(); self.addCleanup(self.patch_uid.stop)
        self.patch_gid = patch.object(U, 'ADMIN_GID', os.getgid()); self.patch_gid.start(); self.addCleanup(self.patch_gid.stop)
        self.p_run = patch.object(U, 'run', side_effect=self.run_command); self.p_run.start(); self.addCleanup(self.p_run.stop)
        self.p_unit = patch.object(U, 'unit_state', side_effect=lambda name: dict(self.units[name])); self.p_unit.start(); self.addCleanup(self.p_unit.stop)
        files = {
            'install.sh': "#!/bin/bash\nreadonly release='v1.5.0'\n",
            'tools/manage.sh': '#!/bin/bash\nprintf old-menu\n',
            'tools/render.py': (ROOT / 'tools/render.py').read_text(),
            'tools/verify.sh': '#!/bin/bash\nexit 99 # must never be executed by updater\n',
            'bundle/scripts/target-contract.sh': '#!/bin/bash\ntrue\n',
            'bundle/base/install-pinned-base.sh': '#!/bin/bash\ntrue # unchanged package pins\n',
            'bundle/base/certbot-requirements.txt': 'unchanged dependency pin\n',
            'bundle/warp-egress/tests/test-e2e-local.sh': '#!/bin/bash\ntrue # e2e\n',
            'bundle/warp-egress/tests/test-invalid.sh': '#!/bin/bash\ntrue # invalid\n',
            'bundle/templates/target.txt': '@TARGET_IPV4@ @TARGET_INTERFACE@\n',
        }
        while len(files) < 209: files[f'docs/pad-{len(files)}.txt'] = 'public source\n'
        self.layout.source.mkdir(mode=0o700)
        for name, text in files.items(): self.write(self.layout.source / name, text)
        self.make_manifest(self.layout.source, 'SHA256SUMS')
        target = dict(TARGET_IPV4='8.8.4.4', TARGET_INTERFACE='ens3', TARGET_FQDN='vpn.example.test',
                      TARGET_TLS_MODE='letsencrypt', TARGET_EGRESS_MODE='both', TARGET_PROFILE_SET='basic',
                      TARGET_REALITY_MODE='external', TARGET_ADDRESS_MODE='domain', TARGET_LABEL='Original label')
        self.write(self.layout.target, ''.join(key+'='+shlex.quote(value)+'\n' for key, value in target.items()))
        self.write(self.layout.protected[1], 'OWNER_UUID=fixture-secret-uuid\n')
        self.write(self.layout.protected[2], 'PANEL_PASSWORD=fixture-secret-password\n')
        self.write(self.root / 'usr/local/x-ui/bin/config.json', '{"unchanged":"fixture-secret-uuid"}\n')
        self.write(self.root / 'etc/germanyvpn-xhttp-test/config.json', '{"immutable":true}\n')
        self.write(self.root / 'etc/germanyvpn-xhttp-test/promotion.json', '{"status":"committed"}\n')
        self.write(self.root / 'var/www/vpn-decoy/public/index.html', 'User website, preserve\n')
        for name in ('base', 'certbot', 'tls', 'direct', 'panel', 'nginx-restart', 'cert-reconcile',
                     'xhttp', 'renewal', 'menu', 'verify', 'warp', 'dual'):
            self.write(self.layout.state / (name+'.done'), '2026-11-11T10:00:00Z\n')
        self.layout.runtime.mkdir(mode=0o700)
        for path in (self.layout.source / 'bundle').rglob('*'):
            if path.is_file(): self.write(self.layout.runtime / path.relative_to(self.layout.source / 'bundle'), path.read_bytes())
        with patch.dict(os.environ, {'TARGET_IPV4': '8.8.4.4', 'TARGET_INTERFACE': 'ens3'}): R.render(self.layout.runtime)
        for name in U.TESTS:
            self.write(self.layout.warp_tests / name, (self.layout.runtime / 'warp-egress/tests' / name).read_bytes(), 0o700)
        with closing(sqlite3.connect(self.layout.db)) as database:
            database.executescript('''
CREATE TABLE users(id INTEGER PRIMARY KEY,password TEXT);
CREATE TABLE settings(id INTEGER PRIMARY KEY,value TEXT);
CREATE TABLE inbounds(id INTEGER PRIMARY KEY,settings TEXT,up INTEGER,down INTEGER);
CREATE TABLE clients(id INTEGER PRIMARY KEY,uuid TEXT,up INTEGER);
CREATE TABLE client_inbounds(client_id INTEGER,inbound_id INTEGER);
CREATE TABLE client_external_links(id INTEGER PRIMARY KEY,value TEXT,last_fetch_at INTEGER);
INSERT INTO users VALUES(1,'fixture-password-hash');
INSERT INTO settings VALUES(1,'unchanged');
INSERT INTO inbounds VALUES(1,'fixture-secret-config',0,0);
INSERT INTO clients VALUES(1,'fixture-secret-uuid',0);
INSERT INTO client_inbounds VALUES(1,1);
INSERT INTO client_external_links VALUES(1,'fixture-private-uri',0);
'''); database.commit()
        self.layout.db.chmod(0o600)
        self.candidate = self.root / 'candidate'
        shutil.copytree(self.layout.source, self.candidate)
        self.candidate.chmod(0o700)
        self.write(self.candidate / 'install.sh', "#!/bin/bash\nreadonly release='v1.5.1'\n")
        self.write(self.candidate / 'tools/manage.sh', '#!/bin/bash\nprintf new-name-menu\n')
        self.write(self.candidate / 'tools/profile-name.py', 'PROFILE_NAME_MENU = True\n')
        self.make_manifest(self.candidate, 'SHA256SUMS')
        self.before = {path: path.read_bytes() for path in self.layout.protected}
        self.before_db = U.database_state(self.layout.db)
        self.before_site = (self.root / 'var/www/vpn-decoy/public/index.html').read_bytes()

    def write(self, path, value, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(value.encode() if isinstance(value, str) else value)
        path.chmod(mode)

    def make_manifest(self, tree, name):
        rows = []
        for path in sorted(tree.rglob('*')):
            if path.is_file() and path.name != name and '__pycache__' not in path.parts:
                rows.append(U.digest(path.read_bytes())+'  '+path.relative_to(tree).as_posix()+'\n')
        self.write(tree / name, ''.join(rows))

    def run_command(self, args, *, timeout=180, env=None):
        self.events.append(list(args))
        if args[0] == 'systemctl':
            self.units[args[2]]['ActiveState'] = 'active' if args[1] == 'start' else 'inactive'
            return b''
        if args[0] == 'python3':
            self.assertEqual(Path(args[3]).name, 'render.py')
            with patch.dict(os.environ, env): R.render(Path(args[4]))
            return b''
        if args[0] in ('ufw', 'nft'): return b'# unchanged firewall\n'
        self.assertIn(args[0], ('bash', 'tar'), 'Unexpected production command: '+repr(args))
        if args[0] == 'bash': self.assertEqual(args[1], '-n', 'Updater must not run VPN/network verifiers')
        process = subprocess.run(args, env=env, capture_output=True, timeout=timeout)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        return process.stdout

    def assert_preserved(self):
        for path, raw in self.before.items(): self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(U.database_state(self.layout.db), self.before_db)
        self.assertEqual((self.root / 'var/www/vpn-decoy/public/index.html').read_bytes(), self.before_site)
        self.assertTrue(all(self.units[name]['ActiveState']=='active' for name in U.TIMERS))

    def test_update_adds_name_menu_preserves_all_data_and_skips_unchanged_warp_tests(self):
        tests = {name: U.identity(self.layout.warp_tests / name) for name in U.TESTS}
        U.apply(self.layout, self.candidate)
        self.assertEqual(U.version(self.layout.source)[0], 'v1.5.1')
        self.assertIn('new-name-menu', (self.layout.source/'tools/manage.sh').read_text())
        self.assertFalse(self.layout.pending.exists())
        self.assert_preserved()
        for name, inode in tests.items(): self.assertEqual(U.identity(self.layout.warp_tests/name), inode)
        backup, = self.layout.backups.iterdir()
        record = json.loads((backup/'journal.json').read_bytes())
        self.assertEqual(record['status'], 'committed')
        self.assertEqual(len(record['swaps']), 2)

    def test_changed_owned_warp_tests_are_updated_with_the_four_swap_journal(self):
        for name in U.TESTS:
            self.write(self.candidate/'bundle/warp-egress/tests'/name, '#!/bin/bash\ntrue # new reviewed test\n')
        self.make_manifest(self.candidate, 'SHA256SUMS')
        U.apply(self.layout, self.candidate)
        backup, = self.layout.backups.iterdir()
        self.assertEqual(len(json.loads((backup/'journal.json').read_bytes())['swaps']), 4)
        self.assertTrue(all(b'new reviewed test' in (self.layout.warp_tests/name).read_bytes() for name in U.TESTS))
        self.assert_preserved()

    def test_failure_after_first_directory_move_rolls_back_by_identity(self):
        original, inode = U.move, U.identity(self.layout.source)
        failed = []
        def move(source, destination, **options):
            original(source, destination, **options)
            if source == self.layout.source and not failed:
                failed.append(True); raise OSError('injected failure after source rename')
        with patch.object(U, 'move', side_effect=move), self.assertRaises(OSError):
            U.apply(self.layout, self.candidate)
        self.assertEqual(U.identity(self.layout.source), inode)
        self.assertEqual(U.version(self.layout.source)[0], 'v1.5.0')
        self.assertFalse(self.layout.pending.exists())
        self.assert_preserved()

    def test_recover_handles_kill_between_the_two_source_renames(self):
        original, failed = U.move, []
        def move(source, destination, **options):
            original(source, destination, **options)
            if source == self.layout.source and not failed:
                failed.append(True); raise OSError('simulated killed caller')
        with patch.object(U, 'move', side_effect=move), patch.object(U, 'rollback', return_value=False), self.assertRaises(OSError):
            U.apply(self.layout, self.candidate)
        self.assertFalse(self.layout.source.exists())
        self.assertTrue(self.layout.pending.exists())
        U.recover(self.layout)
        self.assertEqual(U.version(self.layout.source)[0], 'v1.5.0')
        self.assertFalse(self.layout.pending.exists())
        self.assert_preserved()

    def test_modified_installed_warp_test_or_unmanifested_executable_blocks_before_timers(self):
        self.write(self.layout.warp_tests/U.TESTS[0], '#!/bin/bash\necho foreign\n', 0o700)
        with self.assertRaisesRegex(RuntimeError, 'WARP_TEST_DRIFT'): U.apply(self.layout, self.candidate)
        self.assertFalse(self.layout.pending.exists()); self.assertEqual(self.events, [])
        self.write(self.layout.warp_tests/U.TESTS[0], (self.layout.runtime/'warp-egress/tests'/U.TESTS[0]).read_bytes(), 0o700)
        self.write(self.layout.source/'extra.sh', '#!/bin/bash\necho extra\n', 0o700)
        with self.assertRaisesRegex(RuntimeError, 'UNEXPECTED_CACHE'): U.apply(self.layout, self.candidate)
        self.assertEqual(self.events, [])

    def test_source_cache_must_match_compilation_of_manifested_source(self):
        source = self.layout.source/'tools/render.py'
        py_compile.compile(str(source), doraise=True)
        U.manifest(self.layout.source, 'SHA256SUMS', caches=True)
        cache, = (source.parent/'__pycache__').iterdir()
        wrong = compile('raise RuntimeError("unmanifested executable")', str(source), 'exec')
        import marshal
        cache.write_bytes(cache.read_bytes()[:16]+marshal.dumps(wrong))
        with self.assertRaisesRegex(RuntimeError, 'CACHE_CODE'): U.manifest(self.layout.source, 'SHA256SUMS', caches=True)

    def test_pending_rename_or_incomplete_install_refuses_update(self):
        pending = self.layout.state/'profile-name-management.pending'
        self.write(pending, 'pending')
        with self.assertRaisesRegex(RuntimeError, 'PENDING_RECOVERY'): U.apply(self.layout, self.candidate)
        pending.unlink(); (self.layout.state/'verify.done').unlink()
        with self.assertRaises(FileNotFoundError): U.apply(self.layout, self.candidate)
        self.assertEqual(self.events, [])

    def test_old_http_and_binary_version_migrations_are_rejected(self):
        self.write(self.candidate/'bundle/base/install-pinned-base.sh', '#!/bin/bash\nfalse # changed binary pin\n')
        self.make_manifest(self.candidate, 'SHA256SUMS')
        with self.assertRaisesRegex(RuntimeError, 'BINARY_MIGRATION_UNSUPPORTED'): U.apply(self.layout, self.candidate)
        self.write(self.candidate/'bundle/base/install-pinned-base.sh', (self.layout.source/'bundle/base/install-pinned-base.sh').read_bytes())
        self.make_manifest(self.candidate, 'SHA256SUMS')
        self.write(self.layout.target, self.layout.target.read_text().replace('letsencrypt','none'))
        with self.assertRaisesRegex(RuntimeError, 'HTTPS_REQUIRED'): U.apply(self.layout, self.candidate)
        self.assertEqual(self.events, [])

    def test_live_traffic_counters_do_not_change_config_fingerprint_but_credentials_do(self):
        before = U.database_state(self.layout.db)
        with closing(sqlite3.connect(self.layout.db)) as db:
            db.execute('UPDATE inbounds SET up=100,down=200'); db.execute('UPDATE clients SET up=100'); db.commit()
        self.assertEqual(U.database_state(self.layout.db), before)
        with closing(sqlite3.connect(self.layout.db)) as db:
            db.execute("UPDATE clients SET uuid='different-credential'"); db.commit()
        self.assertNotEqual(U.database_state(self.layout.db), before)

    def test_pending_unlink_failure_after_durable_commit_never_rolls_back_new_code(self):
        original = Path.unlink
        fail = []
        def unlink(path, *args, **kwargs):
            if path == self.layout.pending and not fail:
                fail.append(True); raise OSError('injected cleanup failure')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'unlink', unlink), self.assertRaisesRegex(RuntimeError, 'COMMITTED_RECOVERY_REQUIRED'):
            U.apply(self.layout, self.candidate)
        self.assertEqual(U.version(self.layout.source)[0], 'v1.5.1')
        self.assertTrue(self.layout.pending.exists())
        U.recover(self.layout)
        self.assertEqual(U.version(self.layout.source)[0], 'v1.5.1')
        self.assertFalse(self.layout.pending.exists())
        self.assert_preserved()

    def test_failed_commit_journal_save_rolls_back_before_accepting_update(self):
        original, failed = U.Journal.save, []
        def save(journal):
            if journal.record['status'] == 'committed' and not failed:
                failed.append(True); raise OSError('injected failed commit save')
            return original(journal)
        with patch.object(U.Journal, 'save', save), self.assertRaises(OSError):
            U.apply(self.layout, self.candidate)
        self.assertEqual(U.version(self.layout.source)[0], 'v1.5.0')
        self.assertFalse(self.layout.pending.exists())
        self.assert_preserved()

    def test_signal_after_commit_save_cannot_begin_rollback(self):
        original, signalled = U.Journal.save, []
        def save(journal):
            original(journal)
            if journal.record['status'] == 'committed' and not signalled:
                signalled.append(True); os.kill(os.getpid(), signal.SIGTERM)
        with patch.object(U.Journal, 'save', save), self.assertRaisesRegex(RuntimeError, 'COMMITTED_RECOVERY_REQUIRED'):
            U.apply(self.layout, self.candidate)
        self.assertEqual(U.version(self.layout.source)[0], 'v1.5.1')
        U.recover(self.layout)
        self.assert_preserved()

    def test_ambiguous_commit_save_requires_durable_rollback_intent_or_holds_pending(self):
        original = U.Journal.save
        def save(journal):
            if journal.record['status'] == 'rolling_back': raise OSError('storage unavailable')
            original(journal)
            if journal.record['status'] == 'committed': raise OSError('failed after replacement')
        with patch.object(U.Journal, 'save', save), self.assertRaisesRegex(RuntimeError, 'RECOVERY_REQUIRED'):
            U.apply(self.layout, self.candidate)
        self.assertEqual(U.version(self.layout.source)[0], 'v1.5.1')
        self.assertTrue(self.layout.pending.exists())
        U.recover(self.layout)
        self.assertFalse(self.layout.pending.exists())
        self.assert_preserved()


if __name__ == '__main__': unittest.main()
