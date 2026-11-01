"""Exercise the production Nginx policy transaction in an isolated file tree."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'bundle/base/install-nginx-restart.sh'
TEMPLATE = ROOT / 'bundle/templates/30-vpn-nginx-restart.conf'


@unittest.skipUnless(os.name == 'posix' and all(shutil.which(x) for x in
                    ('bash', 'flock', 'tar', 'install', 'sha256sum', 'stat')),
                    'Linux shell tools are required')
class NginxRestartTransaction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpn-nginx-policy-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('bundle/base', 'bundle/templates', 'backups', 'bin',
                     'etc/nginx', 'etc/letsencrypt', 'etc/x-ui', 'usr/local/x-ui',
                     'etc/systemd/system', 'etc/ufw', 'etc/krysyuk-standalone'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        self.dropin_dir = self.root / 'etc/systemd/system/nginx.service.d'
        self.dropin = self.dropin_dir / TEMPLATE.name
        self.source = self.root / 'bundle/templates' / TEMPLATE.name
        shutil.copyfile(TEMPLATE, self.source)
        with sqlite3.connect(self.root / 'etc/x-ui/x-ui.db') as db:
            db.execute('CREATE TABLE original(value TEXT)')
            db.execute("INSERT INTO original VALUES ('preserved')")
        self.old_policy = {'Restart': 'no', 'RestartUSec': '100ms',
                           'StartLimitIntervalUSec': '10s', 'DropInPaths': '', 'MainPID': '321'}
        self.state = self.root / 'state.json'
        self.state.write_text(json.dumps(self.old_policy))
        self.log = self.root / 'calls.jsonl'
        self._stub('systemctl', r'''
import json,os,sys
from pathlib import Path
r=Path(os.environ['VPN_NGINX_TEST_ROOT']); a=sys.argv[1:]
with (r/'calls.jsonl').open('a') as f:f.write(json.dumps(a)+'\n')
s=json.loads((r/'state.json').read_text()); d=r/'etc/systemd/system/nginx.service.d/30-vpn-nginx-restart.conf'
if a[0]=='daemon-reload':
    if (r/'fail-reload-once').exists():
        (r/'fail-reload-once').unlink();sys.exit(1)
    exists=d.is_file()
    s.update(Restart='on-failure' if exists else 'no',RestartUSec='5s' if exists else '100ms',
             StartLimitIntervalUSec='0' if exists else '10s',DropInPaths=str(d) if exists else '')
    if exists and (r/'bad-readback-once').exists():
        s['Restart']='no';(r/'bad-readback-once').unlink()
    if exists and (r/'foreign-change-once').exists():
        d.parent.rename(r/'foreign-moved-owned-directory')
        d.parent.mkdir();d.write_text('# foreign replacement\n')
        (r/'foreign-change-once').unlink()
    (r/'state.json').write_text(json.dumps(s));sys.exit(0)
if a[0]=='show':
    if '-p' not in a:sys.exit(2)
    props=[a[i+1] for i,x in enumerate(a) if x=='-p']
    if (r/'unknown-effective-dropin').exists():s['DropInPaths']='/unknown/policy.conf'
    print('\n'.join(s[p] if '--value' in a else p+'='+s[p] for p in props));sys.exit(0)
if a[0]=='is-active':sys.exit(1 if (r/'inactive').exists() else 0)
if a[0]=='is-enabled':sys.exit(0)
if a[0]=='cat':print('# vendor Nginx unit');sys.exit(0)
sys.exit(2)
''')
        self._stub('nginx', "import os,sys\nfrom pathlib import Path\nsys.exit(1 if (Path(os.environ['VPN_NGINX_TEST_ROOT'])/'invalid-config').exists() else 0)\n")
        self._stub('sqlite3', r'''
import sqlite3,sys
a=sys.argv[1:];readonly=a[0]=='-readonly'
if readonly:a=a[1:]
with sqlite3.connect('file:'+a[0]+'?mode=ro',uri=True) if readonly else sqlite3.connect(a[0]) as db:
    q=a[1]
    if q.startswith('.backup '):
        with sqlite3.connect(q.split("'",2)[1]) as out:db.backup(out)
    else:
        for row in db.execute(q):print(row[0])
''')
        self._stub('install', r'''
import os,signal,subprocess,sys
from pathlib import Path
r=Path(os.environ['VPN_NGINX_TEST_ROOT']);target=Path(sys.argv[-1])
if target.name=='30-vpn-nginx-restart.conf' and (r/'signal-during-install-once').exists():
    target.write_text('# partially installed\n');target.chmod(0o644)
    (r/'signal-during-install-once').unlink();os.kill(os.getppid(),signal.SIGTERM);sys.exit(0)
sys.exit(subprocess.run([os.environ['VPN_NGINX_REAL_INSTALL'],*sys.argv[1:]]).returncode)
''')
        self._stub('mv', r'''
import os,signal,subprocess,sys
from pathlib import Path
r=Path(os.environ['VPN_NGINX_TEST_ROOT']);target=Path(sys.argv[-1])
result=subprocess.run([os.environ['VPN_NGINX_REAL_MV'],*sys.argv[1:]]).returncode
if result==0 and target==r/'etc/systemd/system/nginx.service.d' and (r/'signal-after-publish-once').exists():
    (r/'signal-after-publish-once').unlink();os.kill(os.getppid(),signal.SIGTERM)
sys.exit(result)
''')
        self._stub('ufw', "print('Status: active')\n")
        self._stub('nft', "print('# fixture firewall')\n")
        script = SCRIPT.read_text(encoding='utf-8')
        replacements = {
            '[[ $EUID == 0 ]]': f'[[ $EUID == {os.getuid()} ]]',
            '/etc/systemd/system/nginx.service.d': self.dropin_dir.as_posix(),
            '/run/vpn-nginx-restart.lock': (self.root / 'lock').as_posix(),
            '/var/backups': (self.root / 'backups').as_posix(),
            '-p /etc/systemd/system ': '-p ' + (self.root / 'etc/systemd/system').as_posix() + ' ',
            '/etc/x-ui/x-ui.db': (self.root / 'etc/x-ui/x-ui.db').as_posix(),
            '-C / ': '-C ' + self.root.as_posix() + ' ',
            '0:0:755': f'{os.getuid()}:{os.getgid()}:755',
            '0:0:644:1': f'{os.getuid()}:{os.getgid()}:644:1',
            'install -o root -g root': 'install',
        }
        for old, new in replacements.items():
            self.assertIn(old, script)
            script = script.replace(old, new)
        self.script = self.root / 'bundle/base/install-nginx-restart.sh'
        self.script.write_text(script, encoding='utf-8')
        self.env = dict(os.environ, PATH=str(self.root / 'bin') + os.pathsep + os.environ['PATH'],
                        VPN_NGINX_TEST_ROOT=str(self.root), LC_ALL='C',
                        VPN_NGINX_REAL_INSTALL=shutil.which('install'), VPN_NGINX_REAL_MV=shutil.which('mv'))

    def _stub(self, name, body):
        path = self.root / 'bin' / name
        path.write_text('#!' + sys.executable + '\n' + body, encoding='utf-8')
        path.chmod(0o755)

    def run_script(self, mode='--apply', success=True):
        result = subprocess.run(['bash', str(self.script), mode], env=self.env,
                                text=True, capture_output=True, timeout=20)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def calls(self):
        return [json.loads(x) for x in self.log.read_text().splitlines()]

    def test_installs_persistent_verified_policy_without_restarting_healthy_nginx(self):
        self.run_script()
        self.assertEqual(self.dropin.read_bytes(), self.source.read_bytes())
        self.assertEqual(self.dropin.stat().st_mode & 0o777, 0o644)
        self.run_script('--check-only')
        self.assertFalse(any(x[0] in ('start', 'stop', 'restart', 'reload') for x in self.calls()))
        backups = list((self.root / 'backups').iterdir())
        self.assertEqual(len(backups), 1)
        self.assertTrue((backups[0] / 'COMMITTED').is_file())

    def test_certificate_free_policy_snapshots_existing_stack_without_certificate_directory(self):
        (self.root / 'etc/letsencrypt').rmdir()
        self.env['TARGET_TLS_MODE'] = 'none'
        self.run_script()
        self.run_script('--check-only')
        backups = list((self.root / 'backups').iterdir())
        self.assertEqual(len(backups), 1)
        with tarfile.open(backups[0] / 'system-before.tar') as archive:
            names = set(archive.getnames())
        self.assertIn('etc/nginx', names)
        self.assertIn('etc/x-ui', names)
        self.assertNotIn('etc/letsencrypt', names)
        self.assertFalse((self.root / 'etc/letsencrypt').exists())
        self.assertFalse(any(call[0] in ('start', 'stop', 'restart', 'reload') for call in self.calls()))
        with sqlite3.connect(backups[0] / 'x-ui.db') as db:
            self.assertEqual(db.execute('SELECT value FROM original').fetchone(), ('preserved',))

    def test_repeat_after_outer_checkpoint_loss_is_idempotent(self):
        self.run_script()
        self.run_script()
        self.assertEqual(len(list((self.root / 'backups').iterdir())), 1)
        self.assertEqual(sum(x[0] == 'daemon-reload' for x in self.calls()), 1)

    def test_foreign_dropin_directory_or_effective_policy_is_never_adopted(self):
        for kind in ('directory', 'effective'):
            with self.subTest(kind=kind):
                if kind == 'directory':
                    self.dropin_dir.mkdir()
                    foreign = self.dropin_dir / 'foreign.conf'
                    foreign.write_text('preserve\n')
                else:
                    (self.root / 'unknown-effective-dropin').touch()
                self.run_script(success=False)
                self.assertEqual(list((self.root / 'backups').iterdir()), [])
                self.assertFalse(any(x[0] == 'daemon-reload' for x in self.calls()))
                if kind == 'directory':
                    self.assertEqual(foreign.read_text(), 'preserve\n')
                    foreign.unlink(); self.dropin_dir.rmdir()

    def test_bad_config_and_stopped_service_fail_before_mutation(self):
        for marker in ('invalid-config', 'inactive'):
            with self.subTest(marker=marker):
                flag = self.root / marker; flag.touch()
                self.run_script(success=False)
                self.assertFalse(self.dropin_dir.exists())
                self.assertEqual(list((self.root / 'backups').iterdir()), [])
                flag.unlink()

    def test_reload_failure_or_wrong_effective_policy_restores_previous_policy(self):
        for marker in ('fail-reload-once', 'bad-readback-once'):
            with self.subTest(marker=marker):
                (self.root / marker).touch()
                result = self.run_script(success=False)
                self.assertIn('NGINX_RESTART_ROLLBACK_OK=1', result.stderr)
                self.assertFalse(self.dropin_dir.exists())
                self.assertEqual(json.loads(self.state.read_text()), self.old_policy)

    def test_foreign_change_during_transaction_is_preserved_and_rollback_reports_failure(self):
        (self.root / 'foreign-change-once').touch()
        result = self.run_script(success=False)
        self.assertIn('NGINX_RESTART_ROLLBACK_OK=0', result.stderr)
        self.assertEqual(self.dropin.read_text(), '# foreign replacement\n')

    def test_term_after_directory_publication_preserves_owned_tree_and_retry_succeeds(self):
        (self.root / 'signal-after-publish-once').touch()
        result = self.run_script(success=False)
        self.assertIn('NGINX_RESTART_ROLLBACK_OK=1', result.stderr)
        self.assertFalse(self.dropin_dir.exists())
        self.assertEqual(json.loads(self.state.read_text()), self.old_policy)
        saved = list((self.root / 'backups').glob('*/published.failed/30-vpn-nginx-restart.conf'))
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0].read_bytes(), self.source.read_bytes())
        self.run_script()

    def test_term_during_policy_install_preserves_partial_file_and_retry_succeeds(self):
        (self.root / 'signal-during-install-once').touch()
        result = self.run_script(success=False)
        self.assertIn('NGINX_RESTART_ROLLBACK_OK=1', result.stderr)
        self.assertFalse(self.dropin_dir.exists())
        saved = list((self.root / 'backups').glob('*/staged.failed/30-vpn-nginx-restart.conf'))
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0].read_text(), '# partially installed\n')
        self.run_script()

    def test_check_only_rejects_changed_mode_content_and_extra_dropins(self):
        self.run_script()
        self.dropin.chmod(0o666)
        self.run_script('--check-only', success=False)
        self.dropin.chmod(0o644)
        self.dropin.write_text('# changed\n')
        self.run_script('--check-only', success=False)
        self.dropin.write_bytes(self.source.read_bytes())
        extra = self.dropin_dir / 'unknown.conf'; extra.write_text('# unknown\n')
        self.run_script('--check-only', success=False)

    def test_check_only_rejects_symlink_and_hardlinked_policy(self):
        self.run_script()
        self.dropin.unlink(); self.dropin.symlink_to(self.source)
        self.run_script('--check-only', success=False)
        self.dropin.unlink(); os.link(self.source, self.dropin)
        self.run_script('--check-only', success=False)


if __name__ == '__main__':
    unittest.main()
