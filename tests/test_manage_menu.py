"""Run the real root menu and launcher against isolated files and commands."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = r"""
import atexit, fcntl, hashlib, json, os, pathlib, shlex, shutil, subprocess, sys

settings = json.loads(sys.argv[1])
root = pathlib.Path(settings['root']).resolve()
assert root.parent == pathlib.Path('/tmp') and root.name.startswith('vpn-manage-menu.')
os.umask(0o077)
source, state, binary = (root / name for name in ('source', 'state', 'bin'))
runtime = state / 'bundle'
target, events, lock = (root / name for name in ('target.env', 'events', 'installer.lock'))
production = pathlib.Path(settings['production'])

def cleanup():
    # The outer TemporaryDirectory belongs to the ordinary test user, whereas
    # these children are root0700. Remove only the fixed private fixture paths
    # while the root helper still owns them so CI can remove its outer folder.
    for path in (source, state, binary, root / 'sbin'):
        assert path.parent == root
        if path.is_symlink(): path.unlink()
        elif path.exists(): shutil.rmtree(path)
    for path in (target, events, lock, root / 'install-menu.sh'):
        path.unlink(missing_ok=True)

atexit.register(cleanup)

def write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    path.chmod(mode)

def manifest(directory, name):
    paths = [path for path in sorted(directory.rglob('*')) if path.is_file() and path.name != name]
    write(directory / name, ''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' +
          path.relative_to(directory).as_posix() + '\n' for path in paths))

for path in (source, state, runtime, binary):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
replacements = {'/opt/vpn-installer': str(source), '/var/lib/vpn-installer': str(state),
                '/run/vpn-installer.lock': str(lock), '/var/www/vpn-decoy/public': str(root / 'public')}
manager = (production / 'tools/manage.sh').read_text()
for old, new in replacements.items():
    assert old in manager, old
    manager = manager.replace(old, new)
write(source / 'tools/manage.sh', manager)
shell = '#!/bin/bash\nset -Eeuo pipefail\n'
write(source / 'install.sh', shell + '''
printf 'INSTALL:%s\\n' "$1" >>"$FIXTURE_EVENTS"
case $1 in --verify) printf 'FIXTURE_VERIFIED\\n';; --show-access) printf 'FIXTURE_EXPLICIT_ACCESS\\n';; *) exit 91;; esac
''')
values = dict(TARGET_IPV4='8.8.4.4', TARGET_FQDN='vpn.example.org', TARGET_ADDRESS_MODE='domain',
              TARGET_INTERFACE='ens3', TARGET_SSH_PORT='2222', TARGET_DEVICE_LIMIT='0',
              TARGET_LABEL='Fixture VPN', TARGET_REALITY_MODE=settings.get('mode', 'decoy'),
              TARGET_REALITY_SNI='max.ru', TARGET_TLS_MODE='letsencrypt')
if settings.get('ip'):
    values.update(TARGET_FQDN='8.8.4.4', TARGET_ADDRESS_MODE='ip')
write(target, ''.join(key + '=' + shlex.quote(value) + '\n' for key, value in values.items()))
contract = (production / 'bundle/scripts/target-contract.sh').read_text()
write(runtime / 'scripts/target-contract.sh', contract.replace('/etc/germanyvpn-target.env', str(target)))
write(runtime / 'scripts/manage-reality.py', '''import json,os,sys
if sys.argv[1:]==['--recover']:
    with open(os.environ['FIXTURE_EVENTS'],'a') as stream: stream.write('RECOVER\\n')
    print('FIXTURE_RECOVERED=1')
    sys.exit(0)
value=json.load(sys.stdin)
assert set(value)=={'mode','sni'}
with open(os.environ['FIXTURE_EVENTS'],'a') as stream:
    stream.write('SNI:'+json.dumps({'argv':sys.argv[1:],'value':value})+'\\n')
print('FIXTURE_SNI_OK=1')
''')
write(runtime / 'base/install-reality-decoy.sh', shell + '''
if flock -n "$FIXTURE_LOCK" true; then printf 'MUTATION_WITHOUT_INSTALLER_LOCK\\n' >&2; exit 92; fi
case $1 in --reset-page|--enable-php) ;; *) exit 93;; esac
printf 'BACKEND:%s\\n' "$1" >>"$FIXTURE_EVENTS"
''')
write(binary / 'systemctl', shell + 'printf "SERVICE:%s\\n" "$*" >>"$FIXTURE_EVENTS"\nprintf "active\\n"\n', 0o700)
if settings.get('pending_during_lock'):
    write(binary / 'flock', '#!/usr/bin/python3\n'+r'''
import os, pathlib, subprocess, sys
a=sys.argv[1:]
fds=(8,) if a==['-n','8'] else ()
result=subprocess.run([os.environ['FIXTURE_REAL_FLOCK'],*a],pass_fds=fds)
if result.returncode==0 and a==['-n','8']:
    # The parent shell owns the same descriptor. Verify that recovery becomes
    # pending while that lock is actually held, not in an unlocked precheck.
    check=subprocess.run([os.environ['FIXTURE_REAL_FLOCK'],'-n',os.environ['FIXTURE_LOCK'],'true'])
    if check.returncode==0:sys.exit(96)
    pathlib.Path(os.environ['FIXTURE_PENDING']).write_text('new pending recovery')
sys.exit(result.returncode)
''',0o700)
manifest(source, 'SHA256SUMS')
manifest(runtime, 'SOURCE_SHA256SUMS')
environment = dict(os.environ, PATH=str(binary)+':/usr/sbin:/usr/bin:/sbin:/bin',
                   FIXTURE_EVENTS=str(events), FIXTURE_LOCK=str(lock),
                   FIXTURE_REAL_FLOCK=shutil.which('flock'),
                   FIXTURE_PENDING=str(state / 'reality-management.pending'))
if settings.get('pending'):
    write(state / 'reality-management.pending', 'private snapshot fixture')
if settings.get('tamper'):
    path = source / 'install.sh' if settings['tamper']=='source' else runtime / 'scripts/manage-reality.py'
    path.write_text(path.read_text()+'\n# changed after manifest\n')
if settings.get('writable'):
    (source / 'install.sh').chmod(0o622)

guard = None
if settings.get('busy'):
    guard = lock.open('w')
    fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
command = ['/bin/bash', str(source / 'tools/manage.sh'), *settings.get('arguments', [])]
installer_results = []
if settings.get('launcher'):
    sbin = root / 'sbin'
    sbin.mkdir(mode=0o700)
    installer = (production / 'bundle/base/install-menu.sh').read_text()
    installer = installer.replace('/usr/local/sbin', str(sbin)).replace('/opt/vpn-installer', str(source))
    write(root / 'install-menu.sh', installer)
    launcher = sbin / 'vpn'
    if settings.get('foreign'):
        write(launcher, 'foreign command\n', 0o755)
    for argument in ('--apply','--apply','--check-only'):
        process = subprocess.run(['/bin/bash', str(root / 'install-menu.sh'), argument],
                                 env=environment, capture_output=True, text=True, timeout=10)
        installer_results.append([process.returncode, process.stdout+process.stderr])
    if settings.get('foreign'):
        print(json.dumps({'installer':installer_results,'contents':launcher.read_text()}))
        sys.exit(0)
    command = ['/bin/bash', str(launcher), *settings.get('arguments', [])]
try:
    result = subprocess.run(command, input=settings.get('input',''), env=environment,
                            text=True, capture_output=True, timeout=20)
finally:
    if guard is not None: guard.close()
print(json.dumps({'exit':result.returncode,'output':result.stdout+result.stderr,
                  'events':events.read_text().splitlines() if events.exists() else [],
                  'installer':installer_results,
                  'injected':(root / 'injected').exists()}))
"""


@unittest.skipIf(os.name == 'nt', 'Actual root launcher fixtures run in Ubuntu CI')
class ManageMenu(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.prefix = []
        elif shutil.which('sudo') and subprocess.run(['sudo', '-n', 'true'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            self.prefix = ['sudo', '-n']
        else:
            self.skipTest('Root or passwordless sudo required')

    def fixture(self, **settings):
        with tempfile.TemporaryDirectory(prefix='vpn-manage-menu.', dir='/tmp') as directory:
            result = subprocess.run([*self.prefix, 'python3', '-I', '-B', '-c', RUNNER,
                                     json.dumps(dict(settings, root=directory, production=str(ROOT)))],
                                    text=True, capture_output=True, timeout=55)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            return json.loads(result.stdout)

    def test_menu_does_not_show_access_or_change_services_without_action(self):
        result = self.fixture(input='0\n')
        self.assertEqual(result['exit'], 0, result['output'])
        self.assertIn('VPN — управление', result['output'])
        self.assertNotIn('FIXTURE_EXPLICIT_ACCESS', result['output'])
        self.assertEqual(result['events'], [])

    def test_status_verify_and_access_dispatch_only_explicit_actions(self):
        status = self.fixture(arguments=['status'])
        self.assertEqual(status['exit'], 0, status['output'])
        self.assertIn('Клиентский SNI: max.ru', status['output'])
        self.assertEqual(status['events'], ['SERVICE:is-active x-ui.service', 'SERVICE:is-active nginx.service'])
        for action, argument, marker in (('verify','--verify','FIXTURE_VERIFIED'),
                                          ('access','--show-access','FIXTURE_EXPLICIT_ACCESS')):
            with self.subTest(action=action):
                result = self.fixture(arguments=[action])
                self.assertEqual(result['exit'], 0, result['output'])
                self.assertIn(marker, result['output'])
                self.assertEqual(result['events'], ['INSTALL:'+argument])

    def test_sni_settings_travel_over_stdin_and_keep_max_manual(self):
        result = self.fixture(arguments=['sni'], input='2\nmax.ru\n')
        self.assertEqual(result['exit'], 0, result['output'])
        self.assertIn('SNI остаётся виден', result['output'])
        self.assertEqual([json.loads(value.removeprefix('SNI:')) for value in result['events']],
                         [{'argv':[argument], 'value':{'mode':'decoy','sni':'max.ru'}}
                          for argument in ('--check-only','--apply')])
        self.assertFalse(result['injected'])

    def test_ip_installation_rejects_self_steal_without_changing_endpoint(self):
        result = self.fixture(arguments=['sni'], ip=True, input='1\n2\nmax.ru\n')
        self.assertEqual(result['exit'], 0, result['output'])
        self.assertIn('Для self-steal нужен доменный адрес установки.', result['output'])
        self.assertTrue(all(json.loads(value[4:])['value']['mode']=='decoy' for value in result['events']))

    def test_pending_recovery_is_visible_but_runs_only_after_explicit_action(self):
        idle = self.fixture(pending=True, input='0\n')
        self.assertEqual(idle['exit'], 0, idle['output'])
        self.assertIn('Есть незавершённая смена SNI: vpn recover', idle['output'])
        self.assertEqual(idle['events'], [])
        recovered = self.fixture(pending=True, arguments=['recover'])
        self.assertEqual(recovered['exit'], 0, recovered['output'])
        self.assertEqual(recovered['events'], ['RECOVER'])
        absent = self.fixture(arguments=['recover'])
        self.assertEqual(absent['exit'], 0, absent['output'])
        self.assertEqual(absent['events'], [])

    def test_site_reset_and_php_hold_the_installer_lock(self):
        for arguments, answer, expected in ((['site'],'1\n','--reset-page'),
                                             (['php'],'','--enable-php')):
            with self.subTest(action=arguments):
                result = self.fixture(arguments=arguments, input=answer)
                self.assertEqual(result['exit'], 0, result['output'])
                self.assertEqual(result['events'], ['BACKEND:'+expected])
        inactive = self.fixture(arguments=['php'], mode='external')
        self.assertNotEqual(inactive['exit'], 0)
        self.assertEqual(inactive['events'], [])

    def test_pending_sni_recovery_blocks_php_and_site_reset_without_mutating_backend(self):
        for arguments, answer in ((['site'], '1\n'), (['php'], '')):
            with self.subTest(action=arguments):
                result = self.fixture(arguments=arguments, input=answer, pending=True)
                self.assertNotEqual(result['exit'], 0, result['output'])
                self.assertIn('vpn recover', result['output'])
                self.assertEqual(result['events'], [])

    def test_pending_created_during_lock_acquisition_is_checked_before_backend_action(self):
        for arguments, answer in ((['site'], '1\n'), (['php'], '')):
            with self.subTest(action=arguments):
                result = self.fixture(arguments=arguments, input=answer, pending_during_lock=True)
                self.assertNotEqual(result['exit'], 0, result['output'])
                self.assertIn('vpn recover', result['output'])
                self.assertEqual(result['events'], [])

    def test_tampered_files_unsafe_permissions_and_busy_installer_block_actions(self):
        for settings in ({'tamper':'source'},{'tamper':'runtime'}, {'writable':True}, {'busy':True}):
            with self.subTest(settings=settings):
                result = self.fixture(arguments=['access'], **settings)
                self.assertNotEqual(result['exit'], 0)
                self.assertNotIn('FIXTURE_EXPLICIT_ACCESS', result['output'])
                self.assertEqual(result['events'], [])

    def test_launcher_is_idempotent_checks_integrity_and_preserves_foreign_command(self):
        result = self.fixture(launcher=True, arguments=['status'])
        self.assertEqual(result['exit'], 0, result['output'])
        self.assertTrue(all(item[0]==0 for item in result['installer']), result['installer'])
        tampered = self.fixture(launcher=True, arguments=['access'], tamper='source')
        self.assertNotEqual(tampered['exit'], 0)
        self.assertEqual(tampered['events'], [])
        foreign = self.fixture(launcher=True, foreign=True)
        self.assertTrue(all(item[0]!=0 for item in foreign['installer']))
        self.assertEqual(foreign['contents'], 'foreign command\n')


if __name__ == '__main__':
    unittest.main()
