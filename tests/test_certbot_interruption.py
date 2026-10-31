"""Run the actual Certbot installer in a private tree with injected signals.

Only paths, ownership expectations and external package/service commands are
substituted. No host unit, package, certificate or network is changed.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
try:
    import pwd
    import grp
except ImportError:
    pwd = grp = None


SOURCE = Path(__file__).resolve().parents[1] / 'bundle/base/install-certbot.sh'


@unittest.skipUnless(os.name == 'posix' and pwd is not None and
                     all(shutil.which(v) for v in ('bash', 'stat', 'flock', 'sha256sum')),
                     'Linux Bash filesystem fixtures are required')
class CertbotInterruption(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpn-certbot-interruption-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.base = self.root / 'base'
        self.venv = self.root / 'opt/vpn-certbot'
        self.shim = self.root / 'usr/local/bin/certbot'
        self.service = self.root / 'etc/systemd/system/certbot.service.d'
        self.timer = self.root / 'etc/systemd/system/certbot.timer.d'
        self.stopped = self.root / 'timer-stopped'
        self.fired = self.root / 'fault-fired'
        self.calls = self.root / 'calls.log'
        for p in (self.bin, self.base, self.venv.parent, self.shim.parent,
                  self.service.parent, self.root / 'run', self.root / 'backups'):
            p.mkdir(parents=True, exist_ok=True)
        (self.base / 'certbot-requirements.txt').write_text('# offline fixture\n')
        (self.base / 'verify-certbot.py').write_text('# external verifier is mocked\n')
        os_release = self.root / 'os-release'
        os_release.write_text('ID=ubuntu\nVERSION_ID=24.04\n')
        uid, gid = os.getuid(), os.getgid()
        script = SOURCE.read_text(encoding='utf-8')
        substitutions = {
            '/opt/vpn-certbot': self.venv.as_posix(),
            '/usr/local/bin/certbot': self.shim.as_posix(),
            '/etc/systemd/system': self.service.parent.as_posix(),
            '/run/vpn-certbot-install': (self.root / 'run/lock').as_posix(),
            '/var/backups': (self.root / 'backups').as_posix(),
            'source /etc/os-release': 'source ' + os_release.as_posix(),
            '$EUID == 0': f'$EUID == {uid}',
            ') == 0 ]]': f') == {uid} ]]',
            ') == 0 &&': f') == {uid} &&',
            '0:0:700': f'{uid}:{gid}:700',
            '0:0:600:1': f'{uid}:{gid}:600:1',
            '0:0:755': f'{uid}:{gid}:755',
            '0:0:644:1': f'{uid}:{gid}:644:1',
            '! -user root': '! -user ' + pwd.getpwuid(uid).pw_name,
        }
        for old, new in substitutions.items():
            self.assertIn(old, script)
            script = script.replace(old, new)
        # Retain compatibility when reproducing the former install-d window.
        script = script.replace('-o root -g root', '-o ' + pwd.getpwuid(uid).pw_name +
                                ' -g ' + grp.getgrgid(gid).gr_name)
        self.script = self.base / 'install-certbot.sh'
        self.script.write_text(script, encoding='utf-8')
        inject = '''
inject() {
  if [ "$VPN_TEST_FAULT" = "$1" ] && [ ! -e "$VPN_TEST_FIRED" ]; then
    : >"$VPN_TEST_FIRED"
    kill -TERM "$PPID"
    sleep .1
  fi
}
'''
        (self.bin / 'dpkg').write_text('#!/bin/sh\nprintf "amd64\\n"\n')
        (self.bin / 'systemctl').write_text('''#!/bin/sh
printf '%s\\n' "$*" >>"$VPN_TEST_CALLS"
''' + inject + '''
case "$1:$2" in
  is-enabled:certbot.timer) exit 0;;
  is-active:certbot.service) exit 3;;
  is-active:certbot.timer) test ! -e "$VPN_TEST_STOPPED"; exit $?;;
  stop:certbot.timer) : >"$VPN_TEST_STOPPED"; inject stop-timer; exit 0;;
  start:certbot.timer) rm -f "$VPN_TEST_STOPPED"; exit 0;;
  show:-p)
    case "$3" in
      ExecStart) printf '%s/bin/certbot -q renew\\n' "$VPN_TEST_VENV";;
      DropInPaths)
        for arg do last=$arg; done
        case "$last" in
          certbot.service) printf '%s/20-vpn-certbot.conf\\n' "$VPN_TEST_SERVICE";;
          certbot.timer) printf '%s/20-vpn-certbot.conf\\n' "$VPN_TEST_TIMER";;
        esac;;
    esac;;
esac
exit 0
''')
        (self.bin / 'python3').write_text('''#!/bin/sh
if [ "$1:$2" = -I:-c ]; then printf '3.12\\n'; exit 0; fi
if [ "$1:$2:$3" = -I:-m:venv ]; then
  mkdir -p "$4/bin"
  cp "$VPN_TEST_PYTHON" "$4/bin/python"
  cp "$VPN_TEST_CERTBOT" "$4/bin/certbot"
fi
exit 0
''')
        certbot = self.root / 'certbot-command'
        certbot.write_text('''#!/bin/sh
if [ "$1" = --version ]; then printf 'certbot 5.9.0\\n'; else printf '%s\\n' --ip-address --required-profile; fi
''')
        certbot.chmod(0o755)
        real_mv, real_ln, real_install = map(shutil.which, ('mv', 'ln', 'install'))
        (self.bin / 'mv').write_text('#!/bin/sh\n' + inject + f'''
for arg do last=$arg; done
if [ "$last" = "$VPN_TEST_SHIM" ]; then
  case "$VPN_TEST_FAULT" in
    foreign-shim) printf 'foreign file\\n' >"$VPN_TEST_SHIM";;
    foreign-identical-shim) {real_ln} -s "$VPN_TEST_VENV/bin/certbot" "$VPN_TEST_SHIM";;
  esac
fi
{real_mv} "$@" || exit $?
case "$last" in
  "$VPN_TEST_VENV") inject venv;;
  "$VPN_TEST_SERVICE") inject service;;
  "$VPN_TEST_TIMER") inject timer;;
  "$VPN_TEST_SHIM") inject shim;;
esac
''')
        (self.bin / 'ln').write_text('#!/bin/sh\n' + inject + f'''
for arg do last=$arg; done
if [ "$VPN_TEST_FAULT" = foreign-shim ] && [ "$last" = "$VPN_TEST_SHIM" ]; then
  printf 'foreign file\\n' >"$VPN_TEST_SHIM"
fi
{real_ln} "$@" || exit $?
[ "$last" != "$VPN_TEST_SHIM" ] || inject shim
''')
        # Also catch the former install-d -> stat ownership gap, so the same
        # fixtures fail when run against the previous installer implementation.
        (self.bin / 'install').write_text('#!/bin/sh\n' + inject + f'''
{real_install} "$@" || exit $?
for arg do last=$arg; done
case "$last" in
  "$VPN_TEST_VENV") inject venv;;
  "$VPN_TEST_SERVICE") inject service;;
  "$VPN_TEST_TIMER") inject timer;;
esac
''')
        for p in self.bin.iterdir():
            p.chmod(0o755)
        self.environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                                VPN_TEST_CALLS=str(self.calls), VPN_TEST_STOPPED=str(self.stopped),
                                VPN_TEST_FIRED=str(self.fired), VPN_TEST_VENV=str(self.venv),
                                VPN_TEST_SERVICE=str(self.service), VPN_TEST_TIMER=str(self.timer),
                                VPN_TEST_SHIM=str(self.shim), VPN_TEST_PYTHON=str(self.bin / 'python3'),
                                VPN_TEST_CERTBOT=str(certbot))

    def run_installer(self, fault=''):
        return subprocess.run(['bash', str(self.script), '--apply'],
                              env=dict(self.environment, VPN_TEST_FAULT=fault),
                              capture_output=True, text=True, timeout=20)

    def interrupted_then_resume(self, fault):
        first = self.run_installer(fault)
        self.assertTrue(self.fired.exists(), (fault, first.stderr))
        self.assertNotEqual(first.returncode, 0)
        self.assertIn('CERTBOT_ROLLBACK_OK=1', first.stderr)
        self.assertFalse(self.stopped.exists(), 'original timer must be restored')
        for p in (self.venv, self.service, self.timer, self.shim):
            self.assertFalse(p.exists() or p.is_symlink(), str(p))
        second = self.run_installer()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertTrue(self.shim.is_symlink())
        self.assertFalse(self.stopped.exists())

    def test_signal_after_shim_creation_allows_resume(self):
        self.interrupted_then_resume('shim')

    def test_signal_after_venv_directory_publication_allows_resume(self):
        self.interrupted_then_resume('venv')

    def test_signal_after_service_directory_publication_allows_resume(self):
        self.interrupted_then_resume('service')

    def test_signal_after_timer_directory_publication_allows_resume(self):
        self.interrupted_then_resume('timer')

    def test_signal_after_stopping_timer_restores_timer(self):
        self.interrupted_then_resume('stop-timer')

    def test_concurrent_foreign_shim_is_preserved(self):
        result = self.run_installer('foreign-shim')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CERTBOT_ROLLBACK_OK=0', result.stderr)
        self.assertEqual(self.shim.read_text(), 'foreign file\n')
        self.assertFalse(self.stopped.exists())

    def test_concurrent_identical_foreign_symlink_is_preserved(self):
        result = self.run_installer('foreign-identical-shim')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CERTBOT_ROLLBACK_OK=0', result.stderr)
        self.assertTrue(self.shim.is_symlink())
        self.assertEqual(self.shim.readlink(), self.venv / 'bin/certbot')
        self.assertFalse(self.stopped.exists())


if __name__ == '__main__':
    unittest.main()
