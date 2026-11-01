"""Run actual /dev/fd entrypoints without network or host installation changes.

Fresh startup stops at the verified archive's bootstrap import. The existing
resume fixture supplies private older installed source, ownership and manifests.
Both paths execute the real Bash process-substitution launch syntax.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RAW_URL = 'https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/install.sh'
SPEC = importlib.util.spec_from_file_location('vpn_fd_resume_fixture',
                                             ROOT / 'tests/test_resume_dispatch.py')
RESUME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RESUME)

DRIVER = r'''
set -Eeuo pipefail
umask 077
case "$FIXTURE_ROOT" in /tmp/vpn-process-substitution.*) ;; *) exit 98;; esac
cleanup() {
  local status=$?
  trap - EXIT
  for path in "$FIXTURE_ROOT"/task.*; do
    [[ -e $path || -L $path ]] || continue
    [[ -d $path && ! -L $path ]] || exit 99
    rm -rf -- "$path"
  done
  exit "$status"
}
trap cleanup EXIT
export PATH="$FIXTURE_ROOT/bin:/usr/sbin:/usr/bin:/sbin:/bin"
bash <(curl -fsSL "$RAW_URL") "$@"
'''

CURL = r'''#!/bin/bash
set -Eeuo pipefail
url='' output=''
while (($#)); do
  case $1 in
    -o|--output) output=$2; shift 2;;
    https://*) url=$1; shift;;
    *) shift;;
  esac
done
if [[ $url == "$RAW_URL" && -z $output ]]; then
  printf 'RAW\n' >>"$FIXTURE_ROOT/events"
  exec /usr/bin/cat "$FIXTURE_ROOT/raw/install.sh"
elif [[ $url == "$ARCHIVE_URL" ]]; then
  [[ $output == "$FIXTURE_ROOT"/task.*/source.tar.gz &&
     ! -e $output && ! -L $output ]] || exit 91
  printf 'ARCHIVE\n' >>"$FIXTURE_ROOT/events"
  exec /usr/bin/cp -- "$FIXTURE_ROOT/source.tar.gz" "$output"
fi
printf 'UNEXPECTED_NETWORK\n' >>"$FIXTURE_ROOT/events"
exit 92
'''

BOOTSTRAP = r'''#!/bin/bash
[[ $source_dir == "$task_stage/source" && -f $source_dir/tools/wizard.sh ]] || exit 93
printf 'SOURCE_BOOTSTRAP\n' >>"$FIXTURE_ROOT/events"
printf 'FD_VERIFIED_ARCHIVE_BOOTSTRAP_OK=1\n'
# Dry stop: source lookup, extraction and checksum verification are real;
# no questionnaire, package action or persistent bootstrap is run here.
exit 0
'''


@unittest.skipIf(os.name == 'nt', 'Actual root Linux /dev/fd fixtures run in Ubuntu CI')
class ProcessSubstitution(unittest.TestCase):
    def setUp(self):
        # Reuse the existing root/passwordless-sudo policy, including the CI
        # failure when real privileged fixtures would otherwise be skipped.
        RESUME.ResumeDispatch.setUp(self)

    def startup(self, mode=None, corrupt=False):
        with tempfile.TemporaryDirectory(prefix='vpn-process-substitution.', dir='/tmp') as temporary:
            root = Path(temporary).resolve()
            self.assertEqual(root.parent, Path('/tmp'))
            self.assertTrue(root.name.startswith('vpn-process-substitution.'))
            # The outer CI user reads this after sudo returns. Root appends
            # without replacing its original owner or private mode.
            (root / 'events').touch(mode=0o600)
            for directory in ('raw', 'bin', 'archive/tools'):
                (root / directory).mkdir(parents=True)
            source = (ROOT / 'install.sh').read_text(encoding='utf-8')
            replacements = {
                '/var/lib/vpn-installer': str(root / 'state'),
                '/opt/vpn-installer': str(root / 'installed'),
                '/etc/germanyvpn-target.env': str(root / 'target.env'),
                '/run/vpn-installer.lock': str(root / 'installer.lock'),
                '/run/vpn-installer.': str(root / 'task.'),
                '/etc/os-release': str(root / 'os-release'),
            }
            for old, new in replacements.items():
                self.assertIn(old, source)
                source = source.replace(old, new)
            (root / 'raw/install.sh').write_text(source, encoding='utf-8')
            (root / 'archive/install.sh').write_text(source, encoding='utf-8')
            (root / 'archive/tools/bootstrap.sh').write_text(BOOTSTRAP, encoding='utf-8')
            (root / 'archive/tools/preflight.py').write_text(
                'raise RuntimeError("Fresh startup fixture stops before preflight")\n')
            shutil.copyfile(ROOT / 'tools/wizard.sh', root / 'archive/tools/wizard.sh')
            files = sorted(path for path in (root / 'archive').rglob('*') if path.is_file())
            (root / 'archive/SHA256SUMS').write_text(''.join(
                hashlib.sha256(path.read_bytes()).hexdigest() + '  ' +
                path.relative_to(root / 'archive').as_posix() + '\n' for path in files))
            if corrupt:
                with (root / 'archive/tools/bootstrap.sh').open('a') as output:
                    output.write('# changed after manifest\n')
            with tarfile.open(root / 'source.tar.gz', 'w:gz') as archive:
                archive.add(root / 'archive', arcname='VPN-fixture')
            (root / 'os-release').write_text('ID=ubuntu\nVERSION_ID=24.04\n')
            for name, program in (
                ('curl', CURL),
                ('dpkg', '#!/bin/bash\nprintf "amd64\\n"\n'),
                ('ps', '#!/bin/bash\nprintf "systemd\\n"\n'),
                *((name, '#!/bin/bash\nprintf "UNEXPECTED_MUTATION\\n" >>"$FIXTURE_ROOT/events"\nexit 94\n')
                  for name in ('apt-get', 'systemctl', 'ufw', 'nft', 'iptables', 'ip6tables', 'useradd')),
            ):
                path = root / 'bin' / name
                path.write_text(program, encoding='utf-8')
                path.chmod(0o700)
            release = re.search(r"readonly release='([^']+)'", source).group(1)
            environment = dict(os.environ, FIXTURE_ROOT=str(root), RAW_URL=RAW_URL,
                               ARCHIVE_URL='https://github.com/SergeyFromMariupol/VPN/archive/refs/tags/'
                                           + release + '.tar.gz')
            assignments = [name + '=' + environment[name]
                           for name in ('FIXTURE_ROOT', 'RAW_URL', 'ARCHIVE_URL')]
            result = subprocess.run([*self.prefix, 'env', *assignments, 'bash', '-s', '--',
                                     *([mode] if mode else [])], input=DRIVER, text=True,
                                    capture_output=True, env=environment, timeout=30)
            events = (root / 'events').read_text().splitlines() if (root / 'events').exists() else []
            self.assertFalse(any(event.startswith('UNEXPECTED') for event in events),
                             result.stdout + result.stderr + repr(events))
            self.assertFalse(any((root / name).exists() for name in ('state', 'installed', 'target.env')))
            self.assertFalse(list(root.glob('task.*')))
            return result, events, (root / 'installer.lock').exists()

    def test_raw_fd_help_uses_no_archive_or_installer_lock(self):
        result, events, locked = self.startup('--help')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('interactive installation', result.stdout)
        self.assertEqual(events, ['RAW'])
        self.assertFalse(locked)

    def test_raw_fd_fresh_startup_verifies_private_archive_before_bootstrap(self):
        result, events, locked = self.startup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('FD_VERIFIED_ARCHIVE_BOOTSTRAP_OK=1', result.stdout)
        self.assertEqual(events, ['RAW', 'ARCHIVE', 'SOURCE_BOOTSTRAP'])
        self.assertTrue(locked)

    def test_raw_fd_corrupt_archive_never_imports_bootstrap(self):
        result, events, _ = self.startup(corrupt=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('FD_VERIFIED_ARCHIVE_BOOTSTRAP_OK=1', result.stdout)
        self.assertEqual(events, ['RAW', 'ARCHIVE'])

    def test_raw_fd_resume_dispatches_installed_release_offline_before_lock(self):
        original = 'bash "$FIXTURE_ROOT/raw/install.sh" --resume'
        replacement = r'''
curl() {
  [[ $# == 2 && $1 == -fsSL && $2 == 'https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/install.sh' ]] || return 95
  printf raw >"$FIXTURE_ROOT/raw-stream-called"
  cat "$FIXTURE_ROOT/raw/install.sh"
}
stream_result=$(bash <(curl -fsSL 'https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/install.sh') --resume)
printf '%s\n' "$stream_result"
[[ $stream_result == INSTALLED_OLD_RELEASE_RESUMED=1 ]]
'''
        self.assertEqual(RESUME.RUN.count(original), 1)
        driver = RESUME.RUN.replace(original, replacement)
        driver = driver.replace("trap - EXIT\n", "trap - EXIT\n  [[ -f $FIXTURE_ROOT/raw-stream-called ]] || rc=99\n", 1)
        with patch.object(RESUME, 'RUN', driver):
            for case, expected in (('valid', 0), ('missing', 1), ('corrupt', 1)):
                with self.subTest(case=case):
                    RESUME.ResumeDispatch.fixture(self, case, expected)


if __name__ == '__main__':
    unittest.main()
