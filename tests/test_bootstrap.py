"""Actual Bash bootstrap failure/signal fixtures in isolated temporary paths."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

FIXTURE = r'''
set -Eeuo pipefail
umask 077
source "$BOOTSTRAP_LIBRARY"
destination="$FIXTURE_ROOT/opt/vpn-installer"
state="$FIXTURE_ROOT/varlib/vpn-installer"
target_file="$FIXTURE_ROOT/etc/target.env"
source_dir="$FIXTURE_ROOT/source"
task_stage="$FIXTURE_ROOT/task"
published=0
cleanup() {
  local rc=$? failed=0
  trap - EXIT HUP INT TERM
  cleanup_installation_bootstrap || true
  case "$CASE" in
    success|after-commit)
      [[ -d $destination && -d $state/bundle && -f $target_file &&
         -f $state/install-boot-id && -f $state/inventory-before.txt ]] || failed=1
      (cd "$destination"; sha256sum --check --strict SHA256SUMS >/dev/null) || failed=1
      (cd "$state/bundle"; sha256sum --check --strict SOURCE_SHA256SUMS >/dev/null) || failed=1
      ;;
    conflict)
      [[ ! -e $destination && ! -e $state && $(cat "$target_file") == unknown ]] || failed=1
      ;;
    replacement)
      [[ -f $destination/unknown && ! -e $state && ! -e $target_file ]] || failed=1
      ;;
    *)
      [[ ! -e $destination && ! -L $destination && ! -e $state &&
         ! -L $state && ! -e $target_file && ! -L $target_file ]] || failed=1
      ;;
  esac
  # Every path belongs to this root-only fixture; no production path is used.
  case "$FIXTURE_ROOT" in /tmp/vpn-bootstrap-test.*) ;; *) exit 98;; esac
  rm -rf -- "$FIXTURE_ROOT/opt" "$FIXTURE_ROOT/varlib" "$FIXTURE_ROOT/etc" \
    "$FIXTURE_ROOT/replaced-owned"
  (( failed == 0 )) || exit 99
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cp() {
  if [[ $CASE == copy-failure ]]; then command cp "$@"; return 31; fi
  if [[ $CASE == signal-copy ]]; then
    command cp "$@"
    kill -s "$TEST_SIGNAL" "$BASHPID"
    return 0
  fi
  command cp "$@"
}
python3() {
  if [[ $CASE == writer-failure && $1 == */write-target.py ]]; then
    printf 'PARTIAL_TARGET=' >"$2"
    return 32
  fi
  if [[ $CASE == render-failure && $1 == */render.py ]]; then
    printf 'partial render\n' >>"$2/test.sh"
    return 33
  fi
  command python3 "$@"
}
mv() {
  if [[ $CASE == conflict && ${@: -1} == "$target_file" ]]; then
    printf 'unknown\n' >"$target_file"
  fi
  command mv "$@"
  published=$((published + 1))
  if [[ $CASE == signal-publish && $published == "$PUBLISH_NUMBER" ]]; then
    kill -s "$TEST_SIGNAL" "$BASHPID"
  fi
  if [[ $CASE == replacement && $published == 1 ]]; then
    command mv "$destination" "$FIXTURE_ROOT/replaced-owned"
    mkdir "$destination"
    printf 'unknown\n' >"$destination/unknown"
    kill -TERM "$BASHPID"
  fi
}
prepare_installation_bootstrap
if [[ $CASE == after-commit ]]; then kill -TERM "$BASHPID"; fi
'''


@unittest.skipIf(os.name == 'nt', 'Real Bash/root ownership fixture runs in Ubuntu CI')
class BootstrapTransaction(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.bash = ['bash']
        elif shutil.which('sudo') and subprocess.run(
                ['sudo', '-n', 'true'], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL).returncode == 0:
            self.bash = ['sudo', '-n', 'bash']
        else:
            if os.environ.get('CI'):
                self.fail('Ubuntu CI must execute actual root bootstrap fixtures')
            self.skipTest('Root or passwordless sudo required for ownership fixture')

    def run_fixture(self, case, expected, **values):
        with tempfile.TemporaryDirectory(prefix='vpn-bootstrap-test.', dir='/tmp') as temp:
            root = Path(temp)
            for name in ('source/tools', 'source/bundle', 'opt', 'varlib', 'etc', 'task'):
                (root / name).mkdir(parents=True, exist_ok=True)
            for name in ('write-target.py', 'render.py'):
                shutil.copyfile(ROOT / 'tools' / name, root / 'source/tools' / name)
            (root / 'source/bundle/test.sh').write_text('@TARGET_IPV4@ @TARGET_INTERFACE@\n')
            (root / 'task/inventory.txt').write_text('CLEAN_HOST=PASS\n')
            files = sorted(p for p in (root / 'source').rglob('*') if p.is_file())
            (root / 'source/SHA256SUMS').write_text(''.join(
                hashlib.sha256(p.read_bytes()).hexdigest() + '  ' +
                p.relative_to(root / 'source').as_posix() + '\n' for p in files))
            # Match the ordinary file modes encountered in GitHub tarballs.
            for file in (root / 'source').rglob('*'):
                if file.is_file():
                    file.chmod(0o664)
            env = dict(os.environ, BOOTSTRAP_LIBRARY=str(ROOT / 'tools/bootstrap.sh'),
                       FIXTURE_ROOT=temp, CASE=case, TARGET_ADDRESS_MODE='ip',
                       TARGET_IPV4='8.8.4.4', TARGET_FQDN='8.8.4.4', TARGET_INTERFACE='eth0',
                       TARGET_SSH_PORT='22', TARGET_DEVICE_LIMIT='0',
                       TARGET_REALITY_SNI='example.org', TARGET_LABEL='Offline fixture',
                       ACME_EMAIL='admin@example.com', **values)
            # sudo's default environment policy may remove fixture variables.
            assignments = [name + '=' + value for name, value in env.items()
                           if name in ('BOOTSTRAP_LIBRARY', 'FIXTURE_ROOT', 'CASE', 'TEST_SIGNAL',
                                       'PUBLISH_NUMBER', 'TARGET_ADDRESS_MODE', 'TARGET_IPV4',
                                       'TARGET_FQDN', 'TARGET_INTERFACE', 'TARGET_SSH_PORT',
                                       'TARGET_DEVICE_LIMIT', 'TARGET_REALITY_SNI', 'TARGET_LABEL',
                                       'ACME_EMAIL')]
            command = self.bash[:-1] + ['env', *assignments, 'bash']
            result = subprocess.run(command, input=FIXTURE, text=True, capture_output=True,
                                    timeout=30, env=env)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_success_publishes_complete_verified_resumable_state(self):
        self.run_fixture('success', 0)

    def test_copy_writer_and_render_failures_leave_no_managed_paths(self):
        for case, code in (('copy-failure', 31), ('writer-failure', 32), ('render-failure', 33)):
            with self.subTest(case=case):
                self.run_fixture(case, code)

    def test_ordinary_signals_before_and_during_publication_roll_back_owned_paths(self):
        for signal, code in (('HUP', 129), ('INT', 130), ('TERM', 143)):
            with self.subTest(signal=signal, boundary='copy'):
                self.run_fixture('signal-copy', code, TEST_SIGNAL=signal)
            for publication in ('1', '2', '3'):
                with self.subTest(signal=signal, boundary=publication):
                    self.run_fixture('signal-publish', code, TEST_SIGNAL=signal,
                                     PUBLISH_NUMBER=publication)

    def test_committed_state_is_retained_for_resume_after_signal(self):
        self.run_fixture('after-commit', 143)

    def test_unknown_concurrent_paths_are_preserved(self):
        self.run_fixture('conflict', 1)
        self.run_fixture('replacement', 143)


if __name__ == '__main__':
    unittest.main()
