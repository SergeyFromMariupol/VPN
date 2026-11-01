"""Run actual foreground phase/checkpoint workers in root-private temporary trees."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

DRIVER = r'''
set -Eeuo pipefail
umask 077
source "$PHASE_LIBRARY"
state=$FIXTURE_ROOT/state
mkdir "$state"
chown root:root "$state"
chmod 0700 "$state"
export state
export INSTALLER_PARENT_PID=$BASHPID
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ $CASE == parent-signal || $CASE == group-signal ]]; then
    installer_checkpoint_valid "$state/direct.done" || status=99
    [[ $(cat "$state/committed") == yes ]] || status=99
    if [[ $CASE == group-signal && $status == 143 ]]; then
      printf 'PHASE_GROUP_SIGNAL_CHECKPOINT_OK=1\n'
    fi
  fi
  case $FIXTURE_ROOT in /tmp/vpn-phase-test.*) ;; *) exit 98;; esac
  rm -rf -- "$state"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
commit() {
  [[ ! -e $state/committed ]] || return 27
  printf yes >"$state/committed"
}
case $CASE in
  success)
    phase direct commit
    installer_checkpoint_valid "$state/direct.done"
    phase direct commit
    [[ $(cat "$state/committed") == yes ]];;
  worker-signal)
    if phase direct bash -c 'printf yes >"$state/committed"; kill -s "$TEST_SIGNAL" "$PPID"'; then
      exit 90
    else rc=$?; fi
    [[ $rc == "$EXPECTED_SIGNAL_STATUS" ]]
    installer_checkpoint_valid "$state/direct.done"
    # A committed non-idempotent command must not be repeated on resume.
    phase direct commit;;
  parent-signal)
    phase direct bash -c 'printf yes >"$state/committed"; kill -s "$TEST_SIGNAL" "$INSTALLER_PARENT_PID"'
    exit 91;;
  group-signal)
    # Python launches this driver in a fresh setsid child. This signal reaches
    # only that disposable process group, never the CI runner or test process.
    [[ $(ps -o pgid= -p "$BASHPID" | tr -d '[:space:]') == "$BASHPID" ]] || exit 96
    phase direct bash -c 'trap "" TERM; printf yes >"$state/committed"; kill -TERM 0'
    exit 91;;
  command-failure)
    if phase direct bash -c 'printf failed; exit 42'; then exit 90; fi
    [[ ! -e $state/direct.done ]]
    [[ $(cat "$state/direct.log") == failed ]]
    phase direct commit
    installer_checkpoint_valid "$state/direct.done";;
  publication-helper-signal)
    date() {
      if [[ -e $state/committed ]]; then
        command bash -c 'kill -TERM "$BASHPID"; exec date "$@"' _ "$@"
      else command date "$@"; fi
    }
    phase direct commit
    unset -f date
    installer_checkpoint_valid "$state/direct.done";;
  cancelled-before-command)
    date() { command date "$@"; kill -TERM "$BASHPID"; }
    if phase direct commit; then exit 90; else rc=$?; fi
    [[ $rc == 143 && ! -e $state/committed && ! -e $state/direct.done ]];;
  cancelled-during-arrow)
    printf() {
      builtin printf "$@"
      if [[ $1 == *'→'* ]]; then kill -TERM "$BASHPID"; fi
    }
    if phase direct commit; then exit 90; else rc=$?; fi
    [[ $rc == 143 && ! -e $state/committed && ! -e $state/direct.done ]];;
  invalid-marker)
    printf '2026-11-01T00:00:00Z\n' >"$state/direct.done"
    case $MARKER_KIND in
      empty) : >"$state/direct.done";;
      malformed) printf '2026-99-99T00:00:00Z\n' >"$state/direct.done";;
      extra-line) printf '\n' >>"$state/direct.done";;
      mode) chmod 0644 "$state/direct.done";;
      owner) chown 65534:65534 "$state/direct.done";;
      hardlink) ln "$state/direct.done" "$state/foreign";;
      symlink) mv "$state/direct.done" "$state/foreign"; ln -s foreign "$state/direct.done";;
      directory) rm "$state/direct.done"; mkdir "$state/direct.done";;
    esac
    before=$(stat -c '%d:%i' "$state/direct.done")
    if phase direct commit; then exit 90; fi
    [[ ! -e $state/committed && $(stat -c '%d:%i' "$state/direct.done") == "$before" ]];;
  invalid-log)
    printf preserve >"$state/foreign"
    if [[ $MARKER_KIND == symlink ]]; then ln -s foreign "$state/direct.log"
    else ln "$state/foreign" "$state/direct.log"; fi
    if phase direct commit; then exit 90; fi
    [[ ! -e $state/committed && $(cat "$state/foreign") == preserve ]];;
  always)
    count() { printf x >>"$state/count"; }
    phase --always verify count
    before=$(stat -c '%d:%i' "$state/verify.done")
    phase --always verify count
    installer_checkpoint_valid "$state/verify.done"
    [[ $(cat "$state/count") == xx && $(stat -c '%d:%i' "$state/verify.done") != "$before" ]];;
  foreign-marker)
    foreign_commit() { printf '2020-01-01T00:00:00Z\n' >"$state/direct.done"; }
    if phase direct foreign_commit; then exit 90; fi
    [[ $(cat "$state/direct.done") == 2020-01-01T00:00:00Z ]];;
  *) exit 97;;
esac
[[ -z $(find "$state" -maxdepth 1 -name '.*.done.*' -print -quit) ]]
printf 'PHASE_FIXTURE_OK=%s\n' "$CASE"
'''


@unittest.skipIf(os.name == 'nt', 'Actual root Bash phase fixtures run in Ubuntu CI')
class PhaseCheckpoints(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.prefix = []
        elif shutil.which('sudo') and subprocess.run(['sudo', '-n', 'true'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            self.prefix = ['sudo', '-n']
        else:
            if os.environ.get('CI'): self.fail('Ubuntu CI must run root phase fixtures')
            self.skipTest('Root or passwordless sudo required')

    def fixture(self, case, expected=0, **values):
        with tempfile.TemporaryDirectory(prefix='vpn-phase-test.', dir='/tmp') as temp:
            command = [*self.prefix, 'env', 'FIXTURE_ROOT=' + temp, 'CASE=' + case,
                       'PHASE_LIBRARY=' + str(ROOT/'tools/phases.sh'),
                       *(name+'='+str(value) for name, value in values.items())]
            command += ['setsid', '--fork', '--wait', 'bash'] if case == 'group-signal' else ['bash']
            result = subprocess.run(command, input=DRIVER, text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, expected, result.stdout+result.stderr)
            if expected == 0: self.assertIn('PHASE_FIXTURE_OK='+case, result.stdout)
            if case == 'group-signal':
                self.assertIn('PHASE_GROUP_SIGNAL_CHECKPOINT_OK=1', result.stdout)

    def test_committed_success_is_checkpointed_and_not_repeated(self):
        self.fixture('success')

    def test_signal_after_child_commit_cannot_lose_checkpoint(self):
        for sig, status in (('HUP', 129), ('INT', 130), ('TERM', 143)):
            with self.subTest(signal=sig, recipient='worker'):
                self.fixture('worker-signal', TEST_SIGNAL=sig, EXPECTED_SIGNAL_STATUS=status)
            with self.subTest(signal=sig, recipient='parent'):
                self.fixture('parent-signal', status, TEST_SIGNAL=sig)

    def test_failed_or_cancelled_command_never_gets_success_checkpoint(self):
        self.fixture('command-failure')
        self.fixture('cancelled-before-command')
        self.fixture('cancelled-during-arrow')

    def test_disposable_terminal_group_signal_preserves_success_checkpoint(self):
        self.fixture('group-signal', 143)

    def test_publication_helpers_cannot_be_interrupted_after_command_success(self):
        self.fixture('publication-helper-signal')

    def test_invalid_checkpoints_fail_before_running_or_replacing_them(self):
        for kind in ('empty', 'malformed', 'extra-line', 'mode', 'owner', 'hardlink', 'symlink', 'directory'):
            with self.subTest(kind=kind): self.fixture('invalid-marker', MARKER_KIND=kind)

    def test_log_links_cannot_overwrite_unowned_files(self):
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind): self.fixture('invalid-log', MARKER_KIND=kind)

    def test_verify_always_runs_with_atomic_checkpoint_update(self):
        self.fixture('always')

    def test_concurrent_checkpoint_is_not_overwritten(self):
        self.fixture('foreign-marker')


if __name__ == '__main__':
    unittest.main()
