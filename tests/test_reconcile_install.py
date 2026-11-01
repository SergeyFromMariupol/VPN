"""Execute the certificate retry installer's real publish/cleanup in /tmp."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import re

SOURCE = Path(__file__).resolve().parents[1] / 'bundle/base/install-cert-reconcile.sh'


@unittest.skipUnless(os.name == 'posix' and all(shutil.which(x) for x in
                     ('bash', 'stat', 'install', 'mv', 'mktemp')), 'Linux tools are required')
class ReconcileInstaller(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpn-reconcile-install-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('units', 'backup', 'runtime'):
            (self.root / name).mkdir()
        self.service = self.root / 'units/vpn-cert-reconcile.service'
        self.timer = self.root / 'units/vpn-cert-reconcile.timer'
        self.service_source = self.root / 'service-source'
        self.timer_source = self.root / 'timer-source'
        self.service_source.write_text('[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')
        self.timer_source.write_text('[Timer]\nOnCalendar=hourly\n')

    def run_publication(self, fault=''):
        source = SOURCE.read_text(encoding='utf-8')
        begin = source.index("unit_stage=''") if "unit_stage=''" in source else source.index('cleanup() {')
        functions = source[begin:source.index('\ntrap cleanup EXIT', begin)]
        helper = re.search(r'(?ms)^unit_is_quiescent\(\) \{.*?^\}', source)
        if helper:
            functions = helper.group() + '\n' + functions
        if 'publish_units() {' in functions:
            operation = 'publish_units\n'
        else:
            # Keep the old source runnable to prove partial canonical writes
            # were left behind by the previous implementation's cleanup.
            begin = source.index('install -o root -g root -m 0644 "$service_source" "$service"')
            operation = source[begin:source.index('\nsystemctl daemon-reload', begin)] + '\n'
        script = r'''
set -Eeuo pipefail
umask 077
root=$FIXTURE_ROOT/runtime
backup=$FIXTURE_ROOT/backup
service=$FIXTURE_ROOT/units/vpn-cert-reconcile.service
timer=$FIXTURE_ROOT/units/vpn-cert-reconcile.timer
service_source=$FIXTURE_ROOT/service-source
timer_source=$FIXTURE_ROOT/timer-source
marker=$root/marker
expected_hash=fixture
marker_existed=0
committed=0
certbot_timer_stopped=1
systemctl() {
  printf '%s\n' "$*" >>"$FIXTURE_ROOT/calls"
  case "$TEST_FAULT:$1:${2:-}" in
    reload-failure:daemon-reload:) return 1;;
    timer-stop:disable:--now|service-stop:stop:vpn-cert-reconcile.service) return 1;;
    timer-readback:show:vpn-cert-reconcile.timer|service-readback:show:vpn-cert-reconcile.service) return 1;;
  esac
  if [[ $1 == daemon-reload ]]; then : >"$FIXTURE_ROOT/reloaded"; fi
  if [[ $1 == show ]]; then
    if [[ -e $FIXTURE_ROOT/reloaded ]]; then printf 'LoadState=loaded\n'
    else printf 'LoadState=not-found\n'; fi
    printf 'ActiveState=inactive\n'
    if [[ $TEST_FAULT == service-orphan && $2 == vpn-cert-reconcile.service ]]; then
      printf 'MainPID=321\n'
    elif [[ $TEST_FAULT != service-missing-pid || $2 != vpn-cert-reconcile.service ]]; then
      printf 'MainPID=0\n'
    fi
  fi
  if [[ $1 == is-active && ${@: -1} != certbot.timer ]]; then return 3; fi
}
install() {
  local -a arguments=()
  while (($#)); do
    case $1 in -o|-g) shift 2;; *) arguments+=("$1"); shift;; esac
  done
  if [[ $TEST_FAULT == partial-install && ${arguments[-2]} == "$service_source" ]]; then
    printf 'partial unit\n' >"${arguments[-1]}"
    kill -TERM "$BASHPID"
  fi
  command install "${arguments[@]}"
}
mv() {
  if [[ $TEST_FAULT == foreign-unit && ${@: -1} == "$service" ]]; then
    command cp -- "$service_source" "$service"
  fi
  command mv "$@"
  if [[ $TEST_FAULT == after-publish && ${@: -1} == "$service" ]]; then
    kill -TERM "$BASHPID"
  fi
}
''' + functions + r'''
trap cleanup EXIT
trap 'exit 143' TERM
''' + operation + r'''
case $TEST_FAULT in
  reload-failure|timer-stop|service-stop|timer-readback|service-readback|service-orphan|service-missing-pid)
    printf '%s\n' "$expected_hash" >"$marker"
    exit 37;;
esac
committed=1
'''
        return subprocess.run(['bash', '-s'], input=script, text=True,
                              env=dict(os.environ, FIXTURE_ROOT=str(self.root), TEST_FAULT=fault),
                              capture_output=True, timeout=15)

    def assert_retry(self, fault):
        first = self.run_publication(fault)
        self.assertEqual(first.returncode, 143, first.stdout + first.stderr)
        self.assertIn('CERT_RECONCILE_ROLLBACK_OK=1', first.stderr)
        self.assertFalse(self.service.exists())
        self.assertFalse(self.timer.exists())
        self.assertEqual(list((self.root / 'units').glob('.vpn-*')), [])
        second = self.run_publication()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(self.service.read_bytes(), self.service_source.read_bytes())
        self.assertEqual(self.timer.read_bytes(), self.timer_source.read_bytes())

    def test_partial_unit_install_does_not_leave_untracked_canonical_file(self):
        self.assert_retry('partial-install')
        self.assertEqual((self.root / 'backup/units-staged.failed/service').read_text(), 'partial unit\n')

    def test_term_after_first_unit_publication_rolls_back_and_allows_retry(self):
        self.assert_retry('after-publish')
        self.assertEqual((self.root / 'backup/vpn-cert-reconcile.service.failed').read_bytes(),
                         self.service_source.read_bytes())

    def test_foreign_same_content_unit_is_preserved_and_not_stopped(self):
        result = self.run_publication('foreign-unit')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.service.read_bytes(), self.service_source.read_bytes())
        calls = (self.root / 'calls').read_text()
        self.assertNotIn('stop vpn-cert-reconcile.service', calls)
        self.assertNotIn('disable --now vpn-cert-reconcile.timer', calls)
        self.assertIn('CERT_RECONCILE_ROLLBACK_OK=0', result.stderr)

    def test_unconfirmed_quiescence_preserves_units_and_current_marker(self):
        for fault in ('reload-failure', 'timer-stop', 'service-stop', 'timer-readback',
                      'service-readback', 'service-orphan', 'service-missing-pid'):
            with self.subTest(fault=fault):
                self.setUp()
                result = self.run_publication(fault)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('CERT_RECONCILE_ROLLBACK_OK=0', result.stderr)
                self.assertEqual(self.service.read_bytes(), self.service_source.read_bytes())
                self.assertEqual(self.timer.read_bytes(), self.timer_source.read_bytes())
                self.assertEqual((self.root / 'runtime/marker').read_text(), 'fixture\n')
                self.assertFalse((self.root / 'backup/vpn-cert-reconcile.service.failed').exists())
                self.assertFalse((self.root / 'backup/vpn-cert-reconcile.timer.failed').exists())


if __name__ == '__main__':
    unittest.main()
