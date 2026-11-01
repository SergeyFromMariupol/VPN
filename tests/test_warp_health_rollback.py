"""Exercise the production WARP health deployment EXIT handler with faults.

Only private fixture metadata is read. Every service and restore operation is
an instrumented Bash function, so the host WARP/network state is untouched.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get('VPN_TEST_BASH') or shutil.which('bash')
SOURCE = ROOT / 'bundle/warp-egress/scripts/deploy-health-watchdog.sh'

DRIVER = r'''
set -Eeuo pipefail
exec 3>"$CALL_LOG"
event() { printf '%s\n' "$*" >&3; }
backup_dir=$PRIVATE_BACKUP
snapshot_complete=1
committed=0
targets=(/fixture/watchdog /fixture/timer /fixture/failure-streak)
active=1
clear_uncommitted_warp_phase_marker() { event clear-marker; }
systemctl() {
  event "systemctl $*"
  case $1 in
    stop)
      [[ $FAULT != stop ]] || return 1
      active=0
      [[ $FAULT != inactive-stop && $FAULT != missing ]] || return 1
      [[ $FAULT != mixed || $2 != *.timer ]] || return 1
      ;;
    show)
      [[ $FAULT != bus ]] || return 1
      if [[ $FAULT == missing || ( $FAULT == mixed && $2 == *.timer ) ]]; then
        printf 'LoadState=not-found\nActiveState=inactive\n'
        return 0
      fi
      printf 'LoadState=loaded\n'
      if [[ $active == 1 ]]; then printf 'ActiveState=active\nMainPID=321\n'
      elif [[ $2 == *.timer ]]; then printf 'ActiveState=inactive\n'
      elif [[ $FAULT == orphan ]]; then printf 'ActiveState=inactive\nMainPID=321\n'
      elif [[ $FAULT == partial ]]; then printf 'ActiveState=inactive\n'
      else printf 'ActiveState=inactive\nMainPID=0\n'; fi
      ;;
  esac
}
rm() { event "rm $*"; [[ $FAULT != rm || ${@: -1} != /fixture/watchdog ]]; }
cp() { event "cp $*"; [[ $FAULT != cp ]]; }
find() { printf '%s\0' "$backup_dir/rootfs/etc"; }
'''


@unittest.skipUnless(BASH, 'Bash is required')
class WarpHealthRollback(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix' and os.environ.get('CI') and shutil.which('systemctl'),
                         'Actual systemd read-back is checked only on Linux CI')
    def test_ci_systemd_missing_service_and_timer_readback(self):
        prefix = 'vpn-installer-audit-nonexistent-' + uuid.uuid4().hex
        for suffix in ('.service', '.timer'):
            with self.subTest(suffix=suffix):
                result = subprocess.run(
                    ['systemctl', 'show', prefix + suffix, '-p', 'LoadState',
                     '-p', 'ActiveState', '-p', 'MainPID'],
                    text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
                self.assertEqual(fields.get('LoadState'), 'not-found', result.stdout)
                self.assertEqual(fields.get('ActiveState'), 'inactive', result.stdout)
                self.assertIn(fields.get('MainPID'), (None, '0'), result.stdout)

    def run_handler(self, fault='', entry=False):
        source = SOURCE.read_text(encoding='utf-8')
        begin = source.index('resume_original_runtime() {')
        end = source.index('\ntrap on_exit EXIT', begin)
        handler = source[begin:end]
        with tempfile.TemporaryDirectory(prefix='vpn-health-rollback-') as temp:
            root = Path(temp)
            (root / 'rootfs/etc').mkdir(parents=True)
            (root / 'timer-enabled-before').write_text('enabled\n', newline='\n')
            (root / 'timer-active-before').write_text('active\n', newline='\n')
            (root / 'service-active-before').write_text('inactive\n', newline='\n')
            if fault in ('missing', 'mixed'):
                (root / 'timer-enabled-before').write_text('disabled\n', newline='\n')
                (root / 'timer-active-before').write_text('inactive\n', newline='\n')
            log = root / 'calls'
            entry_check = ''
            if entry:
                check_start = source.index('\nif ! quiesce_health_units; then')
                check_end = source.index('\nfor target in "${state_targets[@]}";', check_start)
                entry_check = '\nsnapshot_complete=0\n' + source[check_start:check_end]
            result = subprocess.run(
                [BASH, '-s'], input=DRIVER + '\n' + handler +
                '\ntrap on_exit EXIT\n' + entry_check + '\nexit 37\n', text=True,
                capture_output=True, timeout=10,
                env=dict(os.environ, PRIVATE_BACKUP=root.as_posix(),
                         CALL_LOG=log.as_posix(), FAULT=fault))
            return result, log.read_text().splitlines()

    def test_remove_failure_continues_independent_restore_without_starting_partial_state(self):
        result, calls = self.run_handler('rm')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('systemctl daemon-reload', calls)
        self.assertTrue(any(call.startswith('cp ') for call in calls))
        self.assertNotIn('systemctl start krysyuk-warp-health.timer', calls)
        self.assertIn('WARP_HEALTH_AUTO_ROLLBACK_OK=0', result.stderr)

    def test_copy_failure_continues_daemon_reload_and_reports_failed_restore(self):
        result, calls = self.run_handler('cp')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('systemctl daemon-reload', calls)
        self.assertNotIn('systemctl start krysyuk-warp-health.timer', calls)
        self.assertIn('WARP_HEALTH_AUTO_ROLLBACK_OK=0', result.stderr)

    def test_live_or_ambiguous_service_retains_files(self):
        for fault in ('stop', 'inactive-stop', 'bus', 'orphan', 'partial'):
            with self.subTest(fault=fault):
                result, calls = self.run_handler(fault)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(x.startswith(('rm ', 'cp ')) for x in calls))
                self.assertIn('WARP_HEALTH_ROLLBACK_RESOURCES_RETAINED=1', result.stderr)
                self.assertIn('WARP_HEALTH_AUTO_ROLLBACK_OK=0', result.stderr)

    def test_fresh_missing_units_can_be_restored_without_false_stop_failure(self):
        result, calls = self.run_handler('missing')
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertTrue(any(call.startswith('cp ') for call in calls))
        self.assertIn('WARP_HEALTH_AUTO_ROLLBACK_OK=1', result.stderr)
        self.assertNotIn('systemctl start krysyuk-warp-health.timer', calls)

    def test_partial_first_install_checks_each_unit_stop_separately(self):
        result, calls = self.run_handler('mixed')
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertIn('systemctl stop krysyuk-warp-health.timer', calls)
        self.assertIn('systemctl stop krysyuk-warp-health.service', calls)
        self.assertIn('WARP_HEALTH_AUTO_ROLLBACK_OK=1', result.stderr)

    def test_initial_quiescence_rejects_failed_bus_readback_before_snapshot(self):
        result, calls = self.run_handler('bus', entry=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('failed to quiesce', result.stderr)
        self.assertIn('WARP_HEALTH_DEPLOY_ABORTED_BEFORE_SNAPSHOT=1', result.stderr)
        self.assertFalse(any(x.startswith(('rm ', 'cp ')) for x in calls))

    def test_successful_rollback_preserves_initial_failure(self):
        result, calls = self.run_handler()
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertIn('systemctl daemon-reload', calls)
        self.assertIn('systemctl enable krysyuk-warp-health.timer', calls)
        self.assertIn('systemctl start krysyuk-warp-health.timer', calls)
        self.assertIn('WARP_HEALTH_AUTO_ROLLBACK_OK=1', result.stderr)


if __name__ == '__main__':
    unittest.main()
