"""Run production EXIT handlers with failed restore commands and service stops.

Every external operation is an instrumented Bash function. Only the private
metadata fixture and call log are real files; no host services/paths are used.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get('VPN_TEST_BASH') or shutil.which('bash')
SCRIPTS = {'panel': ROOT / 'bundle/scripts/expose-panel-https.sh',
           'direct': ROOT / 'bundle/scripts/configure-standalone.sh'}

DRIVER = r'''
set -Eeuo pipefail
exec 3>"$CALL_LOG"
event() { printf '%s\n' "$*" >&3; }
stage=/fixture/stage
backup=$PRIVATE_BACKUP
committed=0
failure_line=fixture
runtime_root=/fixture/runtime
decoy_root=/fixture/decoy
renew_hook=/fixture/renew-hook
nginx_config=/fixture/nginx-config
access_file=/fixture/access.env
active=1
enabled=enabled
systemctl() {
  event "systemctl $*"
  case $1 in
    stop|disable)
      [[ $FAULT != stop && $FAULT != bus ]] || return 1
      active=0
      [[ $1 != disable ]] || enabled=disabled
      ;;
    enable) enabled=enabled ;;
    is-active) [[ $FAULT != bus && $active == 1 ]]; return $? ;;
    is-enabled) printf '%s\n' "$enabled"; [[ $enabled == enabled ]]; return $? ;;
    show)
      [[ $FAULT != readback && $FAULT != bus ]] || return 1
      printf 'LoadState=loaded\n'
      if [[ $active == 1 ]]; then printf 'ActiveState=active\nMainPID=321\n'
      elif [[ $FAULT == orphan ]]; then printf 'ActiveState=inactive\nMainPID=321\n'
      elif [[ $FAULT == partial ]]; then printf 'ActiveState=inactive\n'
      else printf 'ActiveState=inactive\nMainPID=0\n'; fi
      ;;
  esac
}
rm() { event "rm $*"; }
tar() { event "tar $*"; [[ $FAULT != tar ]]; }
install() {
  event "install $*"
  if [[ $FAULT == install-access && ${@: -1} == "$access_file" ]]; then return 1; fi
}
ufw() {
  event "ufw $*"
  if [[ $1 == status ]]; then printf 'Status: inactive\n'; fi
}
sqlite3() {
  event "sqlite3 $*"
  if [[ $* == *quick_check* ]]; then
    if [[ $FAULT == corrupt-db ]]; then printf 'corruption detected\n'; else printf 'ok\n'; fi
  else printf '0\n'; fi
}
cmp() { event "cmp $*"; }
grep() { return 0; }
cat() { printf 'enabled\n'; }
sed() { local line=''; IFS= read -r line; printf '%s\n' "$line"; }
'''


@unittest.skipUnless(BASH, 'Bash is required')
class ProvisionRollback(unittest.TestCase):
    def run_handler(self, kind, fault='', source=None):
        source = source if source is not None else SCRIPTS[kind].read_text(encoding='utf-8')
        begin = source.index('transaction_exit() {')
        end = source.index("\ntrap 'failure_line=$LINENO' ERR", begin)
        handler = source[begin:end]
        with tempfile.TemporaryDirectory(prefix='vpn-provision-rollback-') as temp:
            root = Path(temp)
            (root / 'x-ui.db.meta').write_text('0:0:600\n', newline='\n')
            log = root / 'calls'
            script = DRIVER + '\n' + handler + '\ntrap transaction_exit EXIT\nexit 37\n'
            result = subprocess.run([BASH, '-s'], input=script, text=True,
                                    capture_output=True, timeout=10,
                                    env=dict(os.environ, PRIVATE_BACKUP=root.as_posix(),
                                             CALL_LOG=log.as_posix(), FAULT=fault))
            return result, log.read_text().splitlines()

    def test_panel_restore_error_does_not_abandon_firewall_recovery(self):
        result, calls = self.run_handler('panel', 'install-access')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('PANEL_ROLLBACK_OK=0', result.stderr)
        self.assertTrue(any(x.startswith('install ') and x.endswith('/etc/ufw/user.rules') for x in calls))
        self.assertIn('ufw reload', calls)

    def test_direct_archive_failure_does_not_abandon_firewall_recovery(self):
        result, calls = self.run_handler('direct', 'tar')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('STANDALONE_ROLLBACK_OK=0', result.stderr)
        self.assertIn('ufw --force disable', calls)
        self.assertIn('systemctl daemon-reload', calls)
        self.assertTrue(any(x.startswith('sqlite3 ') and 'quick_check' in x for x in calls))

    def test_live_xui_stop_failure_retains_runtime_and_firewall(self):
        result, calls = self.run_handler('direct', 'stop')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('STANDALONE_ROLLBACK_RUNTIME_RETAINED=1', result.stderr)
        self.assertIn('STANDALONE_ROLLBACK_OK=0', result.stderr)
        self.assertFalse(any(x.startswith(('rm ', 'tar ', 'install ', 'ufw ')) for x in calls))

    def test_live_nginx_stop_failure_retains_configuration_but_closes_panel_rule(self):
        result, calls = self.run_handler('panel', 'stop')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('PANEL_ROLLBACK_NGINX_RESOURCES_RETAINED=1', result.stderr)
        self.assertIn('PANEL_ROLLBACK_OK=0', result.stderr)
        self.assertFalse(any(x.startswith('tar ') or '/fixture/renew-hook' in x for x in calls))
        self.assertIn('ufw reload', calls)

    def test_sqlite_corruption_is_not_reported_as_successful_restore(self):
        result, calls = self.run_handler('direct', 'corrupt-db')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('STANDALONE_ROLLBACK_OK=0', result.stderr)
        self.assertIn('ufw --force disable', calls)

    def test_failed_or_ambiguous_unit_readback_never_replaces_live_resources(self):
        for fault in ('bus', 'readback', 'orphan', 'partial'):
            for kind, marker in (('direct', 'STANDALONE_ROLLBACK_RUNTIME_RETAINED=1'),
                                 ('panel', 'PANEL_ROLLBACK_NGINX_RESOURCES_RETAINED=1')):
                with self.subTest(kind=kind, fault=fault):
                    result, calls = self.run_handler(kind, fault)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(marker, result.stderr)
                    self.assertFalse(any(x.startswith('tar ') or '/fixture/renew-hook' in x
                                         for x in calls))
                    if kind == 'direct':
                        self.assertFalse(any(x.startswith(('install ', 'ufw ')) for x in calls))
                    else:
                        self.assertIn('ufw reload', calls)

    def test_successful_rollback_preserves_original_installation_error(self):
        for kind, marker in (('direct', 'STANDALONE_ROLLBACK_OK=1'),
                             ('panel', 'PANEL_ROLLBACK_OK=1')):
            with self.subTest(kind=kind):
                result, _ = self.run_handler(kind)
                self.assertEqual(result.returncode, 37, result.stderr)
                self.assertIn(marker, result.stderr)


if __name__ == '__main__':
    unittest.main()
