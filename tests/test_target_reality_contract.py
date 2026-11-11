"""Execute persisted REALITY mode compatibility and computed destinations."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get('VPN_TEST_BASH') or shutil.which('bash')
BASE = dict(TARGET_IPV4='8.8.4.4', TARGET_FQDN='vpn.example.org',
            TARGET_ADDRESS_MODE='domain', TARGET_INTERFACE='ens3',
            TARGET_SSH_PORT='2222', TARGET_REALITY_SNI='max.ru',
            TARGET_DEVICE_LIMIT='0', TARGET_LABEL='Fixture VPN')


@unittest.skipUnless(BASH, 'Bash is required for the actual shared contract')
class TargetRealityContract(unittest.TestCase):
    def contract(self, values=None, saved=None):
        with tempfile.TemporaryDirectory(prefix='vpn-reality-contract-') as directory:
            root = Path(directory)
            target = root / 'target.env'
            if saved is not None:
                target.write_text(''.join(key + '=' + shlex.quote(value) + '\n'
                                          for key, value in saved.items()), encoding='utf-8')
                target.chmod(0o600)
            source = (ROOT / 'bundle/scripts/target-contract.sh').read_text(encoding='utf-8')
            contract = root / 'contract.sh'
            contract.write_text(source.replace('/etc/germanyvpn-target.env', target.as_posix()),
                                encoding='utf-8', newline='\n')
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(('TARGET_', 'GERMANYVPN_TARGET_'))}
            environment.update(BASE)
            environment.update(values or {})
            environment.update(VPN_TEST_PYTHON=Path(sys.executable).as_posix(),
                               VPN_TEST_TARGET=target.as_posix())
            # Metadata is independent of this fixture's behavior. Isolate only
            # its private state file so these tests work under ordinary users
            # and Windows as well as Ubuntu's root fixture suite.
            script = r'''set -Eeuo pipefail
python3() { "$VPN_TEST_PYTHON" "$@"; }
stat() {
  if [[ $* == "-c %U:%G:%a $VPN_TEST_TARGET" ]]; then printf 'root:root:600\n';
  else command stat "$@"; fi
}
source "$1"
printf '%s\n' "$TARGET_REALITY_MODE" "$TARGET_REALITY_SNI" "$TARGET_REALITY_DEST" \
  "$TARGET_REALITY_TARGET_SNI" "$TARGET_TLS_MODE"
'''
            return subprocess.run([BASH, '-c', script, '_', contract.as_posix()],
                                  env=environment, text=True, capture_output=True, timeout=15)

    def test_modes_compute_target_and_override_caller_destinations(self):
        for values, expected in (
                ({}, ['external', 'max.ru', 'max.ru:443', 'max.ru', 'letsencrypt']),
                ({'TARGET_REALITY_MODE': 'self-steal', 'TARGET_REALITY_SNI': BASE['TARGET_FQDN']},
                 ['self-steal', BASE['TARGET_FQDN'], '127.0.0.1:9443', BASE['TARGET_FQDN'], 'letsencrypt']),
                ({'TARGET_REALITY_MODE': 'decoy'},
                 ['decoy', 'max.ru', '127.0.0.1:9443', BASE['TARGET_FQDN'], 'letsencrypt']),
                ({'TARGET_REALITY_MODE': 'decoy', 'TARGET_ADDRESS_MODE': 'ip',
                  'TARGET_FQDN': BASE['TARGET_IPV4']},
                 ['decoy', 'max.ru', '127.0.0.1:9443', BASE['TARGET_IPV4'], 'letsencrypt']),
                ({'TARGET_TLS_MODE': 'none'}, ['external', 'max.ru', 'max.ru:443', 'max.ru', 'none'])):
            with self.subTest(values=values):
                result = self.contract(dict(values, TARGET_REALITY_DEST='caller.invalid:1',
                                            TARGET_REALITY_TARGET_SNI='caller.invalid'))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), expected)

    def test_saved_legacy_mode_ignores_caller_self_steal_and_preserves_max(self):
        result = self.contract(dict(TARGET_REALITY_MODE='self-steal',
                                    TARGET_REALITY_SNI='caller.invalid'), BASE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ['external', 'max.ru', 'max.ru:443', 'max.ru', 'letsencrypt'])

    def test_incompatible_modes_are_rejected(self):
        for changes in ({'TARGET_REALITY_MODE': 'unknown'},
                        {'TARGET_REALITY_MODE': 'self-steal'},
                        {'TARGET_REALITY_MODE': 'self-steal', 'TARGET_ADDRESS_MODE': 'ip',
                         'TARGET_FQDN': BASE['TARGET_IPV4']},
                        {'TARGET_REALITY_MODE': 'decoy', 'TARGET_TLS_MODE': 'none'},
                        {'TARGET_REALITY_MODE': 'decoy', 'TARGET_REALITY_SNI': '8.8.8.8'}):
            with self.subTest(changes=changes):
                result = self.contract(changes)
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
