"""Execute the SNI menu with real input validation and isolated terminal reads."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get('VPN_TEST_BASH') or shutil.which('bash')


@unittest.skipUnless(BASH, 'Bash is required for the actual wizard')
class RealityWizard(unittest.TestCase):
    def wizard(self, answers, address='ip', endpoint='8.8.4.4'):
        environment = dict(os.environ, VPN_TEST_PYTHON=Path(sys.executable).as_posix(),
                           TARGET_IPV4='8.8.4.4', TARGET_FQDN=endpoint,
                           TARGET_ADDRESS_MODE=address, TARGET_TLS_MODE='letsencrypt',
                           TARGET_REALITY_MODE='external', TARGET_REALITY_SNI='caller.invalid')
        script = r'''set -Eeuo pipefail
python3() { "$VPN_TEST_PYTHON" "$@"; }
source "$1"
wizard_init
wizard_read() {
  local name=$1 prompt=$2 default=${3-} answer
  printf '%s' "$prompt"
  IFS= read -r answer || return 1
  printf -v "$name" '%s' "${answer:-$default}"
}
# Only the external network interaction is isolated here; the full PTY
# fixture separately runs the production CLI and OpenSSL argument checks.
wizard_probe_sni() { printf '\nEXTERNAL_PROBE=%s\n' "$TARGET_REALITY_SNI"; [[ $TARGET_REALITY_SNI == max.ru ]]; }
status=0
wizard_reality_sni "$2" || status=$?
printf '\nRESULT=%s|%s|%s|%s|%s\n' "$status" "$TARGET_REALITY_MODE" "$TARGET_ADDRESS_MODE" "$TARGET_FQDN" "$TARGET_REALITY_SNI"
exit "$status"
'''
        result = subprocess.run([BASH, '-c', script, '_', (ROOT / 'tools/wizard.sh').as_posix(),
                                 (ROOT / 'tools/preflight.py').as_posix()],
                                input=answers.encode('utf-8'), env=environment,
                                capture_output=True, timeout=15)
        result.stdout = result.stdout.decode('utf-8')
        result.stderr = result.stderr.decode('utf-8')
        return result

    def test_default_self_steal_requests_own_domain_and_changes_endpoint(self):
        result = self.wizard('\nbad;name.example\n8.8.4.4\nsite.example.org\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=0|self-steal|domain|site.example.org|site.example.org', result.stdout)
        self.assertIn('Он станет адресом VPN, сайта, панели и подписки.', result.stdout)
        self.assertNotIn('EXTERNAL_PROBE=', result.stdout)

    def test_default_self_steal_preserves_valid_existing_domain(self):
        result = self.wizard('\n', 'domain', 'site.example.org')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=0|self-steal|domain|site.example.org|site.example.org', result.stdout)
        self.assertNotIn('Домен сайта, VPN, панели и подписки:', result.stdout)
        self.assertNotIn('EXTERNAL_PROBE=', result.stdout)

    def test_decoy_ip_accepts_manual_max_without_domain_or_external_tls(self):
        result = self.wizard('2\n8.8.8.8\ncloudflare.com\nmax.ru\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=0|decoy|ip|8.8.4.4|max.ru', result.stdout)
        self.assertIn('Клиентский SNI останется виден в сети', result.stdout)
        self.assertNotIn('Домен сайта, VPN, панели и подписки:', result.stdout)
        self.assertNotIn('EXTERNAL_PROBE=', result.stdout)

    def test_external_has_no_preset_and_probes_only_manual_value(self):
        result = self.wizard('3\n\nmax.ru\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT=0|external|ip|8.8.4.4|max.ru', result.stdout)
        self.assertEqual(result.stdout.count('EXTERNAL_PROBE='), 1)
        self.assertIn('EXTERNAL_PROBE=max.ru', result.stdout)
        self.assertNotIn('По умолчанию max.ru', result.stdout)

    def test_eof_cannot_convert_ip_endpoint_or_accept_empty_manual_sni(self):
        for answers in ('1\n', '2\n', '3\n'):
            with self.subTest(answers=answers):
                result = self.wizard(answers)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('|ip|8.8.4.4|', result.stdout)
                self.assertNotIn('EXTERNAL_PROBE=', result.stdout)


if __name__ == '__main__':
    unittest.main()
