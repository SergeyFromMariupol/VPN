"""Classify real failure transcripts without exposing private logs or changing state."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('vpn_error_reporter_tests', ROOT / 'tools/errors.py')
ERRORS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ERRORS)

RATE_LIMIT = '''CERTBOT_LOCKED_DISTRIBUTIONS_OK=1
PINNED_CERTBOT_OK=1 VERSION=5.9.0
Saving debug log to /var/log/letsencrypt/letsencrypt.log
Account registered.
Requesting a certificate for 198.51.100.42
An unexpected error occurred:
too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-11-02 08:11:35 UTC: see https://letsencrypt.org/docs/rate-limits/
ACME_ROLLBACK_OK=1 SNAPSHOT=/var/backups/krysyuk-standalone/test-acme
'''
CANARIES = ('PRIVATE_LOG_CANARY_8e7e28a6', 'secret.user@example.com',
            '91659e6b-6578-4963-bf47-a617834bb140',
            'vless://auth-secret@198.51.100.42:443?token=private-token',
            '/private/secret/subscription-path', '\x1b[2J', '\x07')
PRIVATE_TEXT = '\n'.join(CANARIES)


class ErrorClassification(unittest.TestCase):
    def render(self, stage, text, status=1, **options):
        issue = ERRORS.classify(stage, text, status=status)
        return issue, ERRORS.render(issue, stage, status=status, **options)

    def assert_private(self, output):
        for value in CANARIES:
            self.assertNotIn(value, output)

    def test_actual_identifier_rate_limit_has_exact_retry_time_and_remedy(self):
        issue, output = self.render('tls', RATE_LIMIT + PRIVATE_TEXT, can_resume=True)
        self.assertEqual(issue['code'], 'ACME_EXACT_RATE_LIMIT')
        self.assertEqual(issue['retry_after_utc'], '2026-11-02T08:11:35Z')
        self.assertTrue(issue['resume'])
        self.assertIn('UTC', output)
        self.assertIn('2026', output)
        self.assertIn('bash /opt/vpn-installer/install.sh --resume', output.splitlines())
        self.assertNotIn('--diagnose', output)
        self.assertNotIn('systemctl', output)
        self.assert_private(output)

    def test_other_ca_limits_never_claim_the_exact_identifier_quota(self):
        text = ('urn:ietf:params:acme:error:rateLimited: too many registrations from this IP; '
                'retry after 2026-11-02 08:11:35 UTC')
        issue = ERRORS.classify('tls', text)
        self.assertEqual(issue['code'], 'ACME_RATE_LIMIT')
        explanation = issue['cause'] + ' ' + issue['solution']
        self.assertNotIn('168', explanation)
        self.assertNotRegex(explanation, r'5\s+сертификат')
        self.assertEqual(issue.get('retry_after_utc'), '2026-11-02T08:11:35Z')

    def test_retry_timestamp_is_validated_not_reflected_from_error_text(self):
        for value in ('2026-11-02T08:11:35Z', '2026-11-02 08:11:35 UTC'):
            with self.subTest(value=value):
                issue = ERRORS.classify('tls', RATE_LIMIT.split('retry after', 1)[0] +
                                        'retry after ' + value)
                self.assertEqual(issue['retry_after_utc'], '2026-11-02T08:11:35Z')
        for value in ('2026-99-88 90:77:99 UTC', 'tomorrow ' + PRIVATE_TEXT,
                      '2026-11-02 08:11:35 NOT_A_ZONE'):
            with self.subTest(value=value):
                text = RATE_LIMIT.split('retry after', 1)[0] + 'retry after ' + value
                issue, output = self.render('tls', text, can_resume=True)
                self.assertFalse(issue.get('retry_after_utc'))
                self.assert_private(output)

    def test_failed_recovery_beats_rate_limit_network_and_cancellation(self):
        markers = ('ACME_ROLLBACK_OK=0', 'MANAGED_ROLLBACK_OK=0',
                   'CERTBOT_ROLLBACK_OK=0', 'PANEL_ROLLBACK_OK=0',
                   'ROLLBACK_VERIFIED=0', 'WARP_BOOTSTRAP_ROLLBACK_FAILED=1',
                   'WARP_NETNS_AUTO_ROLLBACK_FAILED=/private/secret/subscription-path',
                   'FRESH_XHTTP_FAILED=ROLLBACK_VALIDATION',
                   'BOOTSTRAP_CLEANUP_REFUSED=/private/secret/subscription-path')
        for marker in markers:
            with self.subTest(marker=marker):
                issue, output = self.render('tls', RATE_LIMIT + '\n' + marker +
                                            '\nTemporary failure resolving\n' + PRIVATE_TEXT,
                                            status=130, can_resume=True)
                self.assertIn(issue['code'], ('RECOVERY_REQUIRED', 'STATE_UNSAFE'))
                self.assertFalse(issue['resume'])
                self.assertNotIn('--resume', output)
                self.assertIn('--diagnose', output)
                self.assert_private(output)

    def test_package_and_integrity_failures_are_not_downgraded_to_network_retry(self):
        for text, expected in (
                ('OS_UPGRADE_INCOMPLETE=1\nCould not resolve host', 'PACKAGE_STATE'),
                ('APT_INSTALL_PACKAGE_CHANGES_REMAIN=1\ncurl: (28) timeout', 'PACKAGE_STATE'),
                ('sha256sum: file: FAILED\nTemporary failure resolving', 'INTEGRITY_FAILED'),
                ('THESE PACKAGES DO NOT MATCH THE HASHES\ncurl: (28)', 'INTEGRITY_FAILED')):
            with self.subTest(text=text):
                issue, output = self.render('base', text, can_resume=True)
                self.assertEqual(issue['code'], expected)
                self.assertFalse(issue['resume'])
                self.assertNotIn('--resume', output)
                self.assertNotIn('curl -k', output)

    def test_known_operational_transcripts_get_specific_causes_and_actions(self):
        cases = (
            ('tls', 'Timeout during connect (likely firewall problem)', 'ACME_HTTP01'),
            ('tls', 'ERROR: target DNS A mismatch', 'DNS_A'),
            ('tls', 'Remove AAAA records before proceeding', 'DNS_AAAA'),
            ('tls', 'Use an exact A record, not CNAME', 'DNS_CNAME'),
            ('tls', 'Could not bind TCP port 80 because it is already in use', 'PORT_BUSY'),
            ('base', 'Could not get lock /var/lib/dpkg/lock-frontend', 'PACKAGE_LOCK'),
            ('base', 'dpkg was interrupted, you must manually run dpkg --configure -a', 'PACKAGE_INTERRUPTED'),
            ('base', 'curl: (6) Could not resolve host: example.invalid', 'NETWORK_DNS'),
            ('certbot', 'curl: (28) Connection timed out after 30000 milliseconds', 'NETWORK_TIMEOUT'),
            ('download', 'curl: (22) The requested URL returned error: 404', 'SOURCE_UNAVAILABLE'),
            ('download', 'curl: (60) SSL certificate problem: certificate has expired', 'TLS_TRUST'),
            ('bootstrap', 'No space left on device', 'DISK_FULL'),
            ('warp', 'isolated WARP registration failed after bounded retries', 'WARP_CONNECTIVITY'),
            ('warp', 'host warp-svc must remain inactive', 'WARP_ISOLATION'),
            ('dual', 'subscription profile mismatch', 'SUBSCRIPTION_MISMATCH'),
            ('xhttp', 'FRESH_XHTTP_FAILED=URI_CLIENT_TIMEOUT', 'XHTTP_TEST_FAILED'),
            ('xhttp', 'FRESH_XHTTP_FAILED=ENV_SHAPE', 'XHTTP_ENV_FORMAT'),
        )
        for stage, text, expected in cases:
            with self.subTest(stage=stage, expected=expected):
                issue = ERRORS.classify(stage, text)
                self.assertEqual(issue['code'], expected)
                for field in ('title', 'cause', 'solution'):
                    self.assertTrue(issue[field].strip(), issue)

    def test_cancellation_uses_status_but_does_not_assume_saved_state(self):
        for status in (129, 130, 143):
            with self.subTest(status=status):
                issue, output = self.render('base', '', status=status, can_resume=False)
                self.assertEqual(issue['code'], 'CANCELLED')
                self.assertTrue(issue['resume'])
                self.assertNotIn('--resume', output)
                resumed = ERRORS.render(issue, 'base', status=status, can_resume=True)
                self.assertIn('bash /opt/vpn-installer/install.sh --resume', resumed.splitlines())

    def test_unknown_failure_has_honest_diagnosis_and_no_guessed_tls_cause(self):
        issue, output = self.render('tls', PRIVATE_TEXT, can_resume=True)
        self.assertEqual(issue['code'], 'UNKNOWN')
        self.assertFalse(issue['resume'])
        self.assertIn('bash /opt/vpn-installer/install.sh --diagnose', output.splitlines())
        self.assertNotIn('--resume', output)
        self.assert_private(output)

    def test_fixed_gate_codes_and_malicious_marker_values_do_not_echo_values(self):
        for code in ('ACME_PORT80', 'ACME_XUI_STATE', 'VERIFY_DATABASE', 'ROOT_REQUIRED'):
            with self.subTest(code=code):
                issue = ERRORS.classify('tls', 'VPN_ERROR_CODE=' + code + '\n' + PRIVATE_TEXT)
                self.assertEqual(issue['code'], code)
                self.assertTrue(issue['solution'])
                self.assert_private(ERRORS.render(issue, 'tls', can_resume=True))
        issue = ERRORS.classify('tls', 'VPN_ERROR_CODE=' + CANARIES[0] + '\n' + PRIVATE_TEXT)
        self.assertEqual(issue['code'], 'UNKNOWN')
        self.assert_private(ERRORS.render(issue, 'tls', can_resume=True))

    def test_complete_commands_quote_a_destination_with_spaces(self):
        issue = ERRORS.classify('tls', RATE_LIMIT)
        destination = '/opt/vpn installer'
        output = ERRORS.render(issue, 'tls', can_resume=True, destination=destination)
        commands = [shlex.split(line) for line in output.splitlines() if line.startswith('bash ')]
        self.assertIn(['bash', destination + '/install.sh', '--resume'], commands)


RUNNER = r'''
import hashlib,json,os,pathlib,shutil,stat,subprocess,sys
config=json.loads(sys.argv[1])
root=pathlib.Path(config['root']).resolve()
assert root.parent==pathlib.Path('/tmp') and root.name.startswith('vpn-errors-test.')
owned=root/'owned'
owned.mkdir(mode=0o700)
state=owned/'state'
state.mkdir(mode=0o700)
log=state/'tls.log'
content=config['text'].encode()
log.write_bytes(content)
log.chmod(0o600)
kind=config['kind']
if kind=='symlink':
    original=state/'private-original'
    log.rename(original)
    log.symlink_to(original.name)
elif kind=='hardlink': os.link(log,state/'private-alias')
elif kind=='fifo': log.unlink();os.mkfifo(log,0o600)
elif kind=='directory': log.unlink();log.mkdir(mode=0o700)
elif kind=='owner': os.chown(log,65534,65534)
elif kind=='mode': log.chmod(0o644)
elif kind=='missing': log.unlink()
elif kind=='oversized':
    log.write_bytes(content+b'x'*(9*1024*1024)+b'\nACME_ROLLBACK_OK=0\n')
elif kind=='diagnose':
    (state/'base.log').write_text(config['canary'])
    (state/'base.log').chmod(0o600)
    (state/'base.done').write_text('2026-11-01T00:00:00Z\n')
    (state/'base.done').chmod(0o600)
    (state/'not-an-installer-log').write_text(config['canary'])
elif kind=='state-mode': state.chmod(0o755)
elif kind=='state-owner': os.chown(state,65534,65534)
elif kind=='state-symlink':
    state.rename(owned/'state-real')
    state.symlink_to('state-real',target_is_directory=True)

def snapshot():
    result={}
    for path in sorted(owned.rglob('*')):
        info=path.lstat()
        key=str(path.relative_to(owned))
        if stat.S_ISLNK(info.st_mode): body=('link',os.readlink(path))
        elif stat.S_ISREG(info.st_mode): body=('file',hashlib.sha256(path.read_bytes()).hexdigest())
        else: body=('other',)
        result[key]=(info.st_mode,info.st_uid,info.st_gid,info.st_ino,info.st_mtime_ns,body)
    return result

before=snapshot()
arguments=[sys.executable,'-I','-B',config['source'],'--destination','/opt/vpn-installer']
if kind.startswith('state-') or kind=='diagnose': arguments+=['--diagnose','--state',str(state)]
else: arguments+=['--stage','tls','--status','1','--log',str(log),'--can-resume']
try:
    result=subprocess.run(arguments,capture_output=True,text=True,timeout=5)
    after=snapshot()
    print(json.dumps(dict(code=result.returncode,stdout=result.stdout,stderr=result.stderr,
                          unchanged=(before==after))))
finally:
    assert owned.parent==root and root.parent==pathlib.Path('/tmp')
    shutil.rmtree(owned)
'''


@unittest.skipIf(os.name == 'nt', 'Actual root-owned log fixtures run in Ubuntu CI')
class ErrorReporterCLI(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.prefix = []
        elif shutil.which('sudo') and subprocess.run(['sudo', '-n', 'true'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            self.prefix = ['sudo', '-n']
        else:
            if os.environ.get('CI'):
                self.fail('Ubuntu CI must run actual root-owned error-log fixtures')
            self.skipTest('Root or passwordless sudo required')

    def fixture(self, kind):
        with tempfile.TemporaryDirectory(prefix='vpn-errors-test.', dir='/tmp') as directory:
            config = dict(root=directory, source=str(ROOT / 'tools/errors.py'), kind=kind,
                          text=RATE_LIMIT + PRIVATE_TEXT, canary=PRIVATE_TEXT)
            result = subprocess.run([*self.prefix, 'python3', '-I', '-B', '-c', RUNNER,
                                     json.dumps(config)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            value = json.loads(result.stdout)
            self.assertTrue(value['unchanged'], value)
            self.assertEqual(value['stderr'], '', value)
            for canary in CANARIES:
                self.assertNotIn(canary, value['stdout'])
            return value

    def test_real_cli_reads_private_log_and_prints_standalone_retry_command(self):
        result = self.fixture('regular')
        self.assertEqual(result['code'], 0, result)
        self.assertIn('ACME_EXACT_RATE_LIMIT', result['stdout'])
        self.assertIn('bash /opt/vpn-installer/install.sh --resume', result['stdout'].splitlines())
        self.assertIn('UTC', result['stdout'])

    def test_unsafe_or_oversized_log_never_blocks_or_leaks_a_stale_retry(self):
        for kind in ('symlink', 'hardlink', 'fifo', 'directory', 'owner', 'mode', 'missing', 'oversized'):
            with self.subTest(kind=kind):
                result = self.fixture(kind)
                self.assertEqual(result['code'], 0, result)
                self.assertNotIn('ACME_EXACT_RATE_LIMIT', result['stdout'])
                self.assertNotIn('--resume', result['stdout'])
                self.assertIn('--diagnose', result['stdout'])

    def test_diagnose_is_readonly_and_distinguishes_historical_completed_logs(self):
        result = self.fixture('diagnose')
        self.assertEqual(result['code'], 0, result)
        self.assertIn('ACME_EXACT_RATE_LIMIT', result['stdout'])
        self.assertIn('UTC', result['stdout'])
        self.assertNotIn('--resume', result['stdout'])

    def test_diagnose_rejects_untrusted_state_directory_without_reading_logs(self):
        for kind in ('state-mode', 'state-owner', 'state-symlink'):
            with self.subTest(kind=kind):
                result = self.fixture(kind)
                self.assertEqual(result['code'], 1, result)
                self.assertNotIn('ACME_EXACT_RATE_LIMIT', result['stdout'])
                self.assertNotIn('--resume', result['stdout'])


if __name__ == '__main__':
    unittest.main()
