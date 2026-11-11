"""Exercise the production SNI gate without DNS, TLS or host mutations."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import runpy
import subprocess
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'tools/preflight.py'
SPEC = importlib.util.spec_from_file_location('reality_preflight', PATH)
PREFLIGHT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREFLIGHT)
HOST = 'www.example.org'
SUCCESS = 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nALPN protocol: h2\n'
INVALID = ('', 'https://example.org', 'example.org:443', '*.example.org',
           '-bad.example.org', 'a..example.org', 'example.org/path',
           'example.org;id', '$(id).example.org', 'example.org\nother.example.org',
           'example.org ', 'Example.org', 'a' * 64 + '.org',
           '8.8.8.8', '127.0.0.1', '2001:4860:4860::8888',
           'cloudflare.com', 'www.cloudflare.com', 'cloudflare-dns.com')


class RealityPreflight(unittest.TestCase):
    def completed(self, code=0, stdout=SUCCESS, stderr='Verification: OK\n'):
        return subprocess.CompletedProcess([], code, stdout, stderr)

    def test_valid_dns_names_need_no_process_for_format_validation(self):
        with patch.object(PREFLIGHT.subprocess, 'run') as process:
            for value in ('max.ru', HOST, 'www.amazon.de'):
                with self.subTest(value=value):
                    PREFLIGHT.validate_reality_sni(value)
            process.assert_not_called()

    def test_invalid_names_cloudflare_and_ip_literals_are_rejected(self):
        for value in INVALID:
            with self.subTest(value=value), self.assertRaises(ValueError):
                PREFLIGHT.validate_reality_sni(value)

    def test_invalid_input_never_reaches_an_external_command(self):
        for value in INVALID:
            with self.subTest(value=value), patch.object(
                    PREFLIGHT.subprocess, 'run', return_value=self.completed()) as process:
                with self.assertRaises(ValueError):
                    PREFLIGHT.check_reality_target(value)
                process.assert_not_called()

    def test_probe_requires_tls13_h2_trust_and_the_exact_requested_hostname(self):
        # OpenSSL may write its verification result to stderr. Both streams
        # must be interpreted while preserving the same hostname for all checks.
        with patch.object(PREFLIGHT.subprocess, 'run', return_value=self.completed()) as process:
            PREFLIGHT.check_reality_target(HOST)
        process.assert_called_once()
        arguments, options = process.call_args
        self.assertEqual(len(arguments), 1)
        argv = arguments[0]
        self.assertIsInstance(argv, (list, tuple))
        self.assertEqual(list(argv[:4]), ['timeout', '20', 'openssl', 's_client'])
        for flag, value in (('-connect', HOST + ':443'), ('-servername', HOST),
                            ('-verify_hostname', HOST), ('-alpn', 'h2')):
            self.assertEqual(argv.count(flag), 1)
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertIn('-tls1_3', argv)
        self.assertIn('-verify_return_error', argv)
        self.assertEqual(options.get('input'), '')
        self.assertIs(options.get('text'), True)
        self.assertIs(options.get('capture_output'), True)
        self.assertEqual(options.get('timeout'), 25)
        self.assertFalse(options.get('shell', False))

    def test_protocol_trust_hostname_and_alpn_failures_do_not_pass(self):
        cases = {
            'tls13-unavailable': self.completed(1, '', 'tlsv1 alert protocol version'),
            'untrusted-chain': self.completed(1, SUCCESS, 'certificate verify failed: self-signed'),
            'hostname-mismatch': self.completed(1, SUCCESS, 'verify error:num=62:hostname mismatch'),
            'no-alpn': self.completed(0, 'New, TLSv1.3\nNo ALPN negotiated\n'),
            'wrong-alpn': self.completed(0, 'New, TLSv1.3\nALPN protocol: http/1.1\n'),
            'verification-not-confirmed': self.completed(0, SUCCESS, ''),
            'timeout-command-failure-with-positive-text': self.completed(124),
        }
        for name, result in cases.items():
            with self.subTest(case=name), patch.object(
                    PREFLIGHT.subprocess, 'run', return_value=result):
                with self.assertRaises(ValueError):
                    PREFLIGHT.check_reality_target(HOST)

    def test_process_timeout_and_start_failure_are_not_reported_as_success(self):
        for error in (subprocess.TimeoutExpired(['openssl'], 20),
                      OSError('fixture executable unavailable')):
            with self.subTest(error=type(error).__name__), patch.object(
                    PREFLIGHT.subprocess, 'run', side_effect=error):
                with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
                    PREFLIGHT.check_reality_target(HOST)

    def test_general_input_validation_uses_the_same_sni_format_gate(self):
        environment = dict(TARGET_ADDRESS_MODE='ip', TARGET_IPV4='8.8.4.4',
                           TARGET_FQDN='8.8.4.4', TARGET_INTERFACE='enp1s0',
                           TARGET_SSH_PORT='2222', TARGET_DEVICE_LIMIT='0',
                           TARGET_REALITY_SNI=HOST, TARGET_LABEL='Fixture VPN', ACME_EMAIL='')
        with patch.object(PREFLIGHT, 'validate_reality_sni',
                          side_effect=ValueError('SHARED_SNI_GATE')) as validate:
            with self.assertRaisesRegex(ValueError, 'SHARED_SNI_GATE'):
                PREFLIGHT.validate_inputs(environment)
        validate.assert_called_once_with(HOST)

    def test_sni_only_cli_needs_no_other_answers_or_host_preflight(self):
        with patch.dict(os.environ, {'TARGET_REALITY_SNI': HOST}, clear=True), \
                patch.object(sys, 'argv', [str(PATH), '--check-reality-sni']), \
                patch.object(subprocess, 'run', return_value=self.completed()) as process, \
                patch.object(subprocess, 'check_output',
                             side_effect=AssertionError('HOST_PROBE_FORBIDDEN')), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            runpy.run_path(str(PATH), run_name='__main__')
        process.assert_called_once()
        self.assertIn('-verify_hostname', process.call_args.args[0])

    def test_local_sites_check_own_dns_but_never_probe_not_yet_created_tls(self):
        for mode, sni in (('self-steal', HOST), ('decoy', 'max.ru')):
            env = dict(TARGET_REALITY_MODE=mode, TARGET_ADDRESS_MODE='domain',
                       TARGET_TLS_MODE='letsencrypt', TARGET_IPV4='8.8.4.4',
                       TARGET_FQDN=HOST, TARGET_REALITY_SNI=sni)
            with self.subTest(mode=mode), patch.object(PREFLIGHT, 'dns',
                    side_effect=lambda name, kind, resolver: ['8.8.4.4'] if kind == 1 else []) as dns, \
                    patch.object(PREFLIGHT.subprocess, 'run',
                                 side_effect=AssertionError('LOCAL_TLS_NOT_CREATED')):
                self.assertEqual(PREFLIGHT.check_reality_preflight(env), 'PENDING_LOCAL_SITE')
                self.assertEqual(dns.call_args_list, [
                    unittest.mock.call(HOST, kind, resolver)
                    for resolver in ('1.1.1.1', '9.9.9.9') for kind in (1, 28)])

    def test_decoy_ip_has_no_external_target_dns_or_tls_dependency(self):
        env = dict(TARGET_REALITY_MODE='decoy', TARGET_ADDRESS_MODE='ip',
                   TARGET_TLS_MODE='letsencrypt', TARGET_IPV4='8.8.4.4',
                   TARGET_FQDN='8.8.4.4', TARGET_REALITY_SNI='max.ru')
        with patch.object(PREFLIGHT, 'dns', side_effect=AssertionError('IP_DNS_FORBIDDEN')), \
                patch.object(PREFLIGHT.subprocess, 'run',
                             side_effect=AssertionError('EXTERNAL_TLS_FORBIDDEN')):
            self.assertEqual(PREFLIGHT.check_reality_preflight(env), 'PENDING_LOCAL_SITE')

    def test_external_and_legacy_targets_retain_trusted_hostname_probe(self):
        for saved in ({}, {'TARGET_REALITY_MODE': 'external'}):
            env = dict(saved, TARGET_ADDRESS_MODE='ip', TARGET_FQDN='8.8.4.4',
                       TARGET_REALITY_SNI='max.ru')
            with self.subTest(saved=saved), patch.object(PREFLIGHT.subprocess, 'run',
                                                         return_value=self.completed()) as process:
                self.assertEqual(PREFLIGHT.check_reality_preflight(env), 'PASS')
                self.assertIn('max.ru:443', process.call_args.args[0])

    def test_invalid_local_dns_blocks_before_tls_or_acme(self):
        env = dict(TARGET_REALITY_MODE='self-steal', TARGET_FQDN=HOST,
                   TARGET_REALITY_SNI=HOST, TARGET_IPV4='8.8.4.4')
        for kind, results in ((1, []), (1, ['8.8.8.8']), (1, ['8.8.4.4', '8.8.8.8']),
                              (28, ['2001:4860:4860::8888'])):
            with self.subTest(kind=kind, results=results), patch.object(PREFLIGHT, 'dns',
                    side_effect=lambda name, query_kind, resolver:
                        results if query_kind == kind else ['8.8.4.4']), \
                    patch.object(PREFLIGHT.subprocess, 'run') as process:
                with self.assertRaises(ValueError):
                    PREFLIGHT.check_reality_preflight(env)
                process.assert_not_called()


if __name__ == '__main__':
    unittest.main()
