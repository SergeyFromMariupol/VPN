"""Exercise pinned Certbot account setup with real parsing and mocked ACME IO.

Run with the locked Certbot venv after dependency installation. All paths are
temporary, no certificate is issued, and network connections are forbidden.
"""
import importlib.metadata
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


BASE = Path(__file__).resolve().parent


class PinnedAccountRegistration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            version = importlib.metadata.version('certbot')
        except importlib.metadata.PackageNotFoundError:
            version = None
        if version != '5.9.0':
            if os.environ.get('VPN_TEST_LOCKED_CERTBOT'):
                raise AssertionError('Actual pinned Certbot 5.9.0 is required')
            raise unittest.SkipTest('Run this fixture with the pinned Certbot venv')
        cls.bash = os.environ.get('VPN_TEST_BASH') or shutil.which('bash')
        if not cls.bash:
            raise AssertionError('Bash is required to run the production contact helper')
        from acme import messages
        from certbot._internal import account, cli, client, main
        from certbot._internal.plugins import disco
        cls.messages, cls.account, cls.cli = messages, account, cli
        cls.client, cls.main, cls.disco = client, main, disco

    def arguments(self, mode, email):
        endpoint = 'vpn.example.org' if mode == 'domain' else '8.8.4.4'
        result = subprocess.run(
            [self.bash, '-c', 'source "$1"; TARGET_ADDRESS_MODE=$2; TARGET_FQDN=$3; '
             'TARGET_IPV4=8.8.4.4; ACME_EMAIL=$4; acme_identifier_arguments || exit; '
             'acme_contact_arguments || exit; printf "%s\\0" '
             '"${acme_identifiers[@]}" "${acme_contact[@]}"',
             '--', (BASE / 'acme-identifiers.sh').as_posix(), mode, endpoint, email],
            capture_output=True, check=True, timeout=10)
        return result.stdout.decode().rstrip('\0').split('\0')

    def config(self, directory, mode, email, omit_email_option=False):
        directory.mkdir(parents=True, exist_ok=True)
        empty_config = directory / 'cli.ini'
        empty_config.write_text('')
        arguments = self.arguments(mode, email)
        if omit_email_option:
            index = arguments.index('--email')
            del arguments[index:index + 2]
        return self.cli.prepare_and_parse_args(self.disco.PluginsRegistry.find_all(), [
            'certonly', '--standalone', '--non-interactive', '--agree-tos',
            '--config', str(empty_config), '--config-dir', str(directory / 'config'),
            '--work-dir', str(directory / 'work'), '--logs-dir', str(directory / 'logs'),
            *arguments])

    def register(self, config):
        storage = self.account.AccountMemoryStorage()
        acme = Mock()
        acme.external_account_required.return_value = False
        acme.directory.meta.terms_of_service = 'https://acme.example.invalid/terms'
        requests = []

        def create_client(actual_config, key):
            self.assertIs(actual_config, config)
            acme.net.key = key
            return acme

        def new_account(request):
            requests.append(request)
            return self.messages.RegistrationResource(
                body=request, uri='https://acme.example.invalid/account/fixture')

        acme.new_account.side_effect = new_account
        with patch.object(self.main.account, 'AccountFileStorage', return_value=storage), \
                patch.object(self.client, 'create_acme_client', side_effect=create_client), \
                patch.object(self.main.display_ops, 'get_email',
                             side_effect=AssertionError('EMAIL_PROMPT_ATTEMPTED')), \
                patch.object(self.main.display_util, 'yesno',
                             side_effect=AssertionError('INTERACTIVE_PROMPT_ATTEMPTED')), \
                patch.object(self.main.display_util, 'notify'), \
                patch('builtins.input', side_effect=AssertionError('STDIN_PROMPT_ATTEMPTED')), \
                patch.object(socket.socket, 'connect',
                             side_effect=AssertionError('NETWORK_FORBIDDEN')):
            result, returned_acme = self.main._determine_account(config)
        self.assertIs(returned_acme, acme)
        self.assertEqual(len(storage.find_all()), 1)
        self.assertIs(storage.find_all()[0], result)
        self.assertEqual(len(requests), 1)
        self.assertIsNone(result.meta.register_to_eff)
        return requests[0], result, storage

    def test_explicit_empty_email_registers_without_prompts_in_both_modes(self):
        for mode in ('domain', 'ip'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='vpn-certbot-account-') as temporary:
                config = self.config(Path(temporary), mode, '')
                self.assertEqual(config.email, '')
                self.assertTrue(config.noninteractive_mode)
                self.assertFalse(config.register_unsafely_without_email)
                self.assertIs(config.eff_email, False)
                request, _, _ = self.register(config)
                self.assertIsNone(config.email)
                self.assertEqual(tuple(request.contact), ())
                self.assertTrue(request.terms_of_service_agreed)

    def test_provided_email_is_preserved_without_eff_opt_in_in_both_modes(self):
        for mode in ('domain', 'ip'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='vpn-certbot-account-') as temporary:
                config = self.config(Path(temporary), mode, 'owner+vpn@example.org')
                request, _, _ = self.register(config)
                self.assertEqual(config.email, 'owner+vpn@example.org')
                self.assertEqual(tuple(request.contact), ('mailto:owner+vpn@example.org',))

    def test_existing_account_and_key_are_reused_with_empty_contact(self):
        with tempfile.TemporaryDirectory(prefix='vpn-certbot-account-') as temporary:
            directory = Path(temporary)
            original_config = self.config(directory / 'original', 'domain', 'owner@example.org')
            _, original_account, storage = self.register(original_config)
            original_key = original_account.key
            resumed = self.config(directory / 'resumed', 'domain', '')
            resumed.account = original_account.id
            with patch.object(self.main.account, 'AccountFileStorage', return_value=storage), \
                    patch.object(self.client, 'register',
                                 side_effect=AssertionError('UNEXPECTED_REREGISTRATION')), \
                    patch.object(self.main.display_ops, 'get_email',
                                 side_effect=AssertionError('EMAIL_PROMPT_ATTEMPTED')), \
                    patch('builtins.input', side_effect=AssertionError('STDIN_PROMPT_ATTEMPTED')), \
                    patch.object(socket.socket, 'connect',
                                 side_effect=AssertionError('NETWORK_FORBIDDEN')):
                account, acme = self.main._determine_account(resumed)
            self.assertIs(account, original_account)
            self.assertIs(account.key, original_key)
            self.assertEqual(resumed.account, original_account.id)
            self.assertIsNone(acme)

    def test_omitting_email_option_would_reach_the_prompt_path(self):
        with tempfile.TemporaryDirectory(prefix='vpn-certbot-account-') as temporary:
            config = self.config(Path(temporary), 'domain', '', omit_email_option=True)
            self.assertIsNone(config.email)
            with self.assertRaisesRegex(AssertionError, 'EMAIL_PROMPT_ATTEMPTED'):
                self.register(config)


if __name__ == '__main__':
    unittest.main()
