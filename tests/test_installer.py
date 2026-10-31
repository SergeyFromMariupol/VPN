"""Offline tests for installer boundaries; no server or credentials needed."""
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


preflight = module('preflight', ROOT / 'tools/preflight.py')
renderer = module('renderer', ROOT / 'tools/render.py')
writer = module('writer', ROOT / 'tools/write-target.py')
GOOD = dict(TARGET_ADDRESS_MODE='domain', TARGET_IPV4='8.8.4.4', TARGET_FQDN='vpn.example.com',
            TARGET_INTERFACE='enp1s0', TARGET_SSH_PORT='2222',
            TARGET_DEVICE_LIMIT='0', TARGET_REALITY_SNI='example.org',
            TARGET_LABEL='🇩🇪 Германия', ACME_EMAIL='admin@example.com')


class Inputs(unittest.TestCase):
    def test_valid(self):
        preflight.validate_inputs(GOOD)

    def test_ip_and_custom_prefix(self):
        for label in ('🇳🇱 Нидерланды', 'Мой VPN', 'Сервер друга', 'My "VPN" $HOME `literal` \\ 🇫🇷'):
            preflight.validate_inputs({**GOOD, 'TARGET_LABEL': label})
            preflight.validate_inputs({**GOOD, 'TARGET_LABEL': label,
                                       'TARGET_ADDRESS_MODE': 'ip', 'TARGET_FQDN': GOOD['TARGET_IPV4']})

    def test_mode_rejects_unrelated_ip(self):
        for mode, endpoint in (('ip', '8.8.8.8'), ('ip', 'vpn.example.com'), ('domain', '8.8.4.4'),
                               ('unexpected', 'vpn.example.com')):
            with self.subTest(mode=mode, endpoint=endpoint), self.assertRaises(ValueError):
                preflight.validate_inputs({**GOOD, 'TARGET_ADDRESS_MODE': mode, 'TARGET_FQDN': endpoint})

    def test_ip_mode_does_not_query_endpoint_dns(self):
        with patch.object(preflight, 'dns', side_effect=AssertionError('IP DNS queried')):
            preflight.check_endpoint_dns({**GOOD, 'TARGET_ADDRESS_MODE': 'ip', 'TARGET_FQDN': GOOD['TARGET_IPV4']})

    def test_domain_checks_both_resolvers_and_aaaa(self):
        with patch.object(preflight, 'dns', side_effect=lambda name, kind, resolver: [GOOD['TARGET_IPV4']] if kind == 1 else []) as query:
            preflight.check_endpoint_dns(GOOD)
            self.assertEqual(query.call_count, 4)
        for bad in ([GOOD['TARGET_IPV4'], '8.8.8.8'], ['8.8.8.8'], []):
            with self.subTest(records=bad), patch.object(preflight, 'dns', return_value=bad), self.assertRaises(ValueError):
                preflight.check_endpoint_dns(GOOD)
        with patch.object(preflight, 'dns', side_effect=lambda name, kind, resolver: [GOOD['TARGET_IPV4']] if kind == 1 else ['2001:4860:4860::8888']), self.assertRaises(ValueError):
            preflight.check_endpoint_dns(GOOD)

    def test_bad_values_rejected(self):
        for field, values in {
            'TARGET_IPV4': ['127.0.0.1', '192.168.0.4', '::1', '999.1.1.1'],
            'TARGET_FQDN': ['vpn;id.example', '-bad.example', 'a..example', 'a' * 64 + '.com', '*.example.com'],
            'TARGET_INTERFACE': ['eth0\nid', 'eth0;id', ''],
            'TARGET_SSH_PORT': ['0', '65536', '8444', '443', '-1', '22;id'],
            'TARGET_DEVICE_LIMIT': ['-1', '10001', '0;id'],
            'TARGET_REALITY_SNI': ['cloudflare.com', 'a\nb.com', '8.8.8.8'],
            'TARGET_LABEL': ['x\ny', 'x\ry', '\x7f', 'x\u0085y', 'x\u2028y', 'x\u2029y'],
            'ACME_EMAIL': ['not-email', 'a@example.com\nx'],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    preflight.validate_inputs({**GOOD, field: value})


class CleanHostListeners(unittest.TestCase):
    def test_stock_dhcp_and_ssh_are_accepted(self):
        rows = ('tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=12,fd=3))\n'
                'udp UNCONN 0 0 0.0.0.0%enp1s0:68 0.0.0.0:* users:(("systemd-network",pid=42,fd=3))\n'
                'udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:*\n')
        self.assertEqual(preflight.listener_conflicts(
            rows, GOOD, {42: '/usr/lib/systemd/systemd-networkd'},
            {12: '/usr/sbin/sshd'}), [])

    def test_arbitrary_udp68_owner_is_rejected(self):
        row = ('tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=12,fd=3))\n'
               'udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:(("systemd-network",pid=42,fd=3))')
        for owners in ({}, {42: '/tmp/systemd-networkd'}):
            with self.subTest(owners=owners):
                self.assertEqual(len(preflight.listener_conflicts(
                    row, GOOD, owners, {12: '/usr/sbin/sshd'})), 1)

    def test_scoped_extra_public_listener_is_rejected(self):
        row = ('tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=12,fd=3))\n'
               'udp UNCONN 0 0 0.0.0.0%enp1s0:8888 0.0.0.0:*')
        self.assertEqual(len(preflight.listener_conflicts(
            row, GOOD, {}, {12: '/usr/sbin/sshd'})), 1)

    def test_managed_loopback_ports_are_rejected_before_mutation(self):
        ssh = 'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=12,fd=3))'
        for port in preflight.MANAGED_LOOPBACK_PORTS:
            with self.subTest(port=port):
                row = f'tcp LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:* users:(("other",pid=42,fd=3))'
                conflicts = preflight.listener_conflicts(
                    ssh + '\n' + row, GOOD, {}, {12: '/usr/sbin/sshd'})
                self.assertTrue(any('managed loopback port' in conflict for conflict in conflicts))

    def test_ssh_listener_must_be_present_and_authenticated(self):
        row = 'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=12,fd=3))'
        self.assertTrue(any('missing authenticated SSH' in conflict for conflict in
                            preflight.listener_conflicts('', GOOD, {}, {})))
        for owners in ({}, {12: '/tmp/sshd'}):
            with self.subTest(owners=owners):
                self.assertTrue(preflight.listener_conflicts(row, GOOD, {}, owners))
        self.assertEqual(preflight.listener_conflicts(row, GOOD, {}, {12: '/usr/sbin/sshd'}), [])

    def test_systemd_socket_ownership_requires_active_matching_ssh_socket(self):
        row = 'tcp LISTEN 0 4096 0.0.0.0:2222 0.0.0.0:* users:(("systemd",pid=1,fd=99))'
        owners = {1: '/usr/lib/systemd/systemd'}
        self.assertEqual(preflight.listener_conflicts(row, GOOD, {}, owners, True), [])
        self.assertTrue(preflight.listener_conflicts(row, GOOD, {}, owners, False))

    def test_systemd_socket_must_be_active_and_configured_for_selected_port(self):
        with patch.object(preflight.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)), \
                patch.object(preflight, 'run', return_value='[::]:22 (Stream) 0.0.0.0:2222 (Stream)'):
            self.assertTrue(preflight.systemd_ssh_socket_listens(2222))
            self.assertFalse(preflight.systemd_ssh_socket_listens(222))
        with patch.object(preflight.subprocess, 'run', return_value=subprocess.CompletedProcess([], 3)), \
                patch.object(preflight, 'run', side_effect=AssertionError('inactive socket queried')):
            self.assertFalse(preflight.systemd_ssh_socket_listens(2222))


class SavedUfwRules(unittest.TestCase):
    def test_inactive_ufw_with_saved_rules_is_rejected(self):
        empty = "Added user rules (see 'ufw status' for running firewall):\n(None)\n"
        preflight.validate_ufw_saved_rules(empty)
        for output in (
            "Added user rules (see 'ufw status' for running firewall):\nufw allow 22/tcp\n",
            empty + 'ufw allow 80/tcp\n',
            '',
        ):
            with self.subTest(output=output), self.assertRaises(ValueError):
                preflight.validate_ufw_saved_rules(output)


class TargetPersistence(unittest.TestCase):
    def test_arbitrary_prefix_roundtrip(self):
        label = 'Сервер друга: "VPN" \'east\' $HOME `literal` \\ 🇫🇷'
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / 'target.env'
            writer.write_target(destination, {**GOOD, 'TARGET_LABEL': label})
            values = {}
            for line in destination.read_text(encoding='utf-8').splitlines():
                key, raw = line.split('=', 1)
                values[key] = shlex.split(raw)[0]
            self.assertEqual(values['TARGET_LABEL'], label)
            self.assertEqual(values['ACME_EMAIL'], GOOD['ACME_EMAIL'])
            self.assertEqual(values['TARGET_ADDRESS_MODE'], 'domain')
            with self.assertRaises(FileExistsError):
                writer.write_target(destination, GOOD)

    @unittest.skipIf(os.name == 'nt', 'Actual Bash environment fixture runs in Ubuntu CI')
    def test_prefix_is_literal_when_shell_sources_target(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / 'must-not-exist'
            label = f'Мой "VPN" $(touch {marker}) `touch {marker}` \'quote\' $HOME \\ 🇫🇷'
            destination = Path(temp) / 'target.env'
            writer.write_target(destination, {**GOOD, 'TARGET_LABEL': label})
            output = subprocess.check_output(['bash', '-c', 'source "$1"; printf "%s" "$TARGET_LABEL"', '_', str(destination)], text=True)
            self.assertEqual(output, label)
            self.assertFalse(marker.exists())

    @unittest.skipIf(os.name == 'nt', 'Actual OpenSSL/Bash generators run in Ubuntu CI')
    def test_fresh_installs_generate_distinct_access_secrets(self):
        source = (ROOT / 'bundle/scripts/configure-standalone.sh').read_text(encoding='utf-8')
        start = source.index('random_hex() {')
        end = source.index('vless_uuid=', start)
        generators = source[start:end]
        script = generators + '\nprintf "%s\\n" "$panel_username" "$panel_password" "$panel_base_path" "$subscription_path" "$subscription_id"\n'
        first = subprocess.check_output(['bash', '-c', script], text=True).splitlines()
        second = subprocess.check_output(['bash', '-c', script], text=True).splitlines()
        self.assertEqual(len(first), 5)
        self.assertTrue(all(a != b for a, b in zip(first, second)))
        self.assertEqual([len(v) for v in first[2:]], [64, 40, 64])


class Rendering(unittest.TestCase):
    def test_only_topology_replaced(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, GOOD):
            root = Path(temp)
            path = root / 'test.sh'
            path.write_text('@TARGET_IPV4@ @TARGET_INTERFACE@ $REALITY_PRIVATE_KEY\n', encoding='utf-8')
            renderer.render(root)
            self.assertEqual(path.read_text(), '8.8.4.4 enp1s0 $REALITY_PRIVATE_KEY\n')

    def test_no_unsafe_interface(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {**GOOD, 'TARGET_INTERFACE': 'eth0;id'}):
            with self.assertRaises(ValueError):
                renderer.render(Path(temp))


class Publication(unittest.TestCase):
    def test_no_old_target_in_executable_sources(self):
        banned = ['31.76.28.116', '31.76.9.84', 'germany.mrplhome.ru',
                  'germany.krysyuk.online', 'netherlands.mrplhome.ru', 'Z:\\VPN', '192.168.0.4']
        for path in (ROOT / 'bundle').rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                text = path.read_text(encoding='utf-8')
                for value in banned:
                    self.assertNotIn(value, text, f'{value} in {path}')


if __name__ == '__main__':
    unittest.main()
