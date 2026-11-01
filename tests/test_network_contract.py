"""Offline public firewall/socket fixtures; no host changes or network calls."""
import importlib.util
import hashlib
from pathlib import Path, PurePosixPath
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('network_contract', ROOT / 'bundle/scripts/network-contract.py')
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)
IP, INTERFACE, SSH = '45.67.89.10', 'ens3', 2222
DEFAULTS = '''DEFAULT_INPUT_POLICY="DROP"
DEFAULT_OUTPUT_POLICY="ACCEPT"
DEFAULT_FORWARD_POLICY="DROP"
'''


def socket(protocol, endpoint, pid=None, name='fixture'):
    owner = f' users:(("{name}",pid={pid},fd=7))' if pid else ''
    state = 'LISTEN' if protocol == 'tcp' else 'UNCONN'
    return f'{protocol} {state} 0 4096 {endpoint} 0.0.0.0:*{owner}\n'


def sockets(promoted=True):
    text = socket('tcp', f'0.0.0.0:{SSH}') + socket('tcp', f'[::]:{SSH}')
    for port in [443, 2053, 2096, 8443] + ([8444] if promoted else []):
        text += socket('tcp', f'{IP}:{port}')
    text += socket('udp', f'{IP}:443')
    text += socket('udp', '127.0.0.53%lo:53')
    text += socket('tcp', '127.0.0.1:24443') + socket('tcp', '127.0.0.1:24444')
    return text


def firewall(promoted=True):
    text = ('Status: active\nLogging: on (low)\n'
            'Default: deny (incoming), allow (outgoing), deny (routed)\n'
            'New profiles: skip\n\nTo                         Action      From\n'
            '--                         ------      ----\n')
    for port, protocol in [(SSH, 'tcp'), (80, 'tcp'), (443, 'tcp'),
                           (443, 'udp'), (2096, 'tcp'), (8443, 'tcp')]:
        for suffix in ('', ' (v6)'):
            text += f'{str(port) + "/" + protocol + suffix:<40} ALLOW IN    Anywhere{suffix} # vpn\n'
    for port in [2053] + ([8444] if promoted else []):
        text += f'{IP + " " + str(port) + "/tcp on " + INTERFACE:<40} ALLOW IN    Anywhere # vpn\n'
    return text


class CertificateModeContract(unittest.TestCase):
    def test_none_mode_accepts_only_tcp_without_acme_or_hysteria_rules(self):
        listeners = sockets().replace(socket('udp', f'{IP}:443'), '')
        rules = '\n'.join(line for line in firewall().splitlines()
                          if not line.startswith(('80/tcp', '443/udp')))
        network.validate_listeners(network.parse_ss(listeners), IP, INTERFACE, SSH, True,
                                   tls_mode='none')
        network.validate_ufw(rules, IP, INTERFACE, SSH, True, DEFAULTS, 'none')

    def test_none_mode_rejects_hysteria_listener_and_extra_acme_rules(self):
        with self.assertRaises(ValueError):
            network.validate_listeners(network.parse_ss(sockets()), IP, INTERFACE, SSH, True,
                                       tls_mode='none')
        with self.assertRaises(ValueError):
            network.validate_ufw(firewall(), IP, INTERFACE, SSH, True, DEFAULTS, 'none')

    def test_default_letsencrypt_still_requires_hysteria(self):
        listeners = sockets().replace(socket('udp', f'{IP}:443'), '')
        with self.assertRaises(ValueError):
            network.validate_listeners(network.parse_ss(listeners), IP, INTERFACE, SSH, True)


class FirewallContract(unittest.TestCase):
    def check(self, text, promoted=True, defaults=DEFAULTS):
        network.validate_ufw(text, IP, INTERFACE, SSH, promoted, defaults)

    def test_baseline_and_promoted_exact_rules(self):
        for promoted in (False, True):
            self.check(firewall(promoted), promoted)

    def test_missing_8444_cannot_be_replaced_by_foreign_port(self):
        original = firewall()
        changed = original.replace(f'{IP} 8444/tcp on {INTERFACE}', '8888/tcp')
        self.assertEqual(original.count('ALLOW IN'), changed.count('ALLOW IN'))
        with self.assertRaises(ValueError):
            self.check(changed)

    def test_panel_and_8444_scope_direction_and_source_are_exact(self):
        for port in (2053, 8444):
            original = f'{IP} {port}/tcp on {INTERFACE}'
            for replacement in (f'{port}/tcp', f'{IP} {port}/tcp on ens4',
                                f'{IP} {port}/udp on {INTERFACE}'):
                with self.subTest(port=port, replacement=replacement), self.assertRaises(ValueError):
                    self.check(firewall().replace(original, replacement))
        for change in ('ALLOW OUT', 'DENY IN'):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check(firewall().replace('ALLOW IN', change, 1))
        with self.assertRaises(ValueError):
            self.check(firewall().replace('Anywhere # vpn', '8.8.8.8 # vpn', 1))

    def test_duplicate_and_extra_rules_rejected(self):
        for rule in ('8888/tcp ALLOW IN Anywhere', '443/tcp ALLOW IN Anywhere',
                     '24443/tcp ALLOW IN Anywhere'):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                self.check(firewall() + rule + '\n')

    def test_default_policies_checked_in_runtime_and_persistent_config(self):
        for key, before, after in [('INPUT', 'DROP', 'ACCEPT'), ('OUTPUT', 'ACCEPT', 'DROP'),
                                    ('FORWARD', 'DROP', 'ACCEPT')]:
            changed = DEFAULTS.replace(f'DEFAULT_{key}_POLICY="{before}"',
                                       f'DEFAULT_{key}_POLICY="{after}"')
            with self.subTest(policy=key), self.assertRaises(ValueError):
                self.check(firewall(), defaults=changed)
        for old, new in [('deny (incoming)', 'allow (incoming)'),
                         ('allow (outgoing)', 'deny (outgoing)'),
                         ('deny (routed)', 'allow (routed)')]:
            with self.subTest(default=old), self.assertRaises(ValueError):
                self.check(firewall().replace(old, new))
        with self.assertRaises(ValueError):
            self.check(firewall(), defaults=DEFAULTS + 'DEFAULT_INPUT_POLICY="DROP"\n')

    def test_disabled_routing_requires_persistent_drop(self):
        text = firewall().replace('deny (routed)', 'disabled (routed)')
        self.check(text)
        with self.assertRaises(ValueError):
            self.check(text, defaults=DEFAULTS.replace('DEFAULT_FORWARD_POLICY="DROP"',
                                                      'DEFAULT_FORWARD_POLICY="ACCEPT"'))


class ListenerContract(unittest.TestCase):
    def check(self, text, promoted=True, owners=None):
        network.validate_listeners(network.parse_ss(text), IP, INTERFACE, SSH, promoted, owners)

    def test_baseline_and_promoted_required_sockets(self):
        for promoted in (False, True):
            self.check(sockets(promoted), promoted)

    def test_missing_ssh_and_other_required_services_rejected(self):
        lines = sockets().splitlines(keepends=True)
        for port in (SSH, 443, 2053, 2096, 8443, 8444):
            changed = ''.join(line for line in lines
                              if not (line.startswith('tcp ') and line.split()[4].endswith(f':{port}')))
            with self.subTest(port=port), self.assertRaises(ValueError):
                self.check(changed)
        with self.assertRaises(ValueError):
            self.check(sockets().replace(socket('udp', f'{IP}:443'), ''))

    def test_foreign_ipv6_and_scoped_extras_rejected(self):
        for protocol, endpoint in [('tcp', f'{IP}:8888'), ('udp', f'{IP}:123'),
                                   ('tcp', '[::]:8888'), ('udp', '[fe80::1%ens3]:123'),
                                   ('tcp', '0.0.0.0%ens3:8888'), ('tcp', '[::]:443'),
                                   ('tcp', f'{IP}%ens4:443')]:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                self.check(sockets() + socket(protocol, endpoint))

    def test_malformed_listener_records_are_not_silently_ignored(self):
        for record in ('broken', socket('tcp', 'not-an-ip:8888'),
                       socket('tcp', '0.0.0.0%ens3%foreign:8888'),
                       socket('tcp', '[::1:8888'), socket('tcp', f'{IP}:0'),
                       socket('tcp', f'{IP}:65536')):
            with self.subTest(record=record), self.assertRaises(ValueError):
                network.parse_ss(record)

    def test_expected_dhcp_scoped_unscoped_and_direct_binds(self):
        for endpoint in ('0.0.0.0:68', '0.0.0.0%ens3:68', f'{IP}:68'):
            for executable in network.DHCP_EXECUTABLES:
                with self.subTest(endpoint=endpoint, executable=executable):
                    self.check(sockets() + socket('udp', endpoint, 41), owners={41: executable})

    def test_unowned_or_forged_dhcp_and_other_interface_rejected(self):
        valid_executable = '/usr/lib/systemd/systemd-networkd'
        cases = [(socket('udp', '0.0.0.0:68'), {}),
                 (socket('udp', '0.0.0.0:68', 41, 'systemd-network'), {}),
                 (socket('udp', '0.0.0.0:68', 41), {41: '/tmp/systemd-networkd'}),
                 (socket('udp', '0.0.0.0%ens4:68', 41), {41: valid_executable}),
                 (socket('udp', '8.8.8.8:68', 41), {41: valid_executable}),
                 (socket('udp', '[::]:546', 41), {41: valid_executable})]
        for record, owners in cases:
            with self.subTest(record=record, owners=owners), self.assertRaises(ValueError):
                self.check(sockets() + record, owners=owners)

    def test_proc_owner_resolution_requires_trusted_unwritable_root_binary(self):
        listener = network.parse_ss(socket('udp', '0.0.0.0%ens3:68', 41))
        for path, uid, mode, expected in [('/usr/lib/systemd/systemd-networkd', 0, 0o755, True),
                                          ('/usr/sbin/dhclient', 0, 0o755, True),
                                          ('/tmp/systemd-networkd', 0, 0o755, False),
                                          ('/usr/lib/systemd/systemd-networkd', 1000, 0o755, False),
                                          ('/usr/lib/systemd/systemd-networkd', 0, 0o775, False)]:
            with self.subTest(path=path, uid=uid, mode=mode):
                info = SimpleNamespace(st_uid=uid, st_mode=stat.S_IFREG | mode)
                with patch.object(network.Path, 'resolve', return_value=PurePosixPath(path)), \
                        patch.object(network.Path, 'stat', return_value=info):
                    owners = network.trusted_process_executables(listener)
                self.assertEqual(owners, {41: path} if expected else {})


class ListenerConvergence(unittest.TestCase):
    def listeners(self, extra=''):
        return network.parse_ss(sockets() + extra)

    def wait(self, snapshot, owners=frozenset((41,)), clock=(0, 0)):
        with patch.object(network, 'trusted_managed_udp_owners', return_value=owners), \
                patch.object(network.time, 'monotonic', side_effect=clock), \
                patch.object(network.time, 'sleep') as sleep:
            network.wait_for_strict_listeners(snapshot, IP, INTERFACE, SSH, True)
        return sleep

    def test_owned_udp_must_disappear_before_success(self):
        temporary = self.listeners(socket('udp', '*:34192', 41, 'xray-linux-amd6'))
        snapshots = iter((temporary, self.listeners()))
        with self.assertRaisesRegex(ValueError, r'udp \[0.0.0.0\]:34192 pids=41'):
            network.validate_listeners(temporary, IP, INTERFACE, SSH, True)
        sleep = self.wait(lambda: next(snapshots))
        sleep.assert_called_once_with(2)

    def test_owned_udp_that_persists_fails_at_deadline(self):
        temporary = self.listeners(socket('udp', '*:34192', 41))
        with self.assertRaisesRegex(ValueError, 'did not expire within 90s'):
            self.wait(lambda: temporary, clock=(0, 0, 90))

    def test_unowned_udp_and_any_unauthenticated_coowner_fail_without_waiting(self):
        for extra, owners in [(socket('udp', '*:34192'), {41}),
                              (socket('udp', '*:34192', 41), set()),
                              (socket('udp', '*:34192', 41) + socket('udp', '*:34193', 42), {41})]:
            with self.subTest(extra=extra):
                with patch.object(network.time, 'sleep') as sleep, self.assertRaises(ValueError):
                    self.wait(lambda: self.listeners(extra), owners=owners, clock=(0,))
                sleep.assert_not_called()
        extra = socket('udp', '*:34192', 41).replace('fd=7))', 'fd=7),("other",pid=42,fd=8))')
        with self.assertRaises(ValueError):
            self.wait(lambda: self.listeners(extra), clock=(0,))

    def test_missing_required_listener_or_extra_tcp_cannot_be_retried(self):
        extra = socket('udp', '*:34192', 41)
        bad = (self.listeners(extra + socket('tcp', f'{IP}:8888')),
               network.parse_ss((sockets() + extra).replace(socket('udp', f'{IP}:443'), '')),
               network.parse_ss((sockets() + extra).replace(socket('tcp', f'{IP}:2053'), '')))
        for listeners in bad:
            with self.subTest(listeners=listeners), self.assertRaises(ValueError):
                self.wait(lambda: listeners, clock=(0,))

    def test_malformed_snapshot_and_excessive_timeout_fail_immediately(self):
        with patch.object(network.time, 'sleep') as sleep:
            with self.assertRaises(ValueError):
                network.wait_for_strict_listeners(lambda: network.parse_ss('broken'),
                                                  IP, INTERFACE, SSH, True)
            for timeout in (-1, 91):
                with self.assertRaises(ValueError):
                    network.wait_for_strict_listeners(lambda: self.listeners(),
                                                      IP, INTERFACE, SSH, True, timeout)
        sleep.assert_not_called()

    def test_real_image_path_uid_root_ownership_permissions_and_digest_required(self):
        listeners = self.listeners(socket('udp', '*:34192', 41))
        image = b'offline pinned-image fixture'
        digest = hashlib.sha256(image).hexdigest()
        cases = [(network.MAIN_XRAY, 0, 0o755, '1001 1001 1001 1001', digest, True, True),
                 (network.XHTTP_XRAY, 0, 0o750, '1001 1001 1001 1001', digest, True, True),
                 (network.XHTTP_XRAY, 0, 0o750, '1001 1001 1001 1001', digest, False, False),
                 ('/tmp/xray-linux-amd64', 0, 0o755, '1001 1001 1001 1001', digest, True, False),
                 (network.MAIN_XRAY, 1001, 0o755, '1001 1001 1001 1001', digest, True, False),
                 (network.MAIN_XRAY, 0, 0o775, '1001 1001 1001 1001', digest, True, False),
                 (network.MAIN_XRAY, 0, 0o755, '1001 0 1001 1001', digest, True, False),
                 (network.MAIN_XRAY, 0, 0o755, '1001 1001', digest, True, False),
                 (network.MAIN_XRAY, 0, 0o755, '1001 1001 1001 1001', '0' * 64, True, False)]
        for path, owner, mode, uids, pin, promoted, expected in cases:
            with self.subTest(path=path, owner=owner, mode=mode, uids=uids, pin=pin, promoted=promoted):
                info = SimpleNamespace(st_uid=owner, st_mode=stat.S_IFREG | mode)
                with patch.object(network.Path, 'resolve', return_value=PurePosixPath(path)), \
                        patch.object(network.Path, 'stat', return_value=info), \
                        patch.object(network.Path, 'read_text', return_value='Uid:\t' + uids + '\n'), \
                        patch.object(network.Path, 'read_bytes', return_value=image), \
                        patch.object(network, 'managed_uid', return_value=1001), \
                        patch.object(network, 'XRAY_SHA256', pin):
                    owners = network.trusted_managed_udp_owners(listeners, promoted)
                self.assertEqual(owners, {41} if expected else set())


if __name__ == '__main__':
    unittest.main()
