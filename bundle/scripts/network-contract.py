#!/usr/bin/env python3
"""Read-only checks for the installer's public sockets and UFW contract."""
import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time
from typing import NamedTuple


DHCP_EXECUTABLES = frozenset(('/usr/lib/systemd/systemd-networkd', '/usr/sbin/dhclient'))
XRAY_SHA256 = '64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d'
MAIN_XRAY = '/usr/local/x-ui/bin/xray-linux-amd64'
XHTTP_XRAY = '/usr/local/lib/germanyvpn-xhttp-test/xray'


class Listener(NamedTuple):
    protocol: str
    address: str
    port: int
    scope: str | None
    pids: tuple[int, ...]


def parse_ss(text):
    """Parse LC_ALL=C ss -H -lntup; malformed records fail closed."""
    listeners = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ('tcp', 'udp'):
            raise ValueError('Malformed listener record')
        protocol, state = fields[:2]
        if state != ('LISTEN' if protocol == 'tcp' else 'UNCONN'):
            raise ValueError('Unexpected listener state')
        local = fields[4]
        host, separator, port = local.rpartition(':')
        if not separator or not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
            raise ValueError('Malformed listener endpoint')
        if host.startswith('['):
            if not host.endswith(']'):
                raise ValueError('Malformed bracketed listener address')
            host = host[1:-1]
        elif '[' in host or ']' in host:
            raise ValueError('Malformed listener address')
        address, scoped, scope = host.partition('%')
        if scoped and not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', scope):
            raise ValueError('Malformed listener interface scope')
        try:
            normalized = str(ipaddress.ip_address('0.0.0.0' if address == '*' else address))
        except ValueError as error:
            raise ValueError('Malformed listener IP address') from error
        pids = tuple(sorted(set(int(pid) for pid in re.findall(r'\bpid=([1-9][0-9]*)\b', line))))
        listeners.append(Listener(protocol, normalized, int(port), scope if scoped else None, pids))
    return listeners


def trusted_process_executables(listeners):
    """Resolve DHCP socket owners through /proc, not their mutable process names."""
    executables = {}
    for listener in listeners:
        if listener.protocol != 'udp' or listener.port != 68:
            continue
        for pid in listener.pids:
            try:
                executable = Path('/proc') / str(pid) / 'exe'
                canonical = executable.resolve(strict=True)
                info = executable.stat()
                if (str(canonical) in DHCP_EXECUTABLES and stat.S_ISREG(info.st_mode)
                        and info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022):
                    executables[pid] = str(canonical)
            except (OSError, RuntimeError):
                continue
    return executables


def is_expected_dhcp(listener, target_interface, process_executables, target_ipv4=None):
    """Allow DHCPv4 infrastructure only with an authenticated executable owner."""
    addresses = {'0.0.0.0'}
    if target_ipv4 is not None:
        addresses.add(str(ipaddress.IPv4Address(target_ipv4)))
    return (listener.protocol == 'udp' and listener.port == 68
            and listener.address in addresses and listener.scope in (None, target_interface)
            and bool(listener.pids)
            and all(process_executables.get(pid) in DHCP_EXECUTABLES for pid in listener.pids))


def listener_summary(listener):
    scope = '%' + listener.scope if listener.scope else ''
    owners = ','.join(map(str, listener.pids)) or 'none'
    return f'{listener.protocol} [{listener.address}{scope}]:{listener.port} pids={owners}'


def managed_uid(name):
    import pwd
    return pwd.getpwnam(name).pw_uid


def trusted_managed_udp_owners(listeners, promoted):
    """Authenticate running managed Xray images, never their display names."""
    expected = {MAIN_XRAY: 'xui'}
    if promoted:
        expected[XHTTP_XRAY] = 'xhttp-test'
    authenticated = set()
    for pid in {pid for listener in listeners for pid in listener.pids}:
        try:
            process = Path('/proc') / str(pid)
            executable = process / 'exe'
            canonical = str(executable.resolve(strict=True))
            if canonical not in expected:
                continue
            info = executable.stat()
            uid = managed_uid(expected[canonical])
            uids = re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$',
                             (process / 'status').read_text(), re.M)
            if (uid <= 0 or uids is None or any(int(value) != uid for value in uids.groups())
                    or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022):
                continue
            if hashlib.sha256(executable.read_bytes()).hexdigest() == XRAY_SHA256:
                authenticated.add(pid)
        except (OSError, RuntimeError, KeyError, ImportError):
            continue
    return authenticated


def validate_listeners(listeners, target_ipv4, target_interface, ssh_port, promoted,
                       process_executables=None):
    target_ipv4 = str(ipaddress.IPv4Address(target_ipv4))
    ssh_port = int(ssh_port)
    process_executables = process_executables or {}
    required_tcp = {ssh_port, 443, 2053, 2096, 8443}
    if promoted:
        required_tcp.add(8444)
    found_tcp, found_udp = set(), set()
    for listener in listeners:
        if ipaddress.ip_address(listener.address).is_loopback:
            continue
        if is_expected_dhcp(listener, target_interface, process_executables, target_ipv4):
            continue
        if listener.scope not in (None, target_interface):
            raise ValueError('Unexpected public listener interface: ' + listener_summary(listener))
        if listener.protocol == 'tcp' and listener.port == ssh_port:
            if listener.address not in (target_ipv4, '0.0.0.0', '::'):
                raise ValueError('SSH listener is not bound to the server address: ' + listener_summary(listener))
            found_tcp.add(ssh_port)
        elif listener.address != target_ipv4:
            raise ValueError('Unexpected public listener address: ' + listener_summary(listener))
        elif listener.protocol == 'tcp' and listener.port in required_tcp:
            found_tcp.add(listener.port)
        elif listener.protocol == 'udp' and listener.port == 443:
            found_udp.add(443)
        else:
            raise ValueError('Unexpected public listener port: ' + listener_summary(listener))
    if found_tcp != required_tcp or found_udp != {443}:
        raise ValueError('Required public listener is missing')


def wait_for_strict_listeners(read_listeners, target_ipv4, target_interface, ssh_port,
                              promoted, wait_seconds=90):
    """Let owned self-test UDP sessions expire; PASS still needs the exact contract.

    Xray's outbound UDP sockets are unconnected and therefore appear in ss -l.
    Closing a self-test client does not immediately expire its server session.
    Only those authenticated extra sockets can cause a bounded retry. Required
    services, other public sockets and the strict validator stay unchanged.
    """
    if not 0 <= wait_seconds <= 90:
        raise ValueError('Listener convergence timeout must be between 0 and 90 seconds')
    deadline = time.monotonic() + wait_seconds
    while True:
        listeners = read_listeners()
        dhcp_owners = trusted_process_executables(listeners)
        try:
            validate_listeners(listeners, target_ipv4, target_interface, ssh_port,
                               promoted, dhcp_owners)
            return
        except ValueError as error:
            extras = [listener for listener in listeners
                      if listener.protocol == 'udp'
                      and not ipaddress.ip_address(listener.address).is_loopback
                      and not is_expected_dhcp(listener, target_interface, dhcp_owners, target_ipv4)
                      and not (listener.address == target_ipv4 and listener.port == 443
                               and listener.scope in (None, target_interface))]
            if not extras:
                raise
            # Removing the candidate sessions must leave every required listener
            # and no other mismatch; this is only a retry eligibility check.
            validate_listeners([listener for listener in listeners if listener not in extras],
                               target_ipv4, target_interface, ssh_port, promoted, dhcp_owners)
            owners = trusted_managed_udp_owners(extras, promoted)
            if any(not listener.pids or not set(listener.pids) <= owners for listener in extras):
                raise error
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Managed UDP sessions did not expire within '
                                 f'{wait_seconds}s; {error}') from error
            time.sleep(min(2, remaining))


def validate_ufw(text, target_ipv4, target_interface, ssh_port, promoted, defaults_text):
    """Require exact rules, including direction, address scope and default policies."""
    lines = text.splitlines()
    if lines.count('Status: active') != 1:
        raise ValueError('UFW is not active')
    policies = {}
    for line in defaults_text.splitlines():
        match = re.fullmatch(r'\s*(DEFAULT_(?:INPUT|OUTPUT|FORWARD)_POLICY)\s*=\s*(.*?)\s*', line)
        if not match:
            continue
        key, raw = match.groups()
        values = shlex.split(raw, comments=True)
        if key in policies or len(values) != 1:
            raise ValueError('Malformed UFW default policy')
        policies[key] = values[0]
    if policies != {'DEFAULT_INPUT_POLICY': 'DROP', 'DEFAULT_OUTPUT_POLICY': 'ACCEPT',
                    'DEFAULT_FORWARD_POLICY': 'DROP'}:
        raise ValueError('Unexpected UFW persistent default policies')
    defaults = [line for line in lines if line.startswith('Default:')]
    # UFW reports disabled routing when kernel forwarding is off; the persistent
    # DROP policy above still governs routed traffic once forwarding is enabled.
    if len(defaults) != 1 or defaults[0] not in (
            'Default: deny (incoming), allow (outgoing), deny (routed)',
            'Default: deny (incoming), allow (outgoing), disabled (routed)'):
        raise ValueError('Unexpected UFW default policies')
    rules, in_rules = [], False
    for line in lines:
        if re.fullmatch(r'To\s+Action\s+From', line.strip()):
            if in_rules:
                raise ValueError('Duplicate UFW rules header')
            in_rules = True
            continue
        if not in_rules:
            continue
        line = line.split('#', 1)[0].strip()
        if not line or re.fullmatch(r'[-\s]+', line):
            continue
        match = re.fullmatch(r'(.*?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+(.*?)', line)
        if not match:
            raise ValueError('Malformed UFW rule')
        rules.append(tuple(' '.join(value.split()) for value in match.groups()))
    baseline = [(int(ssh_port), 'tcp'), (80, 'tcp'), (443, 'tcp'),
                (443, 'udp'), (2096, 'tcp'), (8443, 'tcp')]
    expected = set()
    for port, protocol in baseline:
        endpoint = f'{port}/{protocol}'
        expected.add((endpoint, 'ALLOW', 'IN', 'Anywhere'))
        expected.add((endpoint + ' (v6)', 'ALLOW', 'IN', 'Anywhere (v6)'))
    for port in ([2053, 8444] if promoted else [2053]):
        expected.add((f'{target_ipv4} {port}/tcp on {target_interface}', 'ALLOW', 'IN', 'Anywhere'))
    if len(rules) != len(expected) or set(rules) != expected:
        raise ValueError('UFW rules differ from the exact required ports and scope')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target-ip', required=True)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--ssh-port', type=int, required=True)
    parser.add_argument('--promoted', choices=('0', '1'), required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('root is required to authenticate listener owners')
    environment = dict(os.environ, LC_ALL='C')
    def output(command):
        return subprocess.run(command, check=True, text=True, capture_output=True,
                              env=environment, timeout=30).stdout
    try:
        wait_for_strict_listeners(lambda: parse_ss(output(['ss', '-H', '-lntup'])),
                                 args.target_ip, args.interface, args.ssh_port,
                                 args.promoted == '1')
        validate_ufw(output(['ufw', 'status', 'verbose']), args.target_ip, args.interface,
                     args.ssh_port, args.promoted == '1', Path('/etc/default/ufw').read_text())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit('NETWORK_CONTRACT_FAILED: ' + str(error)) from error
    print('NETWORK_CONTRACT_OK=1')


if __name__ == '__main__':
    main()
