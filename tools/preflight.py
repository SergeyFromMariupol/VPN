"""Read-only clean-host, input and public DNS checks. No packages are installed."""
import ipaddress
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import unicodedata

NETWORK_SPEC = importlib.util.spec_from_file_location(
    'vpn_network_contract', Path(__file__).resolve().parents[1] / 'bundle/scripts/network-contract.py')
NETWORK = importlib.util.module_from_spec(NETWORK_SPEC)
sys.modules[NETWORK_SPEC.name] = NETWORK
NETWORK_SPEC.loader.exec_module(NETWORK)

MANAGED_LOOPBACK_PORTS = frozenset((2053, 11111, 24443, 24444, 62789))
SSHD_EXECUTABLE = '/usr/sbin/sshd'
SYSTEMD_EXECUTABLE = '/usr/lib/systemd/systemd'
RESERVED_PATHS = (
    '/usr/local/x-ui', '/etc/x-ui', '/etc/nginx', '/etc/letsencrypt',
    '/etc/krysyuk-standalone', '/etc/wireguard', '/etc/openvpn', '/var/lib/docker',
    '/usr/sbin/policy-rc.d', '/etc/germanyvpn-xhttp-test', '/etc/germanyvpn-xhttp-warp',
    '/var/lib/cloudflare-warp', '/opt/vpn-certbot', '/usr/local/bin/certbot',
    '/etc/systemd/system/certbot.service.d', '/etc/systemd/system/certbot.timer.d',
    '/etc/systemd/system/x-ui.service', '/etc/systemd/system/x-ui.service.d',
    '/usr/local/share/krysyuk-bootstrap', '/var/lib/x-ui', '/var/log/x-ui',
    '/var/www/krysyuk-standalone-decoy', '/etc/systemd/system/nginx.service',
    '/etc/systemd/system/nginx.service.d',
    '/usr/local/lib/germanyvpn-xhttp-test',
    '/etc/systemd/system/germanyvpn-xhttp-test.service',
    '/etc/systemd/system/germanyvpn-xhttp-warp.service',
    '/etc/krysyuk-warp-egress', '/opt/krysyuk-warp-egress',
    '/usr/local/libexec/krysyuk-warp-egress', '/var/lib/krysyuk-warp-egress',
    '/var/lib/krysyuk-warp-egress-warp', '/var/log/krysyuk-warp-egress-warp',
    '/run/krysyuk-warp-egress', '/run/krysyuk-warp-egress-warp',
    '/etc/netns/krysyuk-warp', '/run/netns/krysyuk-warp',
    '/var/log/cloudflare-warp', '/run/cloudflare-warp',
    '/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg',
    '/etc/apt/sources.list.d/cloudflare-client.list',
    '/etc/apt/preferences.d/90-krysyuk-cloudflare-warp',
    '/etc/apt/preferences.d/00-germanyvpn-warp-bootstrap-freeze',
    '/etc/systemd/system/warp-svc.service',
    '/etc/systemd/system/multi-user.target.wants/warp-svc.service',
)
RESERVED_IDENTITIES = ('xui', 'xui-secrets', 'xraywarp', 'xhttp-test')


def reserved_path_conflicts(paths=RESERVED_PATHS) -> list[str]:
    conflicts = []
    for value in paths:
        path = Path(value)
        if path.exists() or path.is_symlink():
            conflicts.append(str(path))
    return conflicts


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=20,
                                   env=dict(os.environ, LC_ALL='C')).strip()


def virtualization() -> str:
    # systemd-detect-virt reports a normal physical host as "none" with status 1.
    result = subprocess.run(('systemd-detect-virt',), text=True, capture_output=True,
                            timeout=20, env=dict(os.environ, LC_ALL='C'))
    value = result.stdout.strip()
    if result.returncode == 0 or (result.returncode == 1 and value == 'none'):
        return value
    raise subprocess.CalledProcessError(result.returncode, result.args)


def validate_interface_addresses(records: list, env: dict) -> None:
    addresses = [address for record in records for address in record.get('addr_info', [])]
    if not any(address.get('local') == env['TARGET_IPV4'] for address in addresses):
        raise ValueError('IPv4 is not assigned to the selected interface')
    if any(address.get('scope') == 'global' and address.get('local') != env['TARGET_IPV4']
           for address in addresses):
        raise ValueError('The selected interface must have only the target global IPv4; '
                         'multiple addresses require a reviewed configuration')


def domain(value: str) -> bool:
    return (len(value) <= 253 and '.' in value and all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
        for p in value.split('.')))


def dns(name: str, qtype: int, resolver: str) -> list[str]:
    ident = secrets.randbelow(65536)
    question = b''.join(bytes([len(p)]) + p.encode('ascii') for p in name.split('.')) + b'\0'
    request = struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + question + struct.pack('!HH', qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(6)
        sock.connect((resolver, 53))
        sock.send(request)
        reply = sock.recv(65535)
    response_id, flags, questions, answers, _, _ = struct.unpack_from('!6H', reply)
    if response_id != ident or flags & 0x20f or not flags & 0x8000:
        raise ValueError(f'DNS failure from {resolver}')

    def skip_name(offset: int) -> int:
        for _ in range(128):
            length = reply[offset]
            offset += 1
            if length == 0:
                return offset
            if length & 0xc0 == 0xc0:
                return offset + 1
            if length > 63:
                raise ValueError('Invalid DNS name')
            offset += length
        raise ValueError('DNS name exceeds bounds')

    offset = 12
    for _ in range(questions):
        offset = skip_name(offset) + 4
    results = []
    for _ in range(answers):
        offset = skip_name(offset)
        kind, cls, _, size = struct.unpack_from('!HHIH', reply, offset)
        offset += 10
        payload = reply[offset:offset + size]
        offset += size
        if kind == 5:
            raise ValueError('Use an exact A record, not CNAME')
        if cls == 1 and kind == qtype:
            results.append(str(ipaddress.ip_address(payload)))
    return results


def validate_inputs(env: dict) -> None:
    address = ipaddress.IPv4Address(env['TARGET_IPV4'])
    if not address.is_global:
        raise ValueError('A directly assigned public IPv4 is required (NAT VPS unsupported)')
    mode = env.get('TARGET_ADDRESS_MODE', 'domain')
    if mode not in ('domain', 'ip'):
        raise ValueError('Invalid address mode')
    if mode == 'ip':
        if env['TARGET_FQDN'] != str(address):
            raise ValueError('IP endpoint must equal the server public IPv4')
    elif not domain(env['TARGET_FQDN']):
        raise ValueError('Invalid TARGET_FQDN')
    else:
        try:
            ipaddress.ip_address(env['TARGET_FQDN'])
        except ValueError:
            pass
        else:
            raise ValueError('Use IP mode for an IPv4 endpoint')
    if not domain(env['TARGET_REALITY_SNI']):
        raise ValueError('Invalid TARGET_REALITY_SNI')
    try:
        ipaddress.ip_address(env['TARGET_REALITY_SNI'])
    except ValueError:
        pass
    else:
        raise ValueError('REALITY SNI must be a DNS hostname')
    if 'cloudflare' in env['TARGET_REALITY_SNI']:
        raise ValueError('Cloudflare cannot be used as REALITY SNI')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', env['TARGET_INTERFACE']):
        raise ValueError('Public interface is missing or ambiguous')
    if not re.fullmatch(r'[1-9][0-9]{0,4}', env['TARGET_SSH_PORT']) or not 1 <= int(env['TARGET_SSH_PORT']) <= 65535:
        raise ValueError('Invalid SSH port')
    if int(env['TARGET_SSH_PORT']) in (80, 443, 2053, 2096, 8443, 8444, 24443, 24444):
        raise ValueError('SSH port conflicts with VPN services')
    if not re.fullmatch(r'0|[1-9][0-9]{0,3}|10000', env['TARGET_DEVICE_LIMIT']):
        raise ValueError('Invalid device limit')
    if not re.fullmatch(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', env['ACME_EMAIL']):
        raise ValueError('Invalid ACME email')
    label = env['TARGET_LABEL']
    if not 1 <= len(label) <= 80 or any(unicodedata.category(c) == 'Cc' or c in '\u2028\u2029' for c in label):
        raise ValueError('Invalid profile prefix')


def check_endpoint_dns(env: dict) -> None:
    if env.get('TARGET_ADDRESS_MODE', 'domain') == 'ip':
        return
    for resolver in ('1.1.1.1', '9.9.9.9'):
        if dns(env['TARGET_FQDN'], 1, resolver) != [env['TARGET_IPV4']]:
            raise ValueError(f'DNS A mismatch via {resolver}; use DNS only')
        if dns(env['TARGET_FQDN'], 28, resolver):
            raise ValueError('Remove AAAA before IPv4-only installation')


def trusted_ssh_process_executables(listeners) -> dict[int, str]:
    """Authenticate the executable behind each candidate SSH listener PID."""
    executables = {}
    for listener in listeners:
        if listener.protocol != 'tcp':
            continue
        for pid in listener.pids:
            try:
                executable = Path('/proc') / str(pid) / 'exe'
                canonical = executable.resolve(strict=True)
                info = executable.stat()
                if (str(canonical) in (SSHD_EXECUTABLE, SYSTEMD_EXECUTABLE)
                        and stat.S_ISREG(info.st_mode) and info.st_uid == 0
                        and not stat.S_IMODE(info.st_mode) & 0o022):
                    executables[pid] = str(canonical)
            except (OSError, RuntimeError):
                continue
    return executables


def systemd_ssh_socket_listens(port: int) -> bool:
    """Permit PID 1 only when the active ssh.socket owns this TCP port."""
    active = subprocess.run(('systemctl', 'is-active', '--quiet', 'ssh.socket'),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=20).returncode == 0
    if not active:
        return False
    listeners = run('systemctl', 'show', '--property=Listen', '--value', 'ssh.socket')
    return any(endpoint == str(port) or endpoint.endswith(':' + str(port))
               for endpoint in re.findall(r'(\S+)\s+\(Stream\)', listeners))


def validate_ufw_saved_rules(output: str) -> None:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if lines != ["Added user rules (see 'ufw status' for running firewall):", '(None)']:
        raise ValueError('existing UFW saved user rules')


def listener_conflicts(output: str, env: dict, process_executables=None,
                       ssh_process_executables=None, ssh_socket_listens=None) -> list[str]:
    listeners = NETWORK.parse_ss(output)
    if process_executables is None:
        process_executables = NETWORK.trusted_process_executables(listeners)
    if ssh_process_executables is None:
        ssh_process_executables = trusted_ssh_process_executables(listeners)
    conflicts = []
    ssh_listener_found = False
    for listener in listeners:
        if ipaddress.ip_address(listener.address).is_loopback:
            if listener.port in MANAGED_LOOPBACK_PORTS:
                conflicts.append(f'occupied managed loopback port: {listener.port}/{listener.protocol}')
            continue
        if listener.protocol == 'tcp' and listener.port == int(env['TARGET_SSH_PORT']):
            if listener.address not in (env['TARGET_IPV4'], '0.0.0.0', '::') or not listener.pids:
                conflicts.append('SSH listener has an unexpected address or no authenticated owner')
                continue
            if ssh_socket_listens is None and 1 in listener.pids:
                ssh_socket_listens = systemd_ssh_socket_listens(listener.port)
            owners = (ssh_process_executables.get(pid) == SSHD_EXECUTABLE
                      or (pid == 1 and ssh_process_executables.get(pid) == SYSTEMD_EXECUTABLE
                          and ssh_socket_listens is True)
                      for pid in listener.pids)
            if not all(owners):
                conflicts.append('SSH listener is not owned by trusted sshd/ssh.socket')
                continue
            ssh_listener_found = True
            continue
        if NETWORK.is_expected_dhcp(listener, env['TARGET_INTERFACE'], process_executables,
                                    target_ipv4=env['TARGET_IPV4']):
            continue
        scope = '%' + listener.scope if listener.scope else ''
        conflicts.append(f'listener: {listener.address}{scope}:{listener.port}/{listener.protocol}')
    if not ssh_listener_found:
        conflicts.append('missing authenticated SSH TCP listener on selected port')
    return conflicts


def main() -> None:
    validate_inputs(os.environ)
    conflicts = reserved_path_conflicts()
    listeners = run('ss', '-H', '-lntup')
    conflicts.extend(listener_conflicts(listeners, os.environ))
    for command, args in (('ufw', ('status',)), ('nft', ('list', 'ruleset'))):
        from shutil import which
        if which(command):
            output = run(command, *args)
            if (command == 'ufw' and 'Status: active' in output) or (command == 'nft' and output):
                conflicts.append(f'existing {command} rules')
            if command == 'ufw':
                try:
                    validate_ufw_saved_rules(run('ufw', 'show', 'added'))
                except ValueError as error:
                    conflicts.append(str(error))
    for identity in RESERVED_IDENTITIES:
        for database in ('passwd', 'group'):
            if subprocess.run(['getent', database, identity], stdout=subprocess.DEVNULL).returncode == 0:
                conflicts.append(f'existing {database} {identity}')
    from shutil import which
    for command in ('iptables-save', 'ip6tables-save'):
        if which(command):
            rules = run(command)
            if any(line.startswith('-A ') or (line.startswith(':') and ' ACCEPT ' not in line)
                   for line in rules.splitlines()):
                conflicts.append(f'existing {command} rules')
    if conflicts:
        raise ValueError('Server is not clean: ' + '; '.join(conflicts))
    addresses = json.loads(run('ip', '-j', '-4', 'address', 'show', 'dev', os.environ['TARGET_INTERFACE']))
    validate_interface_addresses(addresses, os.environ)
    if run('timedatectl', 'show', '-p', 'NTPSynchronized', '--value') != 'yes':
        raise ValueError('Wait for NTP synchronization before installing')
    check_endpoint_dns(os.environ)
    sni = os.environ['TARGET_REALITY_SNI']
    probe = subprocess.run(['timeout', '20', 'openssl', 's_client', '-connect', f'{sni}:443',
                            '-servername', sni, '-alpn', 'h2', '-tls1_3', '-verify_return_error',
                            '-verify_hostname', sni], input='', text=True, capture_output=True)
    output = probe.stdout + probe.stderr
    if probe.returncode or 'ALPN protocol: h2' not in output or 'Verification: OK' not in output:
        raise ValueError('REALITY target must pass trusted TLS1.3/H2 hostname validation')
    dns_status = 'NOT_REQUIRED_IP_MODE' if os.environ.get('TARGET_ADDRESS_MODE') == 'ip' else 'PASS'
    print(f'CLEAN_HOST=PASS DNS={dns_status} REALITY_TARGET_TLS=PASS')
    print('VIRTUALIZATION=' + virtualization())
    for args in (('uname', '-a'), ('free', '-m'), ('df', '-h', '/'),
                 ('ip', '-4', 'route'), ('ip', '-4', 'rule'), ('ip', '-6', 'route'),
                 ('ip', '-6', 'rule'), ('systemctl', 'list-units', '--type=service', '--state=running', '--no-pager')):
        print(run(*args))
    print(listeners)
    for key in Path('/etc/ssh').glob('ssh_host_*_key.pub'):
        print(run('ssh-keygen', '-lf', str(key)))
    print('CLIENT_SPEED_ACCEPTANCE=PENDING')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        print(f'PREFLIGHT_FAILED: {error}', file=sys.stderr)
        sys.exit(1)
