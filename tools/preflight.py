"""Read-only clean-host, input and public DNS checks. No packages are installed."""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import sys
import unicodedata


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=20).strip()


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


def main() -> None:
    validate_inputs(os.environ)
    conflicts = []
    for name in ('/usr/local/x-ui', '/etc/x-ui', '/etc/nginx', '/etc/letsencrypt',
                 '/etc/krysyuk-standalone', '/etc/wireguard', '/etc/openvpn',
                 '/var/lib/docker', '/usr/sbin/policy-rc.d', '/etc/germanyvpn-xhttp-test',
                 '/etc/germanyvpn-xhttp-warp', '/var/lib/cloudflare-warp',
                 '/opt/vpn-certbot', '/usr/local/bin/certbot',
                 '/etc/systemd/system/certbot.service.d', '/etc/systemd/system/certbot.timer.d'):
        path = Path(name)
        if path.exists() or path.is_symlink():
            conflicts.append(name)
    listeners = run('ss', '-H', '-lntup')
    for line in listeners.splitlines():
        parts = line.split()
        local = parts[4]
        host, _, port = local.rpartition(':')
        # Allow local stub resolver and stock loopback agents; inspect all WAN listeners.
        if host.strip('[]') in ('127.0.0.1', '127.0.0.53', '127.0.0.54', '::1'):
            continue
        if port == os.environ['TARGET_SSH_PORT'] and parts[0] == 'tcp':
            continue
        if parts[0] == 'udp' and port == '68':  # stock DHCP client
            continue
        conflicts.append(f'listener: {local}/{parts[0]}')
    for command, args in (('ufw', ('status',)), ('nft', ('list', 'ruleset'))):
        from shutil import which
        if which(command):
            output = run(command, *args)
            if (command == 'ufw' and 'Status: active' in output) or (command == 'nft' and output):
                conflicts.append(f'existing {command} rules')
    for identity in ('xui', 'xui-secrets', 'xraywarp'):
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
    if not any(a.get('local') == os.environ['TARGET_IPV4'] for i in addresses for a in i.get('addr_info', [])):
        raise ValueError('IPv4 is not assigned to the selected interface')
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
    for args in (('uname', '-a'), ('systemd-detect-virt',), ('free', '-m'), ('df', '-h', '/'),
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
