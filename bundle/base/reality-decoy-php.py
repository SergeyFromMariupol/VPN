"""Dedicated PHP-FPM pool and a temporary real execution probe for the site."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time


POOL = '''; Managed unprivileged PHP pool for the public decoy website.
[vpn-decoy]
user = vpnsite
group = vpnsite
listen = /run/php/vpn-decoy.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 10s
pm.max_requests = 200
clear_env = yes
catch_workers_output = no
request_terminate_timeout = 30s
security.limit_extensions = .php
php_admin_value[open_basedir] = /var/www/vpn-decoy/public:/var/lib/vpn-decoy/tmp
php_admin_value[upload_tmp_dir] = /var/lib/vpn-decoy/tmp
php_admin_value[session.save_path] = /var/lib/vpn-decoy/tmp
php_admin_value[error_log] = /var/lib/vpn-decoy/tmp/php-errors.log
php_admin_value[memory_limit] = 128M
php_admin_flag[display_errors] = off
php_admin_flag[log_errors] = on
'''
FPM_SOCKET = Path('/run/php/vpn-decoy.sock')
FPM_EXECUTABLE = Path('/usr/sbin/php-fpm8.3')


def unit_state(timeout=5):
    result = subprocess.run(('systemctl', 'show', 'php8.3-fpm.service', '-p', 'LoadState',
                             '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID'),
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=min(5, timeout), check=True,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'})
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def fpm_ready(*, timeout=5, read_unit=unit_state, socket_path=FPM_SOCKET,
              executable=FPM_EXECUTABLE, web_identity=None, master_uid=0, binary_uid=0):
    """Require a correctly owned live pool socket held by the current FPM master.

    Merely seeing the service active or a socket pathname is insufficient:
    USR2 reload is asynchronous and stale/unrelated Unix sockets can exist.
    The optional parameters support isolated process/socket tests; the CLI
    always uses the fixed production paths and root/www-data identities.
    """
    import grp
    import pwd
    unit = read_unit(timeout)
    if (unit.get('LoadState') != 'loaded' or unit.get('ActiveState') != 'active' or
            unit.get('SubState') != 'running' or not unit.get('MainPID', '').isdigit() or
            int(unit['MainPID']) < 1):
        raise ValueError('REALITY_DECOY_PHP_UNIT_NOT_READY')
    if web_identity is None:
        web_identity = (pwd.getpwnam('www-data').pw_uid, grp.getgrnam('www-data').gr_gid)
    info = socket_path.lstat()
    if (not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o660 or
            (info.st_uid, info.st_gid) != web_identity):
        raise ValueError('REALITY_DECOY_PHP_SOCKET_IDENTITY')
    process = Path('/proc') / unit['MainPID']
    canonical = executable.resolve(strict=True)
    binary = canonical.stat()
    if ((process / 'exe').resolve(strict=True) != canonical or not stat.S_ISREG(binary.st_mode) or
            binary.st_uid != binary_uid or binary.st_mode & 0o022):
        raise ValueError('REALITY_DECOY_PHP_MASTER_BINARY')
    identities = [line.split()[1:] for line in (process / 'status').read_text().splitlines()
                  if line.startswith('Uid:')]
    if identities != [[str(master_uid)] * 4]:
        raise ValueError('REALITY_DECOY_PHP_MASTER_IDENTITY')
    listening = set()
    for line in Path('/proc/net/unix').read_text().splitlines()[1:]:
        fields = line.split(maxsplit=7)
        if (len(fields) == 8 and fields[7] == str(socket_path) and fields[4] == '0001' and
                int(fields[3], 16) & 0x10000):
            listening.add('socket:[' + fields[6] + ']')
    held = set()
    for descriptor in (process / 'fd').iterdir():
        try:
            held.add(os.readlink(descriptor))
        except FileNotFoundError:
            continue
    if not listening or not listening.intersection(held):
        raise ValueError('REALITY_DECOY_PHP_SOCKET_NOT_HELD_BY_MASTER')


def wait_ready(check, *, timeout=30, interval=0.2, error_code='REALITY_DECOY_PHP_NOT_READY'):
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(error_code) from None
        try:
            check(remaining)
            return
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            # A PHP source response is never a normal reload transition.
            if str(error) == 'REALITY_DECOY_PHP_SOURCE_EXPOSED':
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(error_code) from None
            time.sleep(min(interval, remaining))


def check_ubuntu_source(package_policy: str, repository_policy: str) -> None:
    """Match the selected package's origins to APT's authenticated release data."""
    origins = {}
    repository = None
    for line in repository_policy.splitlines():
        match = re.match(r'\s*\d+\s+(https?://\S+\s+\S+\s+\S+\s+Packages)\s*$', line)
        if match:
            repository = match[1]
        elif repository is not None and line.strip().startswith('release '):
            fields = line.strip().removeprefix('release ').split(',')
            origins[repository] = 'o=Ubuntu' in fields
            repository = None
    candidate_match = re.search(r'^\s*Candidate:\s*(\S+)\s*$', package_policy, re.M)
    if candidate_match is None or candidate_match[1] == '(none)':
        raise ValueError('REALITY_DECOY_PHP_PACKAGE_UNAVAILABLE')
    candidate = candidate_match[1]
    in_candidate = False
    sources = []
    for line in package_policy.splitlines():
        version = re.match(r'\s*(?:\*\*\*\s+)?(\S+)\s+\d+\s*$', line)
        if version:
            in_candidate = version[1] == candidate
            continue
        source = re.match(r'\s*\d+\s+(https?://\S+\s+\S+\s+\S+\s+Packages)\s*$', line)
        if source and in_candidate:
            sources.append(source[1])
    if not sources or any(not origins.get(source, False) for source in sources):
        raise ValueError('REALITY_DECOY_PHP_UNTRUSTED_ORIGIN')


def probe(env, *, timeout=10):
    import grp
    spec = importlib.util.spec_from_file_location('php_decoy_core', Path(__file__).with_name('reality-decoy.py'))
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    endpoint, _, _ = core.settings(env)
    nonce = 'vpn-php-' + secrets.token_hex(24)
    descriptor, filename = tempfile.mkstemp(prefix='vpn-php-probe-', suffix='.php', dir=core.DOCUMENT_ROOT)
    path = Path(filename)
    inode = os.fstat(descriptor).st_ino
    deadline = time.monotonic() + timeout
    try:
        with os.fdopen(descriptor, 'w') as stream:
            os.fchown(stream.fileno(), 0, grp.getgrnam('vpnsite').gr_gid)
            os.fchmod(stream.fileno(), 0o640)
            stream.write("<?php header('Content-Type: text/plain'); echo '" + nonce + "';")
        context = ssl.create_default_context()
        context.set_alpn_protocols(['http/1.1'])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('REALITY_DECOY_PHP_PROBE_TIMEOUT')
        with context.wrap_socket(socket.create_connection(('127.0.0.1', 9443), timeout=remaining), server_hostname=endpoint) as connection:
            connection.sendall(f'GET /{path.name} HTTP/1.1\r\nHost: {endpoint}\r\nConnection: close\r\n\r\n'.encode())
            response = bytearray()
            while len(response) < 32768:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('REALITY_DECOY_PHP_PROBE_TIMEOUT')
                connection.settimeout(remaining)
                data = connection.recv(4096)
                if not data:
                    break
                response.extend(data)
        head, _, body = bytes(response).partition(b'\r\n\r\n')
        if b'<?php' in body:
            raise ValueError('REALITY_DECOY_PHP_SOURCE_EXPOSED')
        if not head.startswith(b'HTTP/1.1 200 ') or nonce.encode() not in body:
            raise ValueError('REALITY_DECOY_PHP_EXECUTION')
    finally:
        if path.exists():
            if path.is_symlink() or path.stat().st_ino != inode:
                raise ValueError('REALITY_DECOY_PHP_PROBE_REPLACED')
            path.unlink()


if __name__ == '__main__':
    if sys.argv[1:] == ['--pool']:
        sys.stdout.write(POOL)
    elif len(sys.argv) == 4 and sys.argv[1] == '--check-ubuntu-source':
        check_ubuntu_source(Path(sys.argv[2]).read_text(), Path(sys.argv[3]).read_text())
    elif sys.argv[1:] == ['--probe-php'] and os.geteuid() == 0:
        probe(os.environ)
        print('REALITY_DECOY_PHP_OK=1')
    elif sys.argv[1:] == ['--wait-fpm'] and os.geteuid() == 0:
        wait_ready(lambda remaining: fpm_ready(timeout=remaining), error_code='REALITY_DECOY_PHP_SOCKET_TIMEOUT')
        print('REALITY_DECOY_PHP_SOCKET_OK=1')
    elif sys.argv[1:] == ['--wait-php'] and os.geteuid() == 0:
        wait_ready(lambda remaining: probe(os.environ, timeout=min(10, remaining)),
                   error_code='REALITY_DECOY_PHP_PAYLOAD_TIMEOUT')
        print('REALITY_DECOY_PHP_OK=1')
    else:
        raise SystemExit(2)
