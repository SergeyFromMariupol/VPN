"""Dedicated PHP-FPM pool and a temporary real execution probe for the site."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import sys
import tempfile


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


def probe(env):
    import grp
    spec = importlib.util.spec_from_file_location('php_decoy_core', Path(__file__).with_name('reality-decoy.py'))
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    endpoint, _, _ = core.settings(env)
    nonce = 'vpn-php-' + secrets.token_hex(24)
    descriptor, filename = tempfile.mkstemp(prefix='vpn-php-probe-', suffix='.php', dir=core.DOCUMENT_ROOT)
    path = Path(filename)
    inode = os.fstat(descriptor).st_ino
    try:
        with os.fdopen(descriptor, 'w') as stream:
            os.fchown(stream.fileno(), 0, grp.getgrnam('vpnsite').gr_gid)
            os.fchmod(stream.fileno(), 0o640)
            stream.write("<?php header('Content-Type: text/plain'); echo '" + nonce + "';")
        context = ssl.create_default_context()
        context.set_alpn_protocols(['http/1.1'])
        with context.wrap_socket(socket.create_connection(('127.0.0.1', 9443), timeout=10), server_hostname=endpoint) as connection:
            connection.sendall(f'GET /{path.name} HTTP/1.1\r\nHost: {endpoint}\r\nConnection: close\r\n\r\n'.encode())
            response = bytearray()
            while len(response) < 32768:
                data = connection.recv(4096)
                if not data:
                    break
                response.extend(data)
        head, _, body = bytes(response).partition(b'\r\n\r\n')
        if not head.startswith(b'HTTP/1.1 200 ') or nonce.encode() not in body or b'<?php' in body:
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
    else:
        raise SystemExit(2)
