"""Render and verify the local HTTPS target used by REALITY.

The public endpoint certificate is always checked against its own identity.
A different client SNI is an intentional decoy mode; it never counts as a
successful hostname check for the unrelated name.
"""
from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import sys


BODY = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Welcome</title><h1>Welcome</h1><p>This web service is online.</p></html>\n'
CONFIG = Path('/etc/nginx/conf.d/vpn-reality-decoy.conf')
DOCUMENT_ROOT = Path('/var/www/vpn-decoy/public')
PHP_MARKER = Path('/etc/vpn-reality-decoy/PHP_ENABLED')


def settings(env: dict) -> tuple[str, str, str]:
    mode = env.get('TARGET_REALITY_MODE', 'external')
    if mode not in ('self-steal', 'decoy') or env.get('TARGET_TLS_MODE', 'letsencrypt') != 'letsencrypt':
        raise ValueError('REALITY_DECOY_MODE')
    endpoint = env['TARGET_FQDN']
    address_mode = env.get('TARGET_ADDRESS_MODE', 'domain')
    if address_mode == 'ip':
        if mode == 'self-steal' or endpoint != str(ipaddress.IPv4Address(env['TARGET_IPV4'])):
            raise ValueError('REALITY_DECOY_ENDPOINT')
    elif address_mode == 'domain':
        if len(endpoint) > 253 or '.' not in endpoint or any(
                not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                for part in endpoint.split('.')):
            raise ValueError('REALITY_DECOY_ENDPOINT')
        try:
            ipaddress.ip_address(endpoint)
        except ValueError:
            pass
        else:
            raise ValueError('REALITY_DECOY_ENDPOINT')
    else:
        raise ValueError('REALITY_DECOY_ENDPOINT')
    sni = env['TARGET_REALITY_SNI']
    if len(sni) > 253 or '.' not in sni or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
            for part in sni.split('.')):
        raise ValueError('REALITY_DECOY_CLIENT_SNI')
    if mode == 'self-steal' and endpoint != sni:
        raise ValueError('REALITY_DECOY_SELF_STEAL_SNI')
    try:
        ipaddress.ip_address(sni)
    except ValueError:
        pass
    else:
        raise ValueError('REALITY_DECOY_CLIENT_SNI')
    name = env.get('TARGET_CERT_NAME') or endpoint
    if name != endpoint and not (address_mode == 'ip' and re.fullmatch(r'vpn-ip-[a-f0-9]{24}', name)):
        raise ValueError('REALITY_DECOY_CERT_NAME')
    return endpoint, sni, name


def render(env: dict, *, certificate_root=Path('/etc/letsencrypt/live'), port=9443,
           document_root=DOCUMENT_ROOT, php_enabled=False) -> str:
    endpoint, _, name = settings(env)
    # One default TLS vhost deliberately accepts arbitrary and absent SNI.
    # REALITY mirrors the authenticated client's ClientHello to this target too.
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError('REALITY_DECOY_PORT')
    if php_enabled:
        php = '''    location ~ \\.php$ {
        try_files $uri =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/vpn-decoy.sock;
    }
    location ~* \\.php(?:/|$) { return 404; }
'''
    else:
        php = '''    # Never serve PHP source when execution has not been enabled.
    location ~* \\.php(?:/|$) { return 404; }
'''
    index = 'index.php index.html' if php_enabled else 'index.html index.php'
    return f'''# Managed local REALITY target. No public listener is added.
server {{
    listen 127.0.0.1:{port} ssl http2 default_server;
    server_name {endpoint};
    ssl_certificate {(certificate_root / name / 'fullchain.pem').as_posix()};
    ssl_certificate_key {(certificate_root / name / 'privkey.pem').as_posix()};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    access_log off;
    error_log /dev/null crit;
    server_tokens off;
    root {document_root.as_posix()};
    index {index};
    autoindex off;
    location / {{ try_files $uri $uri/ =404; }}
    location ~ /\\. {{ deny all; }}
{php.rstrip()}
}}
'''


def php_is_enabled() -> bool:
    try:
        info = PHP_MARKER.lstat()
    except FileNotFoundError:
        return False
    if (not PHP_MARKER.is_file() or PHP_MARKER.is_symlink() or info.st_uid or info.st_nlink != 1 or
            info.st_mode & 0o777 != 0o600 or PHP_MARKER.read_bytes() != b'enabled\n'):
        raise ValueError('REALITY_DECOY_PHP_MARKER')
    return True


def render_active(env: dict) -> str:
    return render(env, php_enabled=php_is_enabled())


def render_aliases(env: dict) -> bytes:
    if env.get('TARGET_ADDRESS_MODE') != 'ip':
        raise ValueError('REALITY_DECOY_UNEXPECTED_ALIAS')
    access = Path('/etc/krysyuk-standalone/access.env')
    info = access.lstat()
    if not access.is_file() or access.is_symlink() or info.st_uid or info.st_nlink != 1 or info.st_mode & 0o777 != 0o600:
        raise ValueError('REALITY_DECOY_UNSAFE_ACCESS')
    values = {}
    for line in access.read_text().splitlines():
        if line.startswith('SUBSCRIPTION_URL='):
            key, _, value = line.partition('=')
            words = shlex.split(value)
            if len(words) != 1 or key in values:
                raise ValueError('REALITY_DECOY_ACCESS')
            values[key] = words[0]
    aliases = [str(ipaddress.IPv4Address(value)) for value in env.get('TARGET_ADDITIONAL_IPV4', '').split()]
    spec = importlib.util.spec_from_file_location('decoy_ip_network', Path(__file__).with_name('ip_network.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.nginx_aliases(aliases, values['SUBSCRIPTION_URL'])


def expected_leaf(certificate: Path) -> bytes:
    text = certificate.read_text(encoding='ascii')
    match = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.S)
    if not match:
        raise ValueError('REALITY_DECOY_CERTIFICATE')
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(match[0])).digest()


def connection(context: ssl.SSLContext, hostname: str | None):
    return context.wrap_socket(socket.create_connection(('127.0.0.1', 9443), timeout=8),
                               server_hostname=hostname)


def probe(env: dict, *, check_page=True) -> None:
    endpoint, sni, name = settings(env)
    leaf = expected_leaf(Path('/etc/letsencrypt/live') / name / 'fullchain.pem')
    context = ssl.create_default_context()
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2'])
    # Python validates an IP SAN and omits wire SNI when endpoint is an IP.
    with connection(context, endpoint) as stream:
        if (stream.version() != 'TLSv1.3' or stream.selected_alpn_protocol() != 'h2' or
                hashlib.sha256(stream.getpeercert(binary_form=True)).digest() != leaf):
            raise ValueError('REALITY_DECOY_TLS_IDENTITY')
    context.check_hostname = False
    # Trust is still checked. The unrelated name is intentionally NOT claimed
    # to match the own certificate. A scanner must get that same own leaf.
    for scanner_sni in dict.fromkeys((sni, 'probe.invalid', None)):
        with connection(context, scanner_sni) as stream:
            if (stream.version() != 'TLSv1.3' or stream.selected_alpn_protocol() != 'h2' or
                    hashlib.sha256(stream.getpeercert(binary_form=True)).digest() != leaf):
                raise ValueError('REALITY_DECOY_SCANNER_CERTIFICATE')
    if not check_page:
        return
    context.check_hostname = True
    context.set_alpn_protocols(['http/1.1'])
    with connection(context, endpoint) as stream:
        stream.sendall(f'GET / HTTP/1.1\r\nHost: {endpoint}\r\nConnection: close\r\n\r\n'.encode('ascii'))
        response = bytearray()
        while len(response) < 16384:
            data = stream.recv(4096)
            if not data:
                break
            response.extend(data)
        status = bytes(response).split(b'\r\n', 1)[0].split(b' ')
        if len(status) < 2 or status[0] != b'HTTP/1.1' or status[1] not in (b'200', b'301', b'302', b'303', b'307', b'308'):
            raise ValueError('REALITY_DECOY_SITE')


def main() -> None:
    if sys.argv[1:] == ['--nginx']:
        sys.stdout.write(render_active(os.environ))
    elif sys.argv[1:] == ['--default-page']:
        sys.stdout.write(BODY)
    elif sys.argv[1:] == ['--probe-target']:
        probe(os.environ)
        print('REALITY_DECOY_TARGET_OK=1')
    elif sys.argv[1:] == ['--probe-tls']:
        probe(os.environ, check_page=False)
        print('REALITY_DECOY_TLS_OK=1')
    elif sys.argv[1:] == ['--nginx-aliases']:
        sys.stdout.buffer.write(render_aliases(os.environ))
    else:
        raise SystemExit('usage: reality-decoy.py --nginx|--probe-target')


if __name__ == '__main__':
    main()
