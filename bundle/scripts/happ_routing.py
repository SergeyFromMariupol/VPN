#!/usr/bin/env python3
"""Generate and verify routing and Android app settings for subscriptions."""

import base64
import http.client
import io
import json
import os
from pathlib import Path
import re
import runpy
import sys


GEO_URL = 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/'
MAX_HEADER_BYTES = 16 * 1024
SCRIPT_DIR = Path(__file__).resolve().parent
ANDROID_PACKAGE = re.compile(r'[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+')


def routing_link(profile_name):
    # Happ uses the first outbound for unmatched traffic. Keep proxy first and
    # separate domain and IP matches so either can select the direct outbound.
    profile = {
        'Name': profile_name,
        'GlobalProxy': 'true',
        'RemoteDNSType': 'DoH',
        'RemoteDNSDomain': 'https://cloudflare-dns.com/dns-query',
        'RemoteDNSIP': '1.1.1.1',
        'DomesticDNSType': 'DoH',
        'DomesticDNSDomain': 'https://dns.google/dns-query',
        'DomesticDNSIP': '8.8.8.8',
        'DnsHosts': {'cloudflare-dns.com': '1.1.1.1', 'dns.google': '8.8.8.8'},
        'Geoipurl': GEO_URL + 'geoip.dat',
        'Geositeurl': GEO_URL + 'geosite.dat',
        'DirectSites': ['geosite:private', 'geosite:category-ru',
                        'domain:ru', 'domain:xn--p1ai', 'domain:su'],
        'DirectIp': ['geoip:private', 'geoip:ru'],
        'ProxySites': [],
        'ProxyIp': [],
        'BlockSites': [],
        'BlockIp': [],
        'DomainStrategy': 'IPIfNonMatch',
        'RouteOrder': 'block-direct-proxy',
        'FakeDNS': 'false',
    }
    encoded = base64.b64encode(json.dumps(profile, separators=(',', ':')).encode('ascii'))
    return 'happ://routing/onadd/' + encoded.decode('ascii')


def app_list():
    packages = (SCRIPT_DIR / 'android-app-bypass.txt').read_text(encoding='ascii').splitlines()
    if not packages or len(set(packages)) != len(packages) or any(
            not ANDROID_PACKAGE.fullmatch(package) for package in packages):
        raise ValueError('Invalid Android package list')
    return ','.join(packages)


def v2raytun_header(profile_name):
    helper = runpy.run_path(str(SCRIPT_DIR / 'v2raytun_routing.py'))
    return helper['routing_header'](profile_name)


def subscription_proxy(target):
    subscription_path = target['SUBSCRIPTION_PATH']
    provider_id = target.get('TARGET_HAPP_PROVIDER_ID', '')
    scheme = target['TARGET_PUBLIC_SCHEME']
    if (not re.fullmatch(r'[a-f0-9]{40}', subscription_path) or
            (provider_id and not re.fullmatch(r'[a-zA-Z0-9]{8}', provider_id)) or
            scheme not in ('https', 'http')):
        raise ValueError('Invalid subscription proxy settings')
    template = SCRIPT_DIR.parent / 'templates/3x-ui-subscription.nginx.conf'
    replacements = {
        '__SERVER_IPV4__': target['TARGET_IPV4'],
        '__PUBLIC_FQDN__': target['TARGET_FQDN'],
        '__SUBSCRIPTION_PATH__': subscription_path,
        '__SUB_SCHEME__': scheme,
        '__SUB_TLS__': ' ssl' if scheme == 'https' else '',
        '__SUB_CERT__': ('ssl_certificate /etc/krysyuk-standalone/tls/fullchain.pem;\n'
                         '    ssl_certificate_key /etc/krysyuk-standalone/tls/privkey.pem;\n'
                         '    ssl_protocols TLSv1.2 TLSv1.3;' if scheme == 'https' else ''),
        '__ANDROID_APP_LIST__': app_list(),
        '__ANDROID_APP_LIST_URL__': 'https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/bundle/scripts/android-app-bypass.txt',
        '__ANDROID_APP_LIST_ANNOUNCE__': 'base64:' + base64.b64encode(
            'Скопировать список приложений Android'.encode('utf-8')).decode('ascii'),
        '__HAPP_PROVIDER_ID__': provider_id,
        '__INCY_ROUTING__': routing_link(target['TARGET_LABEL']),
        '__V2RAYTUN_ROUTING__': v2raytun_header(target['TARGET_LABEL']),
    }
    config = template.read_text(encoding='ascii')
    for key, value in replacements.items():
        config = config.replace(key, value)
    return config


def check_headers(raw, profile_name, client='', provider_id=''):
    if len(raw) > MAX_HEADER_BYTES:
        return False
    stream = io.BytesIO(raw)
    if not re.fullmatch(rb'HTTP/(?:1\.[01]|2|3) 200(?:[ \t][^\r\n]*)?\r?\n', stream.readline()):
        return False
    headers = http.client.parse_headers(stream)
    routing = v2raytun_header(profile_name) if client == 'v2raytun' else routing_link(profile_name)
    expected = {'Routing-Enable': ['true'], 'Routing': [routing]}
    if client:
        bypass = client in ('happ', 'incy')
        expected.update({
            'per-app-proxy-enable': ['1'] if client == 'incy' else None,
            'per-app-proxy-mode': ['bypass'] if bypass else None,
            'per-app-proxy-list': [app_list()] if bypass else None,
            'providerid': [provider_id] if client == 'happ' and provider_id else None,
        })
    return not stream.read(1) and all(headers.get_all(key) == value for key, value in expected.items())


if __name__ == '__main__':
    if sys.argv[1:] == ['--link']:
        print(routing_link(os.environ['TARGET_LABEL']))
    elif sys.argv[1:] == ['--nginx']:
        sys.stdout.write(subscription_proxy(os.environ))
    elif sys.argv[1:2] == ['--check-headers'] and sys.argv[2:] in ([], ['happ'], ['incy'], ['v2raytun']):
        client = sys.argv[2] if len(sys.argv) == 3 else ''
        try:
            valid = check_headers(sys.stdin.buffer.read(MAX_HEADER_BYTES + 1),
                                  os.environ['TARGET_LABEL'], client,
                                  os.environ.get('TARGET_HAPP_PROVIDER_ID', ''))
        except http.client.HTTPException:
            valid = False
        if not valid:
            raise SystemExit('HAPP_ROUTING_HEADER_MISMATCH')
        print('HAPP_ROUTING_HEADERS=PASS')
    else:
        raise SystemExit('Usage: happ_routing.py --link | --nginx | --check-headers [happ|incy|v2raytun]')
