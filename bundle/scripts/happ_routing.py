#!/usr/bin/env python3
"""Generate and verify the Happ routing metadata for native subscriptions."""

import base64
import http.client
import io
import json
import re
import sys


GEO_URL = 'https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/'
MAX_HEADER_BYTES = 16 * 1024


def routing_link():
    # Happ uses the first outbound for unmatched traffic. Keep proxy first and
    # separate domain and IP matches so either can select the direct outbound.
    profile = {
        'Name': 'RU → DIRECT',
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


def check_headers(raw):
    if len(raw) > MAX_HEADER_BYTES:
        return False
    stream = io.BytesIO(raw)
    if not re.fullmatch(rb'HTTP/(?:1\.[01]|2|3) 200(?:[ \t][^\r\n]*)?\r?\n', stream.readline()):
        return False
    headers = http.client.parse_headers(stream)
    return (not stream.read(1) and headers.get_all('Routing-Enable') == ['true']
            and headers.get_all('Routing') == [routing_link()])


if __name__ == '__main__':
    if sys.argv[1:] == ['--link']:
        print(routing_link())
    elif sys.argv[1:] == ['--check-headers']:
        try:
            valid = check_headers(sys.stdin.buffer.read(MAX_HEADER_BYTES + 1))
        except http.client.HTTPException:
            valid = False
        if not valid:
            raise SystemExit('HAPP_ROUTING_HEADER_MISMATCH')
        print('HAPP_ROUTING_HEADERS=PASS')
    else:
        raise SystemExit('Usage: happ_routing.py --link | --check-headers')
