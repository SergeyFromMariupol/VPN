#!/usr/bin/env python3
"""Generate the v2RayTun subscription Routing header."""

import base64
import json
import os
import sys
import uuid


def routing_header(profile_name: str) -> str:
    profile_id = uuid.uuid5(uuid.NAMESPACE_URL, f'v2raytun:routing:{profile_name}')
    # Xray combines fields in a rule with AND. Either match must route directly.
    profile = {
        'name': profile_name,
        'id': str(profile_id).upper(),
        'domainStrategy': 'IPIfNonMatch',
        'domainMatcher': 'hybrid',
        'balancers': [],
        'rules': [
            {
                'id': str(uuid.uuid5(profile_id, 'domain')).upper(),
                '__name__': 'Российские и локальные домены',
                'type': 'field',
                'outboundTag': 'direct',
                'domain': ['geosite:private', 'geosite:category-ru',
                           'domain:ru', 'domain:xn--p1ai', 'domain:su'],
            },
            {
                'id': str(uuid.uuid5(profile_id, 'ip')).upper(),
                '__name__': 'Российские и локальные IP',
                'type': 'field',
                'outboundTag': 'direct',
                'ip': ['geoip:private', 'geoip:ru'],
            },
        ],
    }
    payload = json.dumps(profile, separators=(',', ':')).encode('ascii')
    return base64.b64encode(payload).decode('ascii')


if __name__ == '__main__':
    if sys.argv[1:] != ['--link']:
        raise SystemExit('Usage: v2raytun_routing.py --link')
    name = os.environ.get('TARGET_LABEL', '')
    if not name.strip():
        raise SystemExit('TARGET_LABEL is required')
    print(routing_header(name))
