"""Pure REALITY destination contract shared by the independent Xray renderers.

The advertised client SNI is independent of the local TLS target's identity in
the explicit decoy mode. Derived addresses never come from inherited values.
"""

import ipaddress
import re


def _dns_name(value):
    if not isinstance(value, str) or len(value) > 253 or len(value.split('.')) < 2:
        return False
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
               for part in value.split('.')):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def reality_identity(target):
    """Return ``(destination, target TLS name)`` without changing saved input."""
    mode = target.get('TARGET_REALITY_MODE', 'external')
    sni = target.get('TARGET_REALITY_SNI')
    if mode not in ('external', 'self-steal', 'decoy'):
        raise ValueError('REALITY_MODE')
    if not _dns_name(sni) or 'cloudflare' in sni:
        raise ValueError('REALITY_SNI')
    if mode == 'external':
        return sni + ':443', sni
    own_name = target.get('TARGET_FQDN')
    address_mode = target.get('TARGET_ADDRESS_MODE', 'domain')
    if target.get('TARGET_TLS_MODE', 'letsencrypt') != 'letsencrypt':
        raise ValueError('REALITY_LOCAL_TARGET')
    if address_mode == 'ip' and mode == 'decoy':
        try:
            if (str(ipaddress.IPv4Address(own_name)) != target['TARGET_IPV4']):
                raise ValueError('REALITY_LOCAL_TARGET')
        except (ValueError, KeyError, TypeError):
            raise ValueError('REALITY_LOCAL_TARGET') from None
        # This is an IP verification identity; the TLS probe must use IP SAN
        # validation and omit DNS SNI on the wire for the own-identity probe.
        return '127.0.0.1:9443', own_name
    if address_mode != 'domain' or not _dns_name(own_name):
        raise ValueError('REALITY_LOCAL_TARGET')
    if mode == 'self-steal' and sni != own_name:
        raise ValueError('REALITY_SELF_STEAL_SNI')
    return '127.0.0.1:9443', own_name


def reality_destination(target):
    return reality_identity(target)[0]


def reality_settings_match(settings, target):
    """Reject destination/SNI drift even when a saved runtime hash is intact."""
    destination = reality_destination(target)
    return (isinstance(settings, dict) and
            settings.get('target', settings.get('dest')) == destination and
            ('dest' not in settings or settings['dest'] == destination) and
            settings.get('serverNames') == [target['TARGET_REALITY_SNI']] and
            settings.get('xver', 0) == 0)
