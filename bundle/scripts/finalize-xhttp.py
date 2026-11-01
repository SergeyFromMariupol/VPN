#!/usr/bin/env python3
"""Fresh-install transition to separate fail-closed REALITY/XHTTP services.

This is an installer phase, never a migration tool for an existing deployment.
Private snapshots stay on the server; stdout contains only status codes.
"""
import argparse
import base64
import copy
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
from contextlib import closing, contextmanager
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

DB = Path('/etc/x-ui/x-ui.db')
RUNTIME = Path('/usr/local/x-ui/bin/config.json')
SOURCE_XRAY = RUNTIME.parent / 'xray-linux-amd64'
EXECROOT = Path('/usr/local/lib/germanyvpn-xhttp-test')
XRAY = EXECROOT / 'xray'
ROOT = Path('/etc/germanyvpn-xhttp-test')
CFROOT = Path('/etc/germanyvpn-xhttp-warp')
MARKER = ROOT / 'promotion.json'
DIRECT_CONF = ROOT / 'config.json'
WARP_CONF = CFROOT / 'config.json'
UNITS = ('germanyvpn-xhttp-test.service', 'germanyvpn-xhttp-warp.service')
UNIT_PATHS = tuple(Path('/etc/systemd/system') / u for u in UNITS)
XRAY_SHA = '64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d'
SERVER_ENV = Path('/etc/krysyuk-standalone/server.env')
TARGET_ENV = Path('/etc/germanyvpn-target.env')
LEGACY_BACKUP_ROOT = Path('/var/backups/krysyuk-standalone')
USER = 'xhttp-test'
ENV = {k: v for k, v in os.environ.items() if k.lower() not in
       ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode()


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'DUP_JSON_KEY')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs)


def run(args, timeout=30, **kw):
    environment = kw.pop('env', {**ENV, 'XRAY_LOCATION_ASSET': str(EXECROOT)})
    return subprocess.run(args, check=True, capture_output=True, timeout=timeout,
                          env=environment, **kw)


def private(path, owner=0):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == owner and
         stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
         'PRIVATE_FILE_OWNERSHIP')
    return path.read_bytes()


def parse_env(raw):
    """Read the installer's shlex.quote format without expanding shell syntax."""
    out = {}
    for line in raw.decode('utf-8').split('\n'):
        if line and not line.startswith('#'):
            need('=' in line, 'ENV_SHAPE')
            key, value = line.split('=', 1)
            need(re.fullmatch('[A-Z][A-Z0-9_]*', key) and key not in out, 'ENV_SHAPE')
            try:
                parts = shlex.split(value)
            except ValueError:
                raise RuntimeError('ENV_SHAPE') from None
            need(len(parts) == 1 and not any(unicodedata.category(c) == 'Cc' for c in parts[0]),
                 'ENV_SHAPE')
            out[key] = parts[0]
    return out


def envfile(path):
    return parse_env(private(path))


def tls_mode(target):
    mode = target.get('TARGET_TLS_MODE', 'letsencrypt')
    need(mode in ('letsencrypt', 'none'), 'TLS_MODE')
    return mode


def protocols(target):
    return ('REALITY', 'HYSTERIA2', 'XHTTP') if tls_mode(target) == 'letsencrypt' else ('REALITY', 'XHTTP')


def profile_count(target):
    return 2 * len(protocols(target))


def profile_roles(target):
    return [(role, transport) for role in ('warp', 'direct') for transport in protocols(target)]


def endpoint(target):
    """Address selection is independent of the user-visible profile prefix."""
    mode, address = target.get('TARGET_ADDRESS_MODE', 'domain'), target['TARGET_FQDN']
    need(mode in ('domain', 'ip'), 'ADDRESS_MODE')
    if mode == 'ip':
        try:
            need(str(ipaddress.IPv4Address(address)) == target['TARGET_IPV4'], 'IP_ENDPOINT')
        except ipaddress.AddressValueError:
            raise RuntimeError('IP_ENDPOINT') from None
    else:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            pass
        else:
            raise RuntimeError('DOMAIN_ENDPOINT')
        need(len(address) <= 253 and len(address.split('.')) >= 2 and
             all(re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                 for part in address.split('.')), 'DOMAIN_ENDPOINT')
    return address


def profile_names(target):
    label = target.get('TARGET_LABEL', '🇩🇪 Германия')
    need(1 <= len(label) <= 80 and not any(unicodedata.category(c) == 'Cc' for c in label),
         'PROFILE_LABEL')
    return [label + ' · ' + egress + ' · ' + protocol
            for egress in ('☁️ Cloudflare', '🖥️ IP сервера')
            for protocol in protocols(target)]


@contextmanager
def defer_interruptions():
    """Finish a short ownership registration before normal signals can raise."""
    if not hasattr(signal, 'pthread_sigmask'):
        yield
        return
    previous = signal.pthread_sigmask(signal.SIG_BLOCK,
                                     (signal.SIGINT, signal.SIGTERM, signal.SIGHUP))
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def inode(path):
    info = path.lstat()
    return info.st_dev, info.st_ino


def save(path, raw, uid=0, gid=0, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    info = os.fstat(fd)
    identity = info.st_dev, info.st_ino
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # A failed write has not yet been registered by callers. Do not leave a
        # partial canonical file that prevents rollback of its owned directory.
        # An identical replacement made by another operation is still foreign.
        with defer_interruptions():
            if path.exists() or path.is_symlink():
                current = path.lstat()
                if (stat.S_ISREG(current.st_mode) and current.st_nlink == 1
                        and (current.st_dev, current.st_ino) == identity):
                    path.unlink()
        raise


def atomic(path, raw, expected, expected_inode=None, before_replace=None):
    need(sha(path.read_bytes()) == expected, 'FILE_CAS')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'FILE_OWNERSHIP')
    if expected_inode is not None:
        need((info.st_dev, info.st_ino) == expected_inode, 'FILE_INODE_CAS')
    fd, name = tempfile.mkstemp(prefix='.vpn-owned-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        need(sha(path.read_bytes()) == expected, 'LATE_FILE_CAS')
        if expected_inode is not None:
            need(inode(path) == expected_inode, 'LATE_FILE_INODE_CAS')
        if before_replace is not None:
            before_replace(Path(name))
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def create_owned_directory(path, mode, created, versions):
    with defer_interruptions():
        path.mkdir(mode=mode)
        created[path] = None
        versions[path] = {inode(path): None}


def save_owned(path, raw, created, versions, **kwargs):
    with defer_interruptions():
        save(path, raw, **kwargs)
        created[path] = sha(raw)
        versions[path] = {inode(path): sha(raw)}


def atomic_owned(path, raw, created, versions):
    with defer_interruptions():
        current = inode(path)
        need(current in versions[path] and versions[path][current] == created[path],
             'OWNED_FILE_INODE_CAS')
        # os.replace can succeed before a directory fsync or signal fails.
        # Register both complete owned generations before crossing that boundary.
        atomic(path, raw, created[path], expected_inode=current,
               before_replace=lambda temporary: versions[path].update({inode(temporary): sha(raw)}))
        created[path] = sha(raw)


def remove_owned_paths(created, versions):
    for path in reversed(created):
        if path.exists() or path.is_symlink():
            info = path.lstat()
            identity = info.st_dev, info.st_ino
            need(not path.is_symlink() and identity in versions[path], 'ROLLBACK_FOREIGN_PATH')
            digest = versions[path][identity]
            if digest is None:
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0, 'ROLLBACK_FOREIGN_DIRECTORY')
                path.rmdir()
            else:
                need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                     and sha(path.read_bytes()) == digest, 'ROLLBACK_FOREIGN_FILE')
                path.unlink()


def query(uri):
    parsed, result = urlsplit(uri), {}
    for key, value in parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True):
        need(key not in result, 'DUP_URI_QUERY')
        result[key] = value
    return parsed, result


def direct_row_matches_feed(row, served, target):
    """3X-UI may apply the stored remark to an older link's URI fragment."""
    stored_uri = urlsplit(row['value'])
    served_uri = urlsplit(served)
    full_name = profile_names(target)[-1]
    old_name = target.get('TARGET_LABEL', '🇩🇪 Германия') + ' · XHTTP'
    return (row['remark'] == full_name and
            stored_uri._replace(fragment='') == served_uri._replace(fragment='') and
            unquote(stored_uri.fragment) in (old_name, full_name) and
            unquote(served_uri.fragment) == full_name)


def decode_feed(raw, expected_count=6):
    text = raw.decode().strip()
    if '://' not in text:
        text = base64.urlsafe_b64decode(text + '=' * ((-len(text)) % 4)).decode()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    need(len(lines) == expected_count and len(set(lines)) == expected_count,
         'NATIVE_SIX_COUNT' if expected_count == 6 else 'NATIVE_PROFILE_COUNT')
    return lines


def native(target, secret, expected_count=None, user_agents=('v2RayTun', 'Happ', 'Karing')):
    host = endpoint(target)
    if expected_count is None:
        expected_count = profile_count(target)
    path = '/' + secret['SUBSCRIPTION_PATH'].strip('/') + '/' + secret['SUBSCRIPTION_ID']
    feeds = []
    for ua in user_agents:
        if tls_mode(target) == 'none':
            connection = http.client.HTTPConnection(host, 2096, timeout=20)
        else:
            connection = http.client.HTTPSConnection(host, 2096, timeout=20,
                                                     context=ssl.create_default_context())
        try:
            connection.request('GET', path, headers={'User-Agent': ua, 'Cache-Control': 'no-cache'})
            response = connection.getresponse()
            raw = response.read(2 * 1024 * 1024 + 1)
            need(response.status == 200 and len(raw) <= 2 * 1024 * 1024, 'SUB_HTTP')
            feeds.append(decode_feed(raw, expected_count))
        finally:
            connection.close()
    need(all(feed == feeds[0] for feed in feeds), 'UA_DIFFERENCE')
    return feeds[0]


def keypair(raw):
    text = raw.decode('ascii')
    private_key = re.findall(r'^Private(?:\s+key|Key):\s*([A-Za-z0-9_-]{43})\s*$', text, re.M)
    public_key = re.findall(r'^(?:Public(?:\s+key|Key)|Password(?: \(PublicKey\))?):\s*([A-Za-z0-9_-]{43})\s*$', text, re.M)
    need(len(private_key) == len(public_key) == 1 and private_key != public_key, 'KEYPAIR_PARSE')
    return private_key[0], public_key[0]


def build(main, target, private_key, sid, path):
    """Render both singleton servers without changing main DNS or egress policy."""
    host = endpoint(target)
    old = [i for i in main['inbounds'] if i.get('port') == 8443]
    need(len(old) == 1 and len(old[0]['settings']['clients']) == 2, 'OLD_XHTTP_CLIENTS')
    clients = {u['email']: u for u in old[0]['settings']['clients']}
    need(set(clients) == {'germany-xhttp', 'germany-warp-xhttp'}, 'XHTTP_ROLES')
    outbounds = {out['tag']: out for out in main['outbounds']}
    need({'WARP_CF', 'DIRECT', 'BLOCK'} <= set(outbounds), 'MAIN_OUTBOUNDS')
    warp = outbounds['WARP_CF']
    need(warp['protocol'] == 'vless' and warp['settings']['vnext'][0]['address'] == '127.0.0.1'
         and warp['settings']['vnext'][0]['port'] == 24443, 'PRIVATE_CONNECTOR')
    dns_tags = [server['tag'] for server in main['dns']['servers'] if 'tag' in server]
    stream = {'network': 'xhttp', 'security': 'reality',
              'sockopt': {'tcpMaxSeg': 1200},
              'xhttpSettings': {'host': host, 'path': path, 'mode': 'auto'},
              'realitySettings': {'show': False, 'xver': 0,
                                  'target': target['TARGET_REALITY_SNI'] + ':443',
                                  'serverNames': [target['TARGET_REALITY_SNI']],
                                  'privateKey': private_key, 'shortIds': [sid],
                                  'minClientVer': '26.3.27'}}
    prefix = [{'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'BLOCK'},
              {'type': 'field', 'inboundTag': dns_tags, 'outboundTag': 'DIRECT'},
              {'type': 'field', 'ip': ['geoip:private', '::/0', target['TARGET_IPV4'] + '/32'],
               'outboundTag': 'BLOCK'},
              {'type': 'field', 'domain': ['full:' + host], 'outboundTag': 'BLOCK'}]
    configs = []
    for role, port, email in [('DIRECT', 8444, 'germany-xhttp'),
                              ('WARP_CF', 8443, 'germany-warp-xhttp')]:
        tag = 'XHTTP_' + role
        config = {'log': {'loglevel': 'none'}, 'dns': copy.deepcopy(main['dns']),
                  'inbounds': [{'listen': target['TARGET_IPV4'], 'port': port, 'tag': tag,
                                'protocol': 'vless', 'settings': {'clients': [copy.deepcopy(clients[email])],
                                                                'decryption': 'none'},
                                'streamSettings': copy.deepcopy(stream),
                                'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'],
                                             'routeOnly': True}}],
                  'outbounds': [copy.deepcopy(outbounds[k]) for k in
                                (['DIRECT', 'BLOCK'] if role == 'DIRECT' else ['DIRECT', 'BLOCK', 'WARP_CF'])],
                  'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': copy.deepcopy(prefix) + [
                      {'type': 'field', 'inboundTag': [tag], 'network': 'tcp,udp', 'outboundTag': role},
                      {'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'BLOCK'}]}}
        configs.append(config)
    return configs


def uri_for(config, public_key, label):
    inbound = config['inbounds'][0]
    stream = inbound['streamSettings']
    values = {'encryption': 'none', 'security': 'reality',
              'sni': stream['realitySettings']['serverNames'][0], 'fp': 'chrome',
              'type': 'xhttp', 'host': stream['xhttpSettings']['host'],
              'path': stream['xhttpSettings']['path'], 'mode': 'stream-one',
              'extra': '{"mode":"stream-one"}', 'pbk': public_key,
              'sid': stream['realitySettings']['shortIds'][0], 'spx': '/', 'flow': ''}
    return ('vless://' + inbound['settings']['clients'][0]['id'] + '@' +
            values['host'] + ':' + str(inbound['port']) + '?' + urlencode(values) + '#' + quote(label, safe=''))


def promoted_feed(feeds, target, configs, public_key):
    """Replace only the two XHTTP links, keeping every other URI byte-for-byte."""
    need(len(feeds) == profile_count(target) and len(configs) == 2, 'NATIVE_PROFILE_COUNT')
    promoted = feeds.copy()
    for index, (role, protocol) in enumerate(profile_roles(target)):
        if protocol == 'XHTTP':
            promoted[index] = uri_for(configs[1 if role == 'warp' else 0], public_key,
                                      unquote(urlsplit(feeds[index]).fragment))
    return promoted


def unit_bytes(conf):
    return f'''[Unit]
Description=Independent VPN XHTTP REALITY service
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User={USER}
Group={USER}
LoadCredential=config.json:{conf}
Environment=XRAY_LOCATION_ASSET={EXECROOT}
Environment=GODEBUG=multipathtcp=0
ExecStartPre={XRAY} run -test -config %d/config.json
ExecStart={XRAY} run -config %d/config.json
Restart=on-failure
RestartSec=3s
TimeoutStopSec=15s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
'''.encode()


SQL_CHILD = r'''
import json,sqlite3,sys
from contextlib import closing
p=json.load(sys.stdin)
with closing(sqlite3.connect('file:'+p['db']+'?mode=rw',uri=True,timeout=10)) as db,db:
 db.execute('BEGIN IMMEDIATE')
 columns=[r[1] for r in db.execute('PRAGMA table_info(client_external_links)')]
 rows=[dict(zip(columns,r)) for r in db.execute('SELECT * FROM client_external_links ORDER BY sort_index,id')]
 current=db.execute('SELECT enable FROM inbounds WHERE id=?',(p['inbound'],)).fetchone()
 if rows!=p['expected_rows'] or current!=(p['expected_enable'],):raise RuntimeError('SQL_CAS')
 assert db.execute('UPDATE inbounds SET enable=? WHERE id=?',(p['wanted_enable'],p['inbound'])).rowcount==1
 if p['action']=='apply':
  assert db.execute('UPDATE client_external_links SET value=?,remark=? WHERE id=?',(p['direct_uri'],p['direct_label'],p['direct_id'])).rowcount==1
  row=p['cf_row'];keys=list(row)
  db.execute('INSERT INTO client_external_links('+','.join(keys)+') VALUES('+','.join('?' for _ in keys)+')',[row[k] for k in keys])
 else:
  assert db.execute('DELETE FROM client_external_links WHERE id=?',(p['cf_id'],)).rowcount==1
  old=p['old_direct']
  assert db.execute('UPDATE client_external_links SET value=?,remark=? WHERE id=?',(old['value'],old['remark'],old['id'])).rowcount==1
 if db.execute('PRAGMA quick_check').fetchone()!=('ok',):raise RuntimeError('SQL_QUICK_CHECK')
'''


def database(target=None):
    count = profile_count(target or {})
    with closing(sqlite3.connect(DB.as_uri() + '?mode=ro', uri=True)) as db:
        need(db.execute('PRAGMA quick_check').fetchone() == ('ok',), 'DB_QUICK_CHECK')
        need(db.execute('SELECT count(*) FROM clients').fetchone() == (count,) and
             db.execute('SELECT count(*) FROM client_inbounds').fetchone() == (count,), 'DB_CLIENT_COUNT')
        cols = [row[1] for row in db.execute('PRAGMA table_info(client_external_links)')]
        rows = [dict(zip(cols, row)) for row in db.execute('SELECT * FROM client_external_links ORDER BY sort_index,id')]
        inbounds = db.execute('SELECT id,port,enable FROM inbounds ORDER BY id').fetchall()
        return rows, inbounds


def sql(payload):
    import pwd
    need(pwd.getpwuid(DB.stat().st_uid).pw_name == 'xui', 'DB_OWNER')
    run(['runuser', '-u', 'xui', '--', 'python3', '-c', SQL_CHILD], timeout=20,
        input=json.dumps({'db': str(DB), **payload}).encode())


def routes():
    return {str(args): sha(run(args).stdout) for args in
            [['ip', '-4', 'rule', 'show'], ['ip', '-6', 'rule', 'show'],
             ['ip', '-4', 'route', 'show', 'table', 'main'],
             ['ip', '-6', 'route', 'show', 'table', 'main']]}


def public_key(config):
    key = config['inbounds'][0]['streamSettings']['realitySettings']['privateKey']
    private_key = base64.urlsafe_b64decode(key + '=')
    raw = run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'],
              input=bytes.fromhex('302e020100300506032b656e04220420') + private_key).stdout
    need(len(raw) == 44, 'REALITY_KEY_DERIVATION')
    return base64.urlsafe_b64encode(raw[-32:]).decode().rstrip('=')


def client_config(uri, local_port):
    parsed, values = query(uri)
    need(parsed.hostname is not None and parsed.username is not None, 'URI_ENDPOINT')
    if parsed.scheme == 'vless':
        stream = {'network': values['type'], 'security': values['security']}
        need(values.get('flow', '') == '', 'CLIENT_SECURITY')
        if values['security'] == 'reality':
            stream['realitySettings'] = {'serverName': values['sni'], 'fingerprint': values['fp'],
                                         'publicKey': values['pbk'], 'shortId': values['sid'],
                                         'spiderX': values.get('spx', '/')}
        elif values['security'] == 'tls' and values['type'] == 'xhttp':
            need(values.get('insecure', '0') == '0', 'CLIENT_SECURITY')
            stream['tlsSettings'] = {'serverName': values['sni'],
                                     'alpn': values['alpn'].split(','),
                                     'allowInsecure': False}
        else:
            raise RuntimeError('CLIENT_SECURITY')
        if values['type'] == 'xhttp':
            stream['xhttpSettings'] = {'host': values['host'], 'path': values['path'],
                                       'mode': values['mode']}
            if 'extra' in values:
                stream['xhttpSettings']['extra'] = strict_json(values['extra'])
        else:
            need(values['type'] == 'grpc', 'CLIENT_TRANSPORT')
            stream['grpcSettings'] = {'serviceName': values['serviceName'], 'multiMode': False}
        out = {'tag': 'VPN', 'protocol': 'vless',
               'settings': {'vnext': [{'address': parsed.hostname, 'port': parsed.port,
                                      'users': [{'id': parsed.username, 'encryption': 'none', 'flow': ''}]}]},
               'streamSettings': stream}
    else:
        need(parsed.scheme in ('hysteria2', 'hy2') and values.get('insecure', '0') == '0', 'CLIENT_HY2')
        out = {'tag': 'VPN', 'protocol': 'hysteria',
               'settings': {'version': 2, 'address': parsed.hostname, 'port': parsed.port},
               'streamSettings': {'network': 'hysteria', 'security': 'tls',
                                   'hysteriaSettings': {'version': 2, 'auth': parsed.username, 'udpIdleTimeout': 60},
                                   'tlsSettings': {'serverName': values['sni'],
                                                    'alpn': values.get('alpn', 'h3').split(','),
                                                    'fingerprint': values.get('fp', 'chrome'),
                                                    'allowInsecure': False}}}
    return {'log': {'loglevel': 'none'},
            'inbounds': [{'listen': '127.0.0.1', 'port': local_port, 'protocol': 'socks',
                          'settings': {'auth': 'noauth', 'udp': True}}],
            'outbounds': [out, {'tag': 'BLOCK', 'protocol': 'blackhole'}],
            'routing': {'rules': [{'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'VPN'}]}}


def recv_exact(stream, length):
    result = b''
    while len(result) < length:
        part = stream.recv(length - len(result))
        need(bool(part), 'SOCKS_EOF')
        result += part
    return result


def udp_dns(port):
    with socket.create_connection(('127.0.0.1', port), timeout=12) as control:
        control.sendall(b'\x05\x01\x00')
        need(recv_exact(control, 2) == b'\x05\x00', 'SOCKS_AUTH')
        control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
        head = recv_exact(control, 4)
        need(head[:2] == b'\x05\x00' and head[3] == 1, 'SOCKS_UDP_ASSOCIATE')
        address = socket.inet_ntoa(recv_exact(control, 4))
        relay_port = struct.unpack('!H', recv_exact(control, 2))[0]
        if address == '0.0.0.0':
            address = '127.0.0.1'
        ident = secrets.token_bytes(2)
        payload = ident + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x07example\x03com\x00\x00\x01\x00\x01'
        request = b'\x00\x00\x00\x01' + socket.inet_aton('9.9.9.9') + struct.pack('!H', 53) + payload
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            sock.settimeout(12)
            sock.sendto(request, (address, relay_port))
            answer = sock.recv(65535)
        need(len(answer) >= 22 and answer[:4] == b'\x00\x00\x00\x01', 'SOCKS_UDP_RESPONSE')
        dns = answer[10:]
        need(dns[:2] == ident and dns[2] & 0x80 and dns[3] & 15 == 0 and
             int.from_bytes(dns[6:8], 'big') > 0, 'UDP_DNS_ANSWER')


def payload(uri, warp, target, binary=XRAY):
    """A new process uses only the exact published URI; never patch its endpoint."""
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='vpn-uri-', dir='/run') as directory:
        conf = Path(directory) / 'config.json'
        save(conf, canonical(client_config(uri, port)))
        client_env = {**ENV, 'XRAY_LOCATION_ASSET': str(binary.parent),
                      'GODEBUG': 'multipathtcp=0'}
        run([str(binary), 'run', '-test', '-config', str(conf)], env=client_env)
        child = subprocess.Popen([str(binary), 'run', '-config', str(conf)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  env=client_env)
        try:
            deadline = time.monotonic() + 10
            while True:
                need(child.poll() is None, 'URI_CLIENT_EXIT')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    need(time.monotonic() < deadline, 'URI_CLIENT_TIMEOUT')
                    time.sleep(.1)
            raw = run(['curl', '--disable', '--silent', '--show-error', '--fail',
                       '--proto', '=https', '--max-time', '30', '--socks5-hostname',
                       '127.0.0.1:' + str(port), 'https://www.cloudflare.com/cdn-cgi/trace'],
                      timeout=35).stdout
            trace = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
            need(trace.get('warp') == ('on' if warp else 'off'), 'PAYLOAD_EGRESS_CLASS')
            observed = ipaddress.ip_address(trace.get('ip', ''))
            need(observed.version == 4 and observed.is_global, 'PAYLOAD_EGRESS_ADDRESS')
            need((trace.get('ip') != target) if warp else (trace.get('ip') == target), 'PAYLOAD_EGRESS_IP')
            udp_dns(port)
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


def validate_legacy_feed(feeds, target, secret):
    """Verify the exact direct profiles published before dual-egress."""
    host = endpoint(target)
    label = target['TARGET_LABEL']
    expected = {
        'reality': ('vless', 443, secret['VLESS_UUID'], label + ' · REALITY'),
        'xhttp': ('vless', 8443, secret['VLESS_UUID'], label + ' · XHTTP'),
    }
    if tls_mode(target) == 'letsencrypt':
        expected['hysteria2'] = ('hysteria2', 443, secret['HYSTERIA2_AUTH'], label + ' · HYSTERIA2')
    need(len(feeds) == len(expected) and len(set(feeds)) == len(expected), 'LEGACY_FEED_COUNT')
    seen = set()
    for uri in feeds:
        parsed, values = query(uri)
        if (parsed.scheme == 'vless' and values.get('security') == 'reality'
                and values.get('type') != 'xhttp'):
            role = 'reality'
            need(values.get('type') == 'grpc' and values.get('serviceName') == 'reality-grpc'
                 and values.get('sni') == target['TARGET_REALITY_SNI']
                 and values.get('pbk') == secret['REALITY_PUBLIC_KEY']
                 and values.get('sid') == secret['REALITY_SHORT_ID']
                 and values.get('fp') == 'chrome' and values.get('flow', '') == '',
                 'LEGACY_REALITY_URI')
        elif parsed.scheme in ('hysteria2', 'hy2'):
            role = 'hysteria2'
            need(role in expected, 'LEGACY_HYSTERIA_DISABLED')
            need(values.get('sni') == host and values.get('alpn') == 'h3'
                 and values.get('insecure', '0').lower() not in ('1', 'true', 'yes'),
                 'LEGACY_HYSTERIA_URI')
        elif parsed.scheme == 'vless' and values.get('type') == 'xhttp':
            role = 'xhttp'
            need(values.get('host') == host
                 and values.get('path') == '/' + secret['XHTTP_PRIVATE_PATH']
                 and values.get('mode') == 'packet-up' and values.get('flow', '') == ''
                 and values.get('insecure', '0') == '0', 'LEGACY_XHTTP_URI')
            if tls_mode(target) == 'none':
                need(values.get('security') == 'reality'
                     and values.get('sni') == target['TARGET_REALITY_SNI']
                     and values.get('pbk') == secret['REALITY_PUBLIC_KEY']
                     and values.get('sid') == secret['REALITY_SHORT_ID']
                     and values.get('fp') == 'chrome', 'LEGACY_XHTTP_URI')
            else:
                need(values.get('security') == 'tls' and values.get('sni') == host
                     and values.get('alpn') == 'h2', 'LEGACY_XHTTP_URI')
            if 'extra' in values:
                extra = strict_json(values['extra'])
                need(isinstance(extra, dict) and extra.get('mode', 'packet-up') == 'packet-up',
                     'LEGACY_XHTTP_EXTRA')
        else:
            raise RuntimeError('LEGACY_URI_ROLE')
        scheme, port, identity, remark = expected[role]
        need(role not in seen and parsed.scheme in (('hysteria2', 'hy2') if role == 'hysteria2' else (scheme,))
             and parsed.hostname == host and parsed.port == port and parsed.username == identity
             and unquote(parsed.fragment) == remark, 'LEGACY_URI_IDENTITY')
        seen.add(role)
    need(seen == set(expected), 'LEGACY_URI_SET')


def verify_legacy_rollback(target, secret, snapshot, baseline_feed=None):
    """Do not certify an inverse transaction until the old data plane works."""
    count = len(protocols(target))
    need(LEGACY_BACKUP_ROOT.is_dir() and not LEGACY_BACKUP_ROOT.is_symlink() and
         snapshot.is_dir() and not snapshot.is_symlink() and
         snapshot.resolve().is_relative_to(LEGACY_BACKUP_ROOT.resolve()),
         'ROLLBACK_SNAPSHOT_PATH')
    need(private(SERVER_ENV) == private(snapshot / 'server.env'), 'ROLLBACK_ENV')
    need('DUAL_EGRESS_SCHEMA' not in secret, 'ROLLBACK_DUAL_ENV')
    need(strict_json(RUNTIME.read_bytes()) == strict_json(private(snapshot / 'config-before.json')),
         'ROLLBACK_RUNTIME')
    need(sha(SOURCE_XRAY.read_bytes()) == XRAY_SHA, 'XRAY_PIN')
    run(['systemctl', 'is-active', 'x-ui.service'])
    run(['systemctl', 'is-active', 'nginx.service'])
    run([str(SOURCE_XRAY), 'run', '-test', '-config', str(RUNTIME)],
        env={**ENV, 'XRAY_LOCATION_ASSET': str(SOURCE_XRAY.parent)})
    run([sys.executable, str(Path(__file__).with_name('network-contract.py')),
         '--target-ip', target['TARGET_IPV4'], '--interface', target['TARGET_INTERFACE'],
         '--ssh-port', target['TARGET_SSH_PORT'], '--promoted', '0',
         '--tls-mode', tls_mode(target)])
    with closing(sqlite3.connect(DB.as_uri() + '?mode=ro', uri=True)) as db:
        need(db.execute('PRAGMA quick_check').fetchone() == ('ok',), 'ROLLBACK_DB_CHECK')
        need(db.execute('SELECT count(*) FROM clients').fetchone() == (count,) and
             db.execute('SELECT count(*) FROM client_inbounds').fetchone() == (count,) and
             db.execute('SELECT count(*) FROM client_external_links').fetchone() == (0,) and
             db.execute('SELECT count(*) FROM inbounds WHERE enable=1').fetchone() == (count,),
             'ROLLBACK_DB_SHAPE')
    need(run(['ip', '-4', 'route', 'show', 'table', 'all']).stdout ==
         private(snapshot / 'ip4-routes-before.txt') and
         run(['ip', '-4', 'rule', 'show']).stdout ==
         private(snapshot / 'ip4-rules-before.txt'), 'ROLLBACK_HOST_ROUTE')
    for unit in UNITS:
        need(subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                            capture_output=True, timeout=10).returncode != 0,
             'ROLLBACK_XHTTP_UNIT')
    for path in (*UNIT_PATHS, ROOT, CFROOT, EXECROOT):
        need(not path.exists() and not path.is_symlink(), 'ROLLBACK_XHTTP_RESOURCE')
    feeds = native(target, secret, expected_count=count)
    validate_legacy_feed(feeds, target, secret)
    if baseline_feed is not None:
        need(native(target, secret, expected_count=count, user_agents=('v2rayN/7',)) ==
             decode_feed(private(baseline_feed), expected_count=count),
             'ROLLBACK_FEED_BYTES')
    for uri in feeds:
        payload(uri, False, target['TARGET_IPV4'], binary=SOURCE_XRAY)


def verify_xhttp_rollback(target, secret, main_before, rows, inbounds,
                          before_feed, route_before):
    """Verify the complete dual-egress state after a failed promotion."""
    need(strict_json(RUNTIME.read_bytes()) == strict_json(main_before), 'ROLLBACK_RUNTIME')
    need(sha(SOURCE_XRAY.read_bytes()) == XRAY_SHA, 'XRAY_PIN')
    run(['systemctl', 'is-active', 'x-ui.service'])
    run([str(SOURCE_XRAY), 'run', '-test', '-config', str(RUNTIME)],
        env={**ENV, 'XRAY_LOCATION_ASSET': str(SOURCE_XRAY.parent)})
    run([sys.executable, str(Path(__file__).with_name('network-contract.py')),
         '--target-ip', target['TARGET_IPV4'], '--interface', target['TARGET_INTERFACE'],
         '--ssh-port', target['TARGET_SSH_PORT'], '--promoted', '0',
         '--tls-mode', tls_mode(target)])
    need(database(target) == (rows, inbounds), 'ROLLBACK_DB_SHAPE')
    need(routes() == route_before, 'ROLLBACK_HOST_ROUTE')
    for unit in UNITS:
        need(subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                            capture_output=True, timeout=10).returncode != 0,
             'ROLLBACK_XHTTP_UNIT')
    for path in (*UNIT_PATHS, ROOT, CFROOT, EXECROOT):
        need(not path.exists() and not path.is_symlink(), 'ROLLBACK_XHTTP_RESOURCE')
    need(native(target, secret) == before_feed, 'ROLLBACK_FEED_BYTES')
    need(len(before_feed) == profile_count(target), 'ROLLBACK_FEED_COUNT')
    for index, uri in enumerate(before_feed):
        payload(uri, index < len(protocols(target)), target['TARGET_IPV4'], binary=SOURCE_XRAY)


def kernel_listener(pid, port):
    """Verify Go actually opened ordinary TCP with MSS1200, not MPTCP."""
    import ctypes
    inodes = {line.split()[9] for line in Path('/proc/net/tcp').read_text().splitlines()[1:]
              if line.split()[1].rsplit(':', 1)[-1] == format(port, '04X') and line.split()[3] == '0A'}
    descriptors = [int(p.name) for p in Path('/proc/' + str(pid) + '/fd').iterdir()
                   if p.is_symlink() and p.readlink().as_posix() in {'socket:[' + i + ']' for i in inodes}]
    need(len(descriptors) == 1, 'LISTENER_FD')
    pidfd, duplicate = os.pidfd_open(pid), -1
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        duplicate = libc.syscall(438, pidfd, descriptors[0], 0)
        need(duplicate >= 0, 'PIDFD_GETFD')
        def option(level, name):
            value = ctypes.c_int()
            size = ctypes.c_uint(ctypes.sizeof(value))
            need(libc.getsockopt(duplicate, level, name, ctypes.byref(value), ctypes.byref(size)) == 0,
                 'LISTENER_SOCKET_OPTION')
            return value.value
        need(option(socket.SOL_SOCKET, 38) == 6 and option(socket.IPPROTO_TCP, socket.TCP_MAXSEG) == 1200,
             'LISTENER_TCP_MSS')
    finally:
        if duplicate >= 0:
            os.close(duplicate)
        os.close(pidfd)


def validate_marker(marker, target, direct_raw, warp_raw, main_raw, allow_pending=False):
    need(set(marker) == {'version', 'target', 'operation_id', 'status', 'direct_config_sha256',
                         'warp_config_sha256', 'main_runtime_sha256'} and marker['version'] == 2
         and marker['status'] in (('pending', 'committed') if allow_pending else ('committed',))
         and marker['target'] == target['TARGET_IPV4']
         and re.fullmatch('[0-9a-f]{32}', marker['operation_id']), 'MARKER_SHAPE')
    need(marker['direct_config_sha256'] == sha(direct_raw) and marker['warp_config_sha256'] == sha(warp_raw)
         and marker['main_runtime_sha256'] == sha(canonical(strict_json(main_raw))), 'MARKER_CONFIG_HASH')


def verify_published_profiles(feeds, target, secret, configs, main):
    """Match the exact published four/six URIs to their canonical runtime roles."""
    host = endpoint(target)
    names = profile_names(target)
    identities = {('warp', 'REALITY'): secret['WARP_REALITY_UUID'],
                  ('warp', 'XHTTP'): secret['WARP_XHTTP_UUID'],
                  ('direct', 'REALITY'): secret['VLESS_UUID'],
                  ('direct', 'XHTTP'): secret['VLESS_UUID']}
    if tls_mode(target) == 'letsencrypt':
        identities.update({('warp', 'HYSTERIA2'): secret['WARP_HYSTERIA2_AUTH'],
                           ('direct', 'HYSTERIA2'): secret['HYSTERIA2_AUTH']})
    need(len(feeds) == len(set(feeds)) == profile_count(target), 'NATIVE_PROFILE_COUNT')
    for index, (role, protocol) in enumerate(profile_roles(target)):
        uri = feeds[index]
        parsed, values = query(uri)
        need(parsed.hostname == host and parsed.username == identities[(role, protocol)]
             and unquote(parsed.fragment) == names[index], 'NATIVE_IDENTITY_LABEL')
        if protocol == 'XHTTP':
            config = configs[1 if role == 'warp' else 0]
            need(uri == uri_for(config, public_key(config), names[index]), 'NATIVE_XHTTP_EXACT')
        elif protocol == 'REALITY':
            need(parsed.scheme == 'vless' and parsed.port == 443 and values.get('sni') == target['TARGET_REALITY_SNI']
                 and values.get('type') == 'grpc' and values.get('serviceName') == 'reality-grpc'
                 and values.get('security') == 'reality' and values.get('flow', '') == ''
                 and values.get('pbk') == secret['REALITY_PUBLIC_KEY']
                 and values.get('sid') == secret['REALITY_SHORT_ID'], 'NATIVE_REALITY')
        else:
            need(parsed.scheme in ('hysteria2', 'hy2') and parsed.port == 443
                 and values.get('sni') == host and values.get('alpn') == 'h3'
                 and values.get('insecure', '0') == '0', 'NATIVE_HYSTERIA')
    connector = next(o for o in main['outbounds'] if o['tag'] == 'WARP_CF')['settings']['vnext'][0]['users'][0]['id']
    need(not any(value in '\n'.join(feeds) for value in (connector, secret['DIRECT_SUBSCRIPTION_ID'],
                                                       '127.0.0.1', ':24443', ':24444')), 'CONNECTOR_LEAK')


def verify(target, secret, do_payload=True, expected=None, allow_pending=False):
    host = endpoint(target)
    for path in (ROOT, CFROOT):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
             stat.S_IMODE(info.st_mode) == 0o700, 'PROMOTED_ROOT_OWNERSHIP')
    info = EXECROOT.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
         stat.S_IMODE(info.st_mode) == 0o555, 'PUBLIC_EXECROOT_OWNERSHIP')
    marker = strict_json(private(MARKER))
    direct_raw, warp_raw, main_raw = private(DIRECT_CONF), private(WARP_CONF), RUNTIME.read_bytes()
    validate_marker(marker, target, direct_raw, warp_raw, main_raw, allow_pending=allow_pending)
    configs = [strict_json(direct_raw), strict_json(warp_raw)]
    main = strict_json(main_raw)
    need(not any(i.get('port') in (8443, 8444) for i in main['inbounds']), 'RETIRED_MAIN_LISTENER')
    if tls_mode(target) == 'none':
        need(not any(i.get('protocol') in ('hysteria', 'hysteria2') or
                     i.get('streamSettings', {}).get('network') == 'hysteria' or
                     'tlsSettings' in i.get('streamSettings', {})
                     for i in main['inbounds']), 'UNEXPECTED_TLS_INBOUND')
    reality = [i for i in main['inbounds'] if i.get('port') == 443 and
               i.get('streamSettings', {}).get('security') == 'reality']
    need(len(reality) == 1, 'MAIN_REALITY_COUNT')
    reality_stream = reality[0]['streamSettings']
    r = reality_stream['realitySettings']
    need(reality_stream['network'] == 'grpc' and
         reality_stream['grpcSettings']['serviceName'] == 'reality-grpc' and
         r.get('target', r.get('dest')) == target['TARGET_REALITY_SNI'] + ':443' and
         r['serverNames'] == [target['TARGET_REALITY_SNI']] and r['minClientVer'] == '26.3.27' and
         r['shortIds'] == [secret['REALITY_SHORT_ID']], 'MAIN_REALITY_CONTRACT')
    need(public_key({'inbounds': [reality[0]]}) == secret['REALITY_PUBLIC_KEY'], 'MAIN_REALITY_PUBLIC_KEY')
    need(sha(XRAY.read_bytes()) == XRAY_SHA, 'XRAY_PIN')
    roles = ('DIRECT', 'WARP_CF')
    for unit, path, config, port, role in zip(UNITS, (DIRECT_CONF, WARP_CONF), configs, (8444, 8443), roles):
        run(['systemctl', 'is-active', unit])
        run(['systemctl', 'is-enabled', unit])
        need(private(Path('/etc/systemd/system') / unit) == unit_bytes(path), 'UNIT_BYTES')
        pid = int(run(['systemctl', 'show', unit, '-p', 'MainPID', '--value']).stdout)
        need(pid > 1 and Path('/proc/' + str(pid) + '/exe').resolve() == XRAY, 'UNIT_EXECUTABLE')
        credential = Path('/proc/' + str(pid) + '/root/run/credentials/' + unit + '/config.json')
        need(credential.read_bytes() == path.read_bytes(), 'LOADED_CREDENTIAL')
        need(b'GODEBUG=multipathtcp=0' in Path('/proc/' + str(pid) + '/environ').read_bytes().split(b'\0'), 'UNIT_GODEBUG')
        sockets = run(['ss', '-H', '-lntp', 'sport', '=', ':' + str(port)]).stdout.decode()
        need(target['TARGET_IPV4'] + ':' + str(port) in sockets and 'pid=' + str(pid) + ',' in sockets, 'LISTENER_PID')
        kernel_listener(pid, port)
        stream = config['inbounds'][0]['streamSettings']
        need(stream['security'] == 'reality' and stream['network'] == 'xhttp'
             and stream['sockopt'] == {'tcpMaxSeg': 1200} and stream['xhttpSettings']['mode'] == 'auto'
             and len(config['inbounds']) == 1 and len(config['inbounds'][0]['settings']['clients']) == 1,
             'SINGLETON_XHTTP_SHAPE')
        need(stream['xhttpSettings']['host'] == host
             and stream['realitySettings']['target'] == target['TARGET_REALITY_SNI'] + ':443'
             and stream['realitySettings']['serverNames'] == [target['TARGET_REALITY_SNI']]
             and stream['realitySettings']['minClientVer'] == '26.3.27'
             and config['inbounds'][0]['listen'] == target['TARGET_IPV4']
             and config['inbounds'][0]['port'] == port, 'XHTTP_TARGET')
        main_outbounds = {o['tag']: o for o in main['outbounds']}
        tags = ['DIRECT', 'BLOCK'] if role == 'DIRECT' else ['DIRECT', 'BLOCK', 'WARP_CF']
        need(config['outbounds'] == [main_outbounds[tag] for tag in tags]
             and config['routing']['rules'][-2:] == [
                 {'type': 'field', 'inboundTag': [config['inbounds'][0]['tag']], 'network': 'tcp,udp', 'outboundTag': role},
                 {'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'BLOCK'}], 'XHTTP_EGRESS_POLICY')
        run([str(XRAY), 'run', '-test', '-config', str(path)])
    need(configs[0]['inbounds'][0]['streamSettings'] == configs[1]['inbounds'][0]['streamSettings'], 'XHTTP_TRANSPORT_CLONE')
    rows, inbounds = database(target)
    count = len(protocols(target))
    need([r['sort_index'] for r in rows] == [-1, *range(count)]
         and len(inbounds) == count and sum(bool(r[2]) for r in inbounds) == count - 1
         and any(r[1:] == (8443, 0) for r in inbounds), 'DB_PROMOTED_SHAPE')
    feeds = native(target, secret)
    if expected is not None:
        need(feeds == expected, 'FINAL_SUBSCRIPTION_CAS')
    verify_published_profiles(feeds, target, secret, configs, main)
    if do_payload:
        for index, uri in enumerate(feeds):
            payload(uri, index < count, target['TARGET_IPV4'])
    return marker


def finalize(target, secret):
    import pwd
    need(os.environ.get('CONFIRM_FRESH_XHTTP') == 'FINALIZE-FRESH-XHTTP', 'FRESH_CONFIRMATION')
    for path in (*UNIT_PATHS, ROOT, CFROOT, EXECROOT):
        need(not path.exists() and not path.is_symlink(), 'EXISTING_XHTTP_RESOURCES')
    try:
        pwd.getpwnam(USER)
    except KeyError:
        pass
    else:
        raise RuntimeError('EXISTING_XHTTP_USER')
    count = len(protocols(target))
    rows, inbounds = database(target)
    need(len(inbounds) == count and all(r[2] == 1 for r in inbounds)
         and [r['sort_index'] for r in rows] == list(range(count)), 'FRESH_DUAL_REQUIRED')
    old = [r for r in inbounds if r[1] == 8443]
    need(len(old) == 1, 'OLD_INBOUND')
    main_before = RUNTIME.read_bytes()
    main = strict_json(main_before)
    before_feed = native(target, secret)
    need(len(before_feed) == profile_count(target), 'NATIVE_PROFILE_COUNT')
    need(direct_row_matches_feed(rows[-1], before_feed[-1], target), 'DIRECT_ROW_BASELINE')
    need(sha(SOURCE_XRAY.read_bytes()) == XRAY_SHA, 'XRAY_PIN')
    route_before = routes()
    private_key, pubkey = keypair(run([str(SOURCE_XRAY), 'x25519']).stdout)
    configs = build(main, target, private_key, secrets.token_hex(8), '/' + secrets.token_hex(32))
    after_feed = promoted_feed(before_feed, target, configs, pubkey)
    cf_row = copy.deepcopy(rows[0])
    cf_row.pop('id')
    cf_row.update(value=after_feed[count - 1], remark=unquote(urlsplit(after_feed[count - 1]).fragment), sort_index=-1,
                  created_at=int(time.time() * 1000), last_fetch_at=0, last_fetch_error='')
    backup = Path(tempfile.mkdtemp(prefix='vpn-fresh-xhttp-', dir='/var/backups'))
    os.chmod(backup, 0o700)
    with closing(sqlite3.connect(DB.as_uri() + '?mode=ro', uri=True)) as source:
        with closing(sqlite3.connect(backup / 'x-ui.db')) as destination:
            source.backup(destination)
            need(destination.execute('PRAGMA quick_check').fetchone() == ('ok',), 'SNAPSHOT_DB')
    os.chmod(backup / 'x-ui.db', 0o600)
    save(backup / 'main-before.json', main_before)
    snapshot_paths = ['etc/x-ui', 'usr/local/x-ui', 'etc/krysyuk-standalone', 'etc/systemd/system',
                      'etc/nginx', 'etc/ufw', 'etc/krysyuk-warp-egress']
    if tls_mode(target) == 'letsencrypt':
        snapshot_paths.append('etc/letsencrypt')
    run(['tar', '--acls', '--xattrs', '--numeric-owner',
         '--exclude=etc/x-ui/x-ui.db', '--exclude=etc/x-ui/x-ui.db-wal', '--exclude=etc/x-ui/x-ui.db-shm',
         '-cpf', str(backup / 'managed-before.tar'),
         '-C', '/', *snapshot_paths], timeout=120)
    run(['tar', '-tf', str(backup / 'managed-before.tar')], timeout=60)
    save(backup / 'nft-before.txt', run(['nft', '-s', 'list', 'ruleset']).stdout)
    save(backup / 'ufw-before.txt', run(['ufw', 'show', 'added']).stdout)
    save(backup / 'routes-before.json', canonical(route_before))
    candidate_main = copy.deepcopy(main)
    candidate_main['inbounds'] = [i for i in main['inbounds'] if i.get('port') != 8443]
    save(backup / 'candidate-main.json', canonical(candidate_main))
    run([str(SOURCE_XRAY), 'run', '-test', '-config', str(backup / 'candidate-main.json')],
        env={**ENV, 'XRAY_LOCATION_ASSET': str(SOURCE_XRAY.parent)})
    for index, config in enumerate(configs):
        path = backup / ('candidate-' + str(index) + '.json')
        save(path, canonical(config))
        run([str(SOURCE_XRAY), 'run', '-test', '-config', str(path)],
            env={**ENV, 'XRAY_LOCATION_ASSET': str(SOURCE_XRAY.parent)})
    manifest = {p.name: sha(p.read_bytes()) for p in backup.iterdir() if p.is_file()}
    save(backup / 'snapshot-manifest.json', canonical(manifest))
    need(all(sha((backup / name).read_bytes()) == digest for name, digest in manifest.items()), 'SNAPSHOT_READBACK')
    save(backup / 'SNAPSHOT_COMPLETE', b'sqlite-quick-check-tar-digest-readback-pass\n')
    user_created = False
    user_identity = None
    created = {}
    created_versions = {}
    rule_intent = False
    sql_intent = False
    marker = None
    try:
        with defer_interruptions():
            run(['useradd', '--system', '--no-create-home', '--user-group', '--home-dir', '/nonexistent',
                 '--shell', '/usr/sbin/nologin', USER])
            user_created = True
            record = pwd.getpwnam(USER)
            user_identity = (record.pw_uid, record.pw_gid)
        for path, mode in ((EXECROOT, 0o755), (ROOT, 0o700), (CFROOT, 0o700)):
            create_owned_directory(path, mode, created, created_versions)
        for name, source in [('xray', SOURCE_XRAY), ('geoip.dat', SOURCE_XRAY.parent / 'geoip.dat'),
                             ('geosite.dat', SOURCE_XRAY.parent / 'geosite.dat')]:
            path = EXECROOT / name
            raw = source.read_bytes()
            save_owned(path, raw, created, created_versions, mode=0o555 if name == 'xray' else 0o444)
        os.chmod(EXECROOT, 0o555)
        for config, conf, unit in zip(configs, (DIRECT_CONF, WARP_CONF), UNIT_PATHS):
            for path, raw in ((conf, canonical(config)), (unit, unit_bytes(conf))):
                save_owned(path, raw, created, created_versions)
            run(['systemd-analyze', 'verify', str(unit)])
        marker = {'version': 2, 'target': target['TARGET_IPV4'], 'operation_id': secrets.token_hex(16),
                  'status': 'pending', 'direct_config_sha256': sha(DIRECT_CONF.read_bytes()),
                  'warp_config_sha256': sha(WARP_CONF.read_bytes()), 'main_runtime_sha256': sha(canonical(main))}
        save_owned(MARKER, canonical(marker), created, created_versions)
        save(backup / 'plan.private.json', canonical({'rows': rows, 'old': old, 'feed_before': before_feed,
                                                     'feed_after': after_feed, 'operation_id': marker['operation_id']}))
        run(['systemctl', 'stop', 'x-ui.service'])
        sql_intent = True
        sql({'action': 'apply', 'expected_rows': rows, 'expected_enable': 1, 'wanted_enable': 0,
             'inbound': old[0][0], 'direct_id': rows[-1]['id'], 'direct_uri': after_feed[-1],
             'direct_label': unquote(urlsplit(after_feed[-1]).fragment), 'cf_row': cf_row})
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'start', 'x-ui.service'])
        for unit in UNITS:
            run(['systemctl', 'enable', '--now', unit], timeout=45)
        need('8444' not in (backup / 'ufw-before.txt').read_text(), 'FIREWALL_EXISTING_8444')
        rule_intent = True
        run(['ufw', 'allow', 'in', 'on', target['TARGET_INTERFACE'], 'to', target['TARGET_IPV4'],
             'port', '8444', 'proto', 'tcp', 'comment', 'vpn-xhttp-direct'])
        time.sleep(2)
        marker['main_runtime_sha256'] = sha(canonical(strict_json(RUNTIME.read_bytes())))
        atomic_owned(MARKER, canonical(marker), created, created_versions)
        verify(target, secret, expected=after_feed, allow_pending=True)
        need(routes() == route_before, 'MAIN_ROUTE_DRIFT')
        marker['status'] = 'committed'
        atomic_owned(MARKER, canonical(marker), created, created_versions)
        save(backup / 'COMMITTED',
             ('fresh-promoted-' + str(profile_count(target)) + '-native3UA-TCP-UDP-egress-pass\n').encode())
        print('FRESH_XHTTP_COMMITTED=1')
    except BaseException:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        for unit in UNITS:
            subprocess.run(['systemctl', 'disable', '--now', unit], capture_output=True, timeout=30)
        if sql_intent:
            run(['systemctl', 'stop', 'x-ui.service'])
            current_rows, current_inbounds = database(target)
            if current_rows != rows:
                added = [r for r in current_rows if r['sort_index'] == -1]
                need(len(added) == 1 and all(added[0].get(k) == v for k, v in cf_row.items()), 'ROLLBACK_FOREIGN_SQL')
                restored = [copy.deepcopy(r) for r in current_rows if r['id'] != added[0]['id']]
                for row in restored:
                    if row['id'] == rows[-1]['id']:
                        need(row['value'] == after_feed[-1], 'ROLLBACK_FOREIGN_DIRECT')
                        row['value'], row['remark'] = rows[-1]['value'], rows[-1]['remark']
                need(restored == rows, 'ROLLBACK_FOREIGN_ROWS')
                sql({'action': 'rollback', 'expected_rows': current_rows, 'expected_enable': 0,
                     'wanted_enable': 1, 'inbound': old[0][0], 'cf_id': added[0]['id'], 'old_direct': rows[-1]})
            else:
                need(current_inbounds == inbounds, 'ROLLBACK_UNKNOWN_SQL_OUTCOME')
        if rule_intent:
            run(['ufw', '--force', 'delete', 'allow', 'in', 'on', target['TARGET_INTERFACE'], 'to',
                 target['TARGET_IPV4'], 'port', '8444', 'proto', 'tcp', 'comment', 'vpn-xhttp-direct'])
        remove_owned_paths(created, created_versions)
        run(['systemctl', 'daemon-reload'])
        if user_created:
            record = pwd.getpwnam(USER)
            need((record.pw_uid, record.pw_gid) == user_identity, 'ROLLBACK_FOREIGN_USER')
            run(['userdel', USER])
            import grp
            try:
                group = grp.getgrnam(USER)
            except KeyError:
                group = None
            if group is not None:
                need(group.gr_gid == user_identity[1] and not group.gr_mem and
                     not any(u.pw_gid == group.gr_gid for u in pwd.getpwall()), 'ROLLBACK_FOREIGN_GROUP')
                run(['groupdel', USER])
        run(['systemctl', 'start', 'x-ui.service'])
        time.sleep(2)
        verify_xhttp_rollback(target, secret, main_before, rows, inbounds,
                              before_feed, route_before)
        save(backup / 'ROLLBACK_VERIFIED', b'owned-fresh-XHTTP-delta-restored\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--apply', action='store_true')
    group.add_argument('--verify', action='store_true')
    group.add_argument('--verify-legacy-rollback', action='store_true')
    parser.add_argument('--rollback-snapshot', type=Path)
    parser.add_argument('--baseline-feed', type=Path)
    args = parser.parse_args()
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    os.umask(0o077)
    import fcntl
    fd = os.open('/run/vpn-fresh-xhttp.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    target, secret = envfile(TARGET_ENV), envfile(SERVER_ENV)
    address = ipaddress.ip_address(target['TARGET_IPV4'])
    need(address.version == 4 and address.is_global, 'PUBLIC_IPV4_REQUIRED')
    endpoint(target)
    profile_names(target)
    def interrupted(signum, frame):
        raise RuntimeError('INTERRUPTED')
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    if args.apply:
        need(args.rollback_snapshot is None and args.baseline_feed is None, 'UNEXPECTED_ROLLBACK_ARG')
        finalize(target, secret)
    elif args.verify:
        need(args.rollback_snapshot is None and args.baseline_feed is None, 'UNEXPECTED_ROLLBACK_ARG')
        need(strict_json(private(MARKER))['status'] == 'committed', 'MARKER_NOT_COMMITTED')
        verify(target, secret)
        print('PROMOTED_XHTTP_VERIFY_OK=1')
    else:
        need(args.rollback_snapshot is not None, 'ROLLBACK_SNAPSHOT_REQUIRED')
        verify_legacy_rollback(target, secret, args.rollback_snapshot, args.baseline_feed)
        print('LEGACY_ROLLBACK_E2E_OK=1')


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        code = str(error) if isinstance(error, RuntimeError) and re.fullmatch('[A-Z0-9_]+', str(error)) else type(error).__name__
        print('FRESH_XHTTP_FAILED=' + code, file=sys.stderr)
        raise SystemExit(1)
