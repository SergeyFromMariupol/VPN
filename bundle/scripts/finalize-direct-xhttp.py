#!/usr/bin/env python3
"""Promote a fresh direct-only XHTTP profile to independent REALITY/XHTTP.

The first-install baseline is created by configure-standalone.sh. This phase
retires its TCP/8443 XHTTP inbound, publishes the independently served
TCP/8444 link, and never installs or invokes WARP. All private rollback data
stays on the server.
"""
import argparse
import copy
import importlib.util
import ipaddress
import json
import os
import pwd
import re
import secrets
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import unquote

_spec = importlib.util.spec_from_file_location(
    'vpn_xhttp_shared', Path(__file__).with_name('finalize-xhttp.py'))
x = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(x)

DB = x.DB
RUNTIME = x.RUNTIME
SOURCE_XRAY = x.SOURCE_XRAY
EXECROOT = x.EXECROOT
XRAY = x.XRAY
ROOT = x.ROOT
CONF = x.DIRECT_CONF
MARKER = x.MARKER
BASELINE = ROOT / 'baseline.json'
UNIT = 'germanyvpn-xhttp-test.service'
UNIT_PATH = Path('/etc/systemd/system') / UNIT
SERVER_ENV = x.SERVER_ENV
TARGET_ENV = x.TARGET_ENV
USER = x.USER
OLD_RULE = "ufw allow 8443/tcp comment 'VLESS XHTTP TLS H2'"
NEW_RULE = 'vpn-xhttp-direct'


def names(target):
    label = target['TARGET_LABEL']
    return [label + ' · 🖥️ IP сервера · ' + protocol for protocol in x.protocols(target)]


def database():
    with closing(sqlite3.connect(DB.as_uri() + '?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        x.need(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'DB_QUICK_CHECK')
        return {
            'clients': [dict(row) for row in db.execute(
                'SELECT id,email,sub_id,comment,uuid,auth,enable FROM clients ORDER BY id')],
            'joins': [dict(row) for row in db.execute(
                'SELECT client_id,inbound_id,flow_override FROM client_inbounds '
                'ORDER BY client_id,inbound_id')],
            'inbounds': [dict(row) for row in db.execute(
                'SELECT id,port,enable,sub_sort_index FROM inbounds ORDER BY id')],
            'external': [dict(row) for row in db.execute(
                'SELECT id,client_id,kind,value,remark,enable,expiry_time,name_prefix,'
                'sort_index,created_at,last_fetch_at,last_fetch_error '
                'FROM client_external_links ORDER BY sort_index,id')],
        }


def baseline_db(db, target, secret):
    protocols = x.protocols(target)
    emails = ['germany-' + protocol.lower() for protocol in protocols]
    clients = db['clients']
    x.need(len(clients) == len(protocols) and
           {c['email'] for c in clients} == set(emails), 'BASELINE_CLIENTS')
    by_email = {c['email']: c for c in clients}
    for protocol, email, name in zip(protocols, emails, names(target)):
        client = by_email[email]
        expected_identity = (secret['HYSTERIA2_AUTH'] if protocol == 'HYSTERIA2'
                             else secret['VLESS_UUID'])
        actual_identity = (client['auth'] if protocol == 'HYSTERIA2' else client['uuid'])
        x.need(client['sub_id'] == secret['SUBSCRIPTION_ID'] and client['comment'] == name
               and actual_identity == expected_identity and client['enable'] == 1,
               'BASELINE_CLIENT_IDENTITY')
    inbounds = db['inbounds']
    x.need(len(inbounds) == len(protocols) and not db['external'] and
           all(ib['enable'] == 1 for ib in inbounds), 'BASELINE_INBOUNDS')
    wanted_ports = {443: 2, 8443: 1} if x.tls_mode(target) == 'letsencrypt' else {443: 1, 8443: 1}
    observed = {port: sum(ib['port'] == port for ib in inbounds) for port in wanted_ports}
    x.need(observed == wanted_ports and
           sorted(ib['sub_sort_index'] for ib in inbounds) == list(range(1, len(protocols) + 1)),
           'BASELINE_INBOUND_PORTS')
    x.need(len(db['joins']) == len(protocols) and
           {j['client_id'] for j in db['joins']} == {c['id'] for c in clients} and
           {j['inbound_id'] for j in db['joins']} == {ib['id'] for ib in inbounds},
           'BASELINE_JOINS')
    return next(ib for ib in inbounds if ib['port'] == 8443), by_email['germany-reality']


def build_direct(main, target, private_key, sid, path):
    """Use the pinned dual promoter's direct transport without any WARP role."""
    host = x.endpoint(target)
    old = [ib for ib in main['inbounds'] if ib.get('port') == 8443]
    x.need(len(old) == 1 and len(old[0]['settings']['clients']) == 1 and
           old[0]['settings']['clients'][0]['email'] == 'germany-xhttp',
           'OLD_XHTTP_CLIENT')
    outbounds = {item['tag']: item for item in main['outbounds']}
    x.need(set(outbounds) == {'DIRECT', 'BLOCK'}, 'DIRECT_ONLY_OUTBOUNDS')
    dns_tags = [server['tag'] for server in main['dns']['servers'] if 'tag' in server]
    tag = 'XHTTP_DIRECT'
    stream = {
        'network': 'xhttp', 'security': 'reality', 'sockopt': {'tcpMaxSeg': 1200},
        'xhttpSettings': {'host': host, 'path': path, 'mode': 'auto'},
        'realitySettings': {
            'show': False, 'xver': 0,
            'target': x.reality_destination(target),
            'serverNames': [target['TARGET_REALITY_SNI']],
            'privateKey': private_key, 'shortIds': [sid],
            'minClientVer': '26.3.27',
        },
    }
    rules = [
        {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'BLOCK'},
        {'type': 'field', 'inboundTag': dns_tags, 'outboundTag': 'DIRECT'},
        {'type': 'field', 'ip': ['geoip:private', '::/0', target['TARGET_IPV4'] + '/32'],
         'outboundTag': 'BLOCK'},
        {'type': 'field', 'domain': ['full:' + host], 'outboundTag': 'BLOCK'},
        {'type': 'field', 'inboundTag': [tag], 'network': 'tcp,udp', 'outboundTag': 'DIRECT'},
        {'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'BLOCK'},
    ]
    return {
        'log': {'loglevel': 'none'}, 'dns': copy.deepcopy(main['dns']),
        'inbounds': [{
            'listen': target['TARGET_IPV4'], 'port': 8444, 'tag': tag,
            'protocol': 'vless',
            'settings': {'clients': [copy.deepcopy(old[0]['settings']['clients'][0])],
                         'decryption': 'none'},
            'streamSettings': stream,
            'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'],
                         'routeOnly': True},
        }],
        'outbounds': [copy.deepcopy(outbounds[k]) for k in ('DIRECT', 'BLOCK')],
        'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': rules},
    }


def validate_feed(feed, config, target, secret):
    x.need(len(feed) == len(x.protocols(target)) and len(set(feed)) == len(feed),
           'DIRECT_FEED_COUNT')
    host = x.endpoint(target)
    expected_names = names(target)
    for uri, protocol, name in zip(feed, x.protocols(target), expected_names):
        parsed, values = x.query(uri)
        identity = secret['HYSTERIA2_AUTH'] if protocol == 'HYSTERIA2' else secret['VLESS_UUID']
        x.need(parsed.hostname == host and parsed.username == identity and
               unquote(parsed.fragment) == name, 'DIRECT_FEED_IDENTITY')
        if protocol == 'XHTTP':
            x.need(uri == x.uri_for(config, x.public_key(config), name), 'DIRECT_XHTTP_URI')
        elif protocol == 'REALITY':
            x.need(parsed.scheme == 'vless' and parsed.port == 443 and
                   values.get('security') == 'reality' and values.get('type') == 'grpc' and
                   values.get('serviceName') == 'reality-grpc' and values.get('flow', '') == '' and
                   values.get('sni') == target['TARGET_REALITY_SNI'] and
                   values.get('pbk') == secret['REALITY_PUBLIC_KEY'] and
                   values.get('sid') == secret['REALITY_SHORT_ID'], 'DIRECT_REALITY_URI')
        else:
            x.need(parsed.scheme in ('hysteria2', 'hy2') and parsed.port == 443 and
                   values.get('sni') == host and values.get('alpn') == 'h3' and
                   values.get('insecure', '0') == '0', 'DIRECT_HYSTERIA_URI')


def firewall(target, promoted):
    added = x.run(['ufw', 'show', 'added']).stdout.decode()
    old = [line for line in added.splitlines() if re.search(r'\b8443/tcp\b', line)]
    new = [line for line in added.splitlines() if re.search(r'\b8444\b', line)]
    if promoted:
        x.need(not old and len(new) == 1 and
               NEW_RULE in new[0] and target['TARGET_IPV4'] in new[0] and
               target['TARGET_INTERFACE'] in new[0], 'PROMOTED_UFW')
    else:
        x.need(old == [OLD_RULE] and not new, 'BASELINE_UFW')
    return added


SQL_CHILD = r'''
import json,sqlite3,sys
p=json.load(sys.stdin)
with sqlite3.connect('file:'+p['db']+'?mode=rw',uri=True,timeout=10) as db:
 db.row_factory=sqlite3.Row
 db.execute('BEGIN IMMEDIATE')
 clients=[dict(r) for r in db.execute('SELECT id,email,sub_id,comment,uuid,auth,enable FROM clients ORDER BY id')]
 joins=[dict(r) for r in db.execute('SELECT client_id,inbound_id,flow_override FROM client_inbounds ORDER BY client_id,inbound_id')]
 current=[dict(r) for r in db.execute('SELECT id,port,enable,sub_sort_index FROM inbounds ORDER BY id')]
 external=[dict(r) for r in db.execute('SELECT id,client_id,kind,value,remark,enable,expiry_time,name_prefix,sort_index,created_at,last_fetch_at,last_fetch_error FROM client_external_links ORDER BY sort_index,id')]
 if clients!=p['expected_clients'] or joins!=p['expected_joins'] or current!=p['expected_inbounds'] or external!=p['expected_external']:raise RuntimeError('SQL_CAS')
 if p['action']=='apply':
  if db.execute('UPDATE inbounds SET enable=0 WHERE id=? AND enable=1',(p['old_id'],)).rowcount!=1:raise RuntimeError('SQL_INBOUND_CAS')
  r=p['new_row'];keys=list(r)
  db.execute('INSERT INTO client_external_links('+','.join(keys)+') VALUES('+','.join('?' for _ in keys)+')',[r[k] for k in keys])
 else:
  if db.execute('DELETE FROM client_external_links WHERE id=?',(p['new_id'],)).rowcount!=1:raise RuntimeError('SQL_LINK_CAS')
  if db.execute('UPDATE inbounds SET enable=1 WHERE id=? AND enable=0',(p['old_id'],)).rowcount!=1:raise RuntimeError('SQL_INBOUND_CAS')
 if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise RuntimeError('SQL_QUICK_CHECK')
'''


def sql(payload):
    x.need(pwd.getpwuid(DB.stat().st_uid).pw_name == 'xui', 'DB_OWNER')
    x.run(['runuser', '-u', 'xui', '--', 'python3', '-c', SQL_CHILD], timeout=20,
          input=json.dumps({'db': str(DB), **payload}).encode())


def marker_data(target, config, baseline, main, status='pending'):
    return {
        'version': 3, 'mode': 'direct-only', 'target': target['TARGET_IPV4'],
        'operation_id': secrets.token_hex(16), 'status': status,
        'direct_config_sha256': x.sha(x.canonical(config)),
        'baseline_sha256': x.sha(x.canonical(baseline)),
        'main_runtime_sha256': x.sha(x.canonical(main)),
    }


def verify(target, secret, selected=False, allow_pending=False, expected=None):
    x.need(target.get('TARGET_EGRESS_MODE') == 'direct', 'DIRECT_MODE_REQUIRED')
    for path, mode in ((ROOT, 0o700), (EXECROOT, 0o555)):
        info = path.lstat()
        x.need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
               stat.S_IMODE(info.st_mode) == mode, 'PROMOTION_DIRECTORY')
    marker = x.strict_json(x.private(MARKER))
    x.need(set(marker) == {'version', 'mode', 'target', 'operation_id', 'status',
                           'direct_config_sha256', 'baseline_sha256', 'main_runtime_sha256'} and
           marker['version'] == 3 and marker['mode'] == 'direct-only' and
           marker['target'] == target['TARGET_IPV4'] and
           re.fullmatch('[0-9a-f]{32}', marker['operation_id']) and
           marker['status'] in (('pending', 'committed') if allow_pending else ('committed',)),
           'DIRECT_MARKER')
    conf_raw, base_raw = x.private(CONF), x.private(BASELINE)
    config, baseline = x.strict_json(conf_raw), x.strict_json(base_raw)
    x.need(x.sha(conf_raw) == marker['direct_config_sha256'] and
           x.sha(base_raw) == marker['baseline_sha256'] and
           set(baseline) == {'links'} and isinstance(baseline['links'], list),
           'DIRECT_MARKER_HASH')
    main_raw = RUNTIME.read_bytes()
    main = x.strict_json(main_raw)
    if not selected:
        x.need(x.sha(x.canonical(main)) == marker['main_runtime_sha256'],
               'DIRECT_MAIN_HASH')
    x.run(['systemctl', 'is-active', 'x-ui.service'])
    x.need(x.sha(XRAY.read_bytes()) == x.XRAY_SHA and
           not x.CFROOT.exists() and not x.CFROOT.is_symlink() and
           not (Path('/etc/systemd/system') / x.UNITS[1]).exists(), 'NO_WARP_RESOURCES')
    outbounds = {out['tag']: out for out in main['outbounds']}
    x.need(set(outbounds) == {'DIRECT', 'BLOCK'} and
           config['outbounds'] == [outbounds['DIRECT'], outbounds['BLOCK']],
           'DIRECT_EGRESS_ONLY')
    x.need(not any(ib.get('port') in (8443, 8444) for ib in main['inbounds']),
           'MAIN_XHTTP_RETIRED')
    reality = [ib for ib in main['inbounds'] if ib.get('port') == 443 and
               ib.get('streamSettings', {}).get('security') == 'reality']
    x.need(len(reality) == 1 and reality[0]['streamSettings']['network'] == 'grpc' and
           reality[0]['streamSettings']['grpcSettings']['serviceName'] == 'reality-grpc' and
           x.reality_settings_match(reality[0]['streamSettings']['realitySettings'], target) and
           reality[0]['streamSettings']['realitySettings']['shortIds'] ==
           [secret['REALITY_SHORT_ID']], 'MAIN_REALITY')
    x.need(x.public_key({'inbounds': reality}) == secret['REALITY_PUBLIC_KEY'],
           'MAIN_REALITY_KEY')
    side_clients = config['inbounds'][0]['settings']['clients'] if len(config['inbounds']) == 1 else []
    x.need(len(config['inbounds']) == 1 and
           config['inbounds'][0]['listen'] == target['TARGET_IPV4'] and
           config['inbounds'][0]['port'] == 8444 and
           len(side_clients) == 1 and
           side_clients[0]['id'] == secret['VLESS_UUID'] and
           side_clients[0]['email'] == 'germany-xhttp' and
           side_clients[0].get('flow', '') == '' and
           config['inbounds'][0]['streamSettings']['security'] == 'reality' and
           config['inbounds'][0]['streamSettings']['network'] == 'xhttp' and
           config['inbounds'][0]['streamSettings']['sockopt'] == {'tcpMaxSeg': 1200} and
           config['inbounds'][0]['streamSettings']['xhttpSettings']['mode'] == 'auto' and
           config['inbounds'][0]['streamSettings']['xhttpSettings']['host'] == x.endpoint(target) and
           x.reality_settings_match(config['inbounds'][0]['streamSettings']['realitySettings'], target),
           'DIRECT_XHTTP_CONFIG')
    x.need(config['routing']['rules'][-2:] == [
        {'type': 'field', 'inboundTag': ['XHTTP_DIRECT'], 'network': 'tcp,udp',
         'outboundTag': 'DIRECT'},
        {'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'BLOCK'},
    ], 'DIRECT_XHTTP_ROUTE')
    x.run(['systemctl', 'is-active', UNIT])
    x.run(['systemctl', 'is-enabled', UNIT])
    x.need(x.private(UNIT_PATH) == x.unit_bytes(CONF), 'DIRECT_UNIT_BYTES')
    pid = int(x.run(['systemctl', 'show', UNIT, '-p', 'MainPID', '--value']).stdout)
    x.need(pid > 1 and Path('/proc/' + str(pid) + '/exe').resolve() == XRAY,
           'DIRECT_UNIT_EXECUTABLE')
    credential = Path('/proc/' + str(pid) + '/root/run/credentials/' + UNIT + '/config.json')
    x.need(credential.read_bytes() == conf_raw, 'DIRECT_LOADED_CREDENTIAL')
    x.need(b'GODEBUG=multipathtcp=0' in
           Path('/proc/' + str(pid) + '/environ').read_bytes().split(b'\0'),
           'DIRECT_GODEBUG')
    sockets = x.run(['ss', '-H', '-lntp', 'sport', '=', ':8444']).stdout.decode()
    x.need(target['TARGET_IPV4'] + ':8444' in sockets and 'pid=' + str(pid) + ',' in sockets,
           'DIRECT_LISTENER_PID')
    x.kernel_listener(pid, 8444)
    x.need(not x.run(['ss', '-H', '-lnt', 'sport', '=', ':8443']).stdout.strip(),
           'RETIRED_8443_LISTENER')
    firewall(target, promoted=True)
    x.run([str(XRAY), 'run', '-test', '-config', str(CONF)])
    x.run([str(SOURCE_XRAY), 'run', '-test', '-config', str(RUNTIME)],
          env={**x.ENV, 'XRAY_LOCATION_ASSET': str(SOURCE_XRAY.parent)})
    links = baseline['links']
    validate_feed(links, config, target, secret)
    if not selected:
        db = database()
        old = [ib for ib in db['inbounds'] if ib['port'] == 8443]
        reality_client = next((c for c in db['clients'] if c['email'] == 'germany-reality'), None)
        x.need(len(old) == 1 and old[0]['enable'] == 0 and reality_client is not None and
               len(db['external']) == 1, 'DIRECT_DB_PROMOTED')
        row = db['external'][0]
        x.need(row['client_id'] == reality_client['id'] and row['kind'] == 'link' and
               row['value'] == links[-1] and row['remark'] == names(target)[-1] and
               row['enable'] == 1 and row['expiry_time'] == 0 and
               row['sort_index'] == 0, 'DIRECT_DB_EXTERNAL')
        public = x.native(target, secret, expected_count=len(links))
        x.need(public == links and (expected is None or public == expected),
               'DIRECT_PUBLIC_BASELINE')
    if selected and target.get('TARGET_PROFILE_SET') == 'custom':
        catalog_path = Path(__file__).resolve().parents[1] / 'portfolio/portfolio_catalog.py'
        spec = importlib.util.spec_from_file_location('vpn_direct_selection', catalog_path)
        catalog = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(catalog)
        recipes = catalog.select_profiles('custom', 'direct', target['TARGET_LABEL'],
                                          target['TARGET_PROFILE_IDS'],
                                          target.get('TARGET_PROFILE_ORDER', 'legacy'))
        names_selected = {row['name'] for row in recipes if row['baseline_reuse']}
        links = [uri for uri in links if unquote(x.query(uri)[0].fragment) in names_selected]
        x.need(len(links) == len(names_selected), 'DIRECT_SELECTED_BASELINE')
    for uri in links:
        x.payload(uri, False, target['TARGET_IPV4'])
    return marker


def promote(target, secret):
    x.need(os.environ.get('CONFIRM_FRESH_XHTTP') == 'FINALIZE-FRESH-DIRECT-XHTTP',
           'FRESH_CONFIRMATION')
    x.need(target.get('TARGET_EGRESS_MODE') == 'direct', 'DIRECT_MODE_REQUIRED')
    for path in (UNIT_PATH, ROOT, EXECROOT, x.CFROOT,
                 Path('/etc/systemd/system') / x.UNITS[1]):
        x.need(not path.exists() and not path.is_symlink(), 'EXISTING_XHTTP_RESOURCES')
    try:
        pwd.getpwnam(USER)
    except KeyError:
        pass
    else:
        raise RuntimeError('EXISTING_XHTTP_USER')
    before_db = database()
    old, reality_client = baseline_db(before_db, target, secret)
    before_feed = x.native(target, secret, expected_count=len(x.protocols(target)))
    x.need([unquote(x.query(uri)[0].fragment) for uri in before_feed] == names(target),
           'DIRECT_BASELINE_NAMES')
    before_main_raw = RUNTIME.read_bytes()
    before_main = x.strict_json(before_main_raw)
    x.need(x.sha(SOURCE_XRAY.read_bytes()) == x.XRAY_SHA, 'XRAY_PIN')
    before_routes = x.routes()
    before_ufw = firewall(target, promoted=False)
    private_key, pubkey = x.keypair(x.run([str(SOURCE_XRAY), 'x25519']).stdout)
    config = build_direct(before_main, target, private_key, secrets.token_hex(8),
                          '/' + secrets.token_hex(32))
    link = x.uri_for(config, pubkey, names(target)[-1])
    after_feed = [*before_feed[:-1], link]
    validate_feed(after_feed, config, target, secret)
    candidate_main = copy.deepcopy(before_main)
    candidate_main['inbounds'] = [ib for ib in before_main['inbounds']
                                  if ib.get('port') != 8443]
    backup = Path(tempfile.mkdtemp(prefix='vpn-fresh-direct-xhttp-', dir='/var/backups'))
    os.chmod(backup, 0o700)
    with closing(sqlite3.connect(DB.as_uri() + '?mode=ro', uri=True)) as source:
        with closing(sqlite3.connect(backup / 'x-ui.db')) as dest:
            source.backup(dest)
            x.need(dest.execute('PRAGMA quick_check').fetchone() == ('ok',), 'SNAPSHOT_DB')
    os.chmod(backup / 'x-ui.db', 0o600)
    x.save(backup / 'main-before.json', before_main_raw)
    paths = ['etc/x-ui', 'usr/local/x-ui', 'etc/krysyuk-standalone',
             'etc/systemd/system', 'etc/nginx', 'etc/ufw']
    if x.tls_mode(target) == 'letsencrypt':
        paths.append('etc/letsencrypt')
    x.run(['tar', '--acls', '--xattrs', '--numeric-owner',
           '--exclude=etc/x-ui/x-ui.db', '--exclude=etc/x-ui/x-ui.db-wal',
           '--exclude=etc/x-ui/x-ui.db-shm', '-cpf', str(backup / 'managed-before.tar'),
           '-C', '/', *paths], timeout=120)
    x.run(['tar', '-tf', str(backup / 'managed-before.tar')], timeout=60)
    x.save(backup / 'nft-before.txt', x.run(['nft', '-s', 'list', 'ruleset']).stdout)
    x.save(backup / 'ufw-before.txt', before_ufw.encode())
    x.save(backup / 'routes-before.json', x.canonical(before_routes))
    x.save(backup / 'candidate-main.json', x.canonical(candidate_main))
    x.save(backup / 'candidate-direct.json', x.canonical(config))
    for candidate in ('candidate-main.json', 'candidate-direct.json'):
        x.run([str(SOURCE_XRAY), 'run', '-test', '-config', str(backup / candidate)],
              env={**x.ENV, 'XRAY_LOCATION_ASSET': str(SOURCE_XRAY.parent)})
    manifest = {p.name: x.sha(p.read_bytes()) for p in backup.iterdir() if p.is_file()}
    x.save(backup / 'snapshot-manifest.json', x.canonical(manifest))
    x.need(all(x.sha((backup / name).read_bytes()) == digest for name, digest in manifest.items()),
           'SNAPSHOT_READBACK')
    x.save(backup / 'SNAPSHOT_COMPLETE', b'sqlite-quick-check-tar-digest-readback-pass\n')
    created, versions = {}, {}
    user_created = False
    user_identity = None
    sql_intent = False
    rule8444_intent = False
    rule8443_intent = False
    row = {
        'client_id': reality_client['id'], 'kind': 'link', 'value': link,
        'remark': names(target)[-1], 'enable': 1, 'expiry_time': 0,
        'name_prefix': '', 'sort_index': 0, 'created_at': int(time.time() * 1000),
        'last_fetch_at': 0, 'last_fetch_error': '',
    }
    try:
        with x.defer_interruptions():
            x.run(['useradd', '--system', '--no-create-home', '--user-group',
                   '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', USER])
            user_created = True
            record = pwd.getpwnam(USER)
            user_identity = record.pw_uid, record.pw_gid
        x.create_owned_directory(EXECROOT, 0o755, created, versions)
        x.create_owned_directory(ROOT, 0o700, created, versions)
        for name, source in [('xray', SOURCE_XRAY),
                             ('geoip.dat', SOURCE_XRAY.parent / 'geoip.dat'),
                             ('geosite.dat', SOURCE_XRAY.parent / 'geosite.dat')]:
            raw = source.read_bytes()
            x.save_owned(EXECROOT / name, raw, created, versions,
                         mode=0o555 if name == 'xray' else 0o444)
        os.chmod(EXECROOT, 0o555)
        x.save_owned(CONF, x.canonical(config), created, versions)
        x.save_owned(BASELINE, x.canonical({'links': after_feed}), created, versions)
        x.save_owned(UNIT_PATH, x.unit_bytes(CONF), created, versions)
        x.run(['systemd-analyze', 'verify', str(UNIT_PATH)])
        marker = marker_data(target, config, {'links': after_feed}, before_main)
        x.save_owned(MARKER, x.canonical(marker), created, versions)
        x.save(backup / 'plan.private.json', x.canonical({
            'db_before': before_db, 'feed_before': before_feed, 'feed_after': after_feed,
            'operation_id': marker['operation_id'],
        }))
        x.run(['systemctl', 'stop', 'x-ui.service'])
        sql_intent = True
        sql({'action': 'apply', 'expected_inbounds': before_db['inbounds'],
             'expected_external': before_db['external'],
             'expected_clients': before_db['clients'], 'expected_joins': before_db['joins'],
             'old_id': old['id'],
             'new_row': row})
        x.run(['systemctl', 'daemon-reload'])
        x.run(['systemctl', 'start', 'x-ui.service'])
        x.run(['systemctl', 'enable', '--now', UNIT], timeout=45)
        rule8444_intent = True
        x.run(['ufw', 'allow', 'in', 'on', target['TARGET_INTERFACE'], 'to',
               target['TARGET_IPV4'], 'port', '8444', 'proto', 'tcp', 'comment', NEW_RULE])
        rule8443_intent = True
        x.run(['ufw', '--force', 'delete', 'allow', '8443/tcp'])
        x.run(['ufw', 'reload'])
        time.sleep(2)
        marker['main_runtime_sha256'] = x.sha(x.canonical(x.strict_json(RUNTIME.read_bytes())))
        x.atomic_owned(MARKER, x.canonical(marker), created, versions)
        verify(target, secret, allow_pending=True, expected=after_feed)
        x.need(x.routes() == before_routes, 'MAIN_ROUTE_DRIFT')
        marker['status'] = 'committed'
        x.atomic_owned(MARKER, x.canonical(marker), created, versions)
        x.save(backup / 'COMMITTED', b'direct-only-native3UA-TCP-UDP-egress-pass\n')
        print('DIRECT_XHTTP_COMMITTED=1')
    except BaseException:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        subprocess.run(['systemctl', 'disable', '--now', UNIT], capture_output=True, timeout=30)
        if sql_intent:
            x.run(['systemctl', 'stop', 'x-ui.service'])
            current = database()
            x.need(current['clients'] == before_db['clients'] and
                   current['joins'] == before_db['joins'], 'ROLLBACK_FOREIGN_CLIENTS')
            if current['inbounds'] != before_db['inbounds'] or current['external']:
                added = current['external']
                x.need(len(added) == 1 and
                       all(added[0].get(key) == value for key, value in row.items()) and
                       [dict(ib, enable=1) if ib['id'] == old['id'] else ib
                        for ib in current['inbounds']] == before_db['inbounds'],
                       'ROLLBACK_FOREIGN_SQL')
                sql({'action': 'rollback', 'expected_inbounds': current['inbounds'],
                     'expected_external': current['external'],
                     'expected_clients': before_db['clients'], 'expected_joins': before_db['joins'],
                     'old_id': old['id'],
                     'new_id': added[0]['id']})
            else:
                x.need(current == before_db, 'ROLLBACK_UNKNOWN_SQL_OUTCOME')
        if rule8443_intent:
            rules_now = x.run(['ufw', 'show', 'added']).stdout.decode().splitlines()
            old_now = [line for line in rules_now if re.search(r'\b8443/tcp\b', line)]
            x.need(not old_now or old_now == [OLD_RULE], 'ROLLBACK_FOREIGN_8443')
            if not old_now:
                x.run(['ufw', 'allow', '8443/tcp', 'comment', 'VLESS XHTTP TLS H2'])
        if rule8444_intent and NEW_RULE in x.run(['ufw', 'show', 'added']).stdout.decode():
            x.run(['ufw', '--force', 'delete', 'allow', 'in', 'on',
                   target['TARGET_INTERFACE'], 'to', target['TARGET_IPV4'],
                   'port', '8444', 'proto', 'tcp', 'comment', NEW_RULE])
        x.run(['ufw', 'reload'])
        x.need(set(x.run(['ufw', 'show', 'added']).stdout.decode().splitlines()) ==
               set(before_ufw.splitlines()),
               'ROLLBACK_UFW')
        x.remove_owned_paths(created, versions)
        x.run(['systemctl', 'daemon-reload'])
        if user_created:
            record = pwd.getpwnam(USER)
            x.need((record.pw_uid, record.pw_gid) == user_identity,
                   'ROLLBACK_FOREIGN_USER')
            x.run(['userdel', USER])
            import grp
            try:
                group = grp.getgrnam(USER)
            except KeyError:
                group = None
            if group is not None:
                x.need(group.gr_gid == user_identity[1] and not group.gr_mem and
                       not any(u.pw_gid == group.gr_gid for u in pwd.getpwall()),
                       'ROLLBACK_FOREIGN_GROUP')
                x.run(['groupdel', USER])
        x.run(['systemctl', 'start', 'x-ui.service'])
        time.sleep(2)
        x.need(database() == before_db and
               x.strict_json(RUNTIME.read_bytes()) == before_main and
               x.routes() == before_routes, 'ROLLBACK_READBACK')
        firewall(target, promoted=False)
        x.need(x.native(target, secret, expected_count=len(before_feed)) == before_feed,
               'ROLLBACK_FEED')
        for uri in before_feed:
            x.payload(uri, False, target['TARGET_IPV4'], binary=SOURCE_XRAY)
        x.save(backup / 'ROLLBACK_VERIFIED', b'owned-direct-XHTTP-delta-restored\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--apply', action='store_true')
    group.add_argument('--verify', action='store_true')
    group.add_argument('--verify-selected', action='store_true')
    args = parser.parse_args()
    x.need(os.geteuid() == 0, 'ROOT_REQUIRED')
    os.umask(0o077)
    import fcntl
    fd = os.open('/run/vpn-fresh-xhttp.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    target, secret = x.envfile(TARGET_ENV), x.envfile(SERVER_ENV)
    address = ipaddress.ip_address(target['TARGET_IPV4'])
    x.need(address.version == 4 and address.is_global, 'PUBLIC_IPV4_REQUIRED')
    x.endpoint(target)
    names(target)

    def interrupted(signum, frame):
        raise RuntimeError('INTERRUPTED')

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    if args.apply:
        promote(target, secret)
    elif args.verify:
        verify(target, secret)
        print('DIRECT_XHTTP_VERIFY_OK=1')
    else:
        verify(target, secret, selected=True)
        print('DIRECT_XHTTP_SELECTED_VERIFY_OK=1')


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        print('ERROR=' + str(error), file=sys.stderr)
        raise
