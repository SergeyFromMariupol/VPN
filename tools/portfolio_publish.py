#!/usr/bin/env python3
"""Publish the selected 3X-UI subscription after the baseline is accepted.

Only managed subscription rows, baseline client/inbound joins and native
subscription visibility flags are changed. Credentials and links travel through private files and worker
stdin; command output contains counts and fixed error codes only.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import closing
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sqlite3
import ssl
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit

_CATALOG_SPEC = importlib.util.spec_from_file_location(
    'vpn_publication_catalog', Path(__file__).resolve().parents[1] /
    'bundle/portfolio/portfolio_catalog.py')
_CATALOG = importlib.util.module_from_spec(_CATALOG_SPEC)
_CATALOG_SPEC.loader.exec_module(_CATALOG)
select_profiles = _CATALOG.select_profiles


DB = Path('/etc/x-ui/x-ui.db')
XRAY_RUNTIME = Path('/usr/local/x-ui/bin/config.json')
TARGET = Path('/etc/germanyvpn-target.env')
ACCESS = Path('/etc/krysyuk-standalone/access.env')
EXTRAS = Path('/etc/germanyvpn-portfolio/links.json')
STATE = Path('/var/lib/vpn-installer/portfolio-publication.json')
BACKUPS = Path('/var/backups/vpn-portfolio-publication')
LOCK = Path('/run/vpn-portfolio-publication.lock')
OWNER_EMAIL = 'germany-warp-reality'
UAS = ('v2RayTun', 'Happ', 'Karing')
MAX_FEED = 2 * 1024 * 1024
STABLE_EXTERNAL = ('id', 'client_id', 'kind', 'value', 'remark', 'enable',
                   'expiry_time', 'name_prefix', 'sort_index', 'created_at')
SAFE_ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'LC_ALL': 'C', 'LANG': 'C', 'LANGUAGE': 'C'}


WORKER = r'''
import json, os, sqlite3, sys
from contextlib import closing
os.umask(0o077)
DB='/etc/x-ui/x-ui.db'
EXT=('id','client_id','kind','value','remark','enable','expiry_time',
     'name_prefix','sort_index','created_at')
def stable(db):
 db.row_factory=sqlite3.Row
 joins=[dict(r) for r in db.execute('SELECT * FROM client_inbounds ORDER BY client_id,inbound_id')]
 external=[dict(r) for r in db.execute(
   'SELECT '+','.join(EXT)+' FROM client_external_links ORDER BY sort_index,id')]
 return {'joins':joins,'external':external}
def full(db,table):
 db.row_factory=sqlite3.Row
 return [dict(r) for r in db.execute('SELECT * FROM '+table+' ORDER BY id')]
def insert(db,table,row):
 columns=list(row)
 db.execute('INSERT INTO '+table+' ('+','.join(columns)+') VALUES ('+
            ','.join('?' for _ in columns)+')',[row[key] for key in columns])
def check(db):
 assert db.execute('PRAGMA quick_check').fetchone()[0]=='ok'
def visibility(db):
 db.row_factory=sqlite3.Row
 columns={r['name'] for r in db.execute('PRAGMA table_info(inbounds)')}
 assert {'id','port','protocol','enable','exclude_from_sub'} <= columns
 return [dict(r) for r in db.execute(
  'SELECT id,port,protocol,enable,exclude_from_sub FROM inbounds ORDER BY id')]
op=sys.argv[1]
if op in ('read','backup','visibility'):
 with closing(sqlite3.connect('file:'+DB+'?mode=ro',uri=True,timeout=20)) as db:
  check(db)
  if op=='visibility':
   sys.stdout.buffer.write(json.dumps(visibility(db),separators=(',',':')).encode('utf-8'))
  elif op=='backup':
   with closing(sqlite3.connect(':memory:')) as copy:
    db.backup(copy)
    check(copy)
    sys.stdout.buffer.write(copy.serialize())
  else:
   data=stable(db)
   data['clients']=[dict(r) for r in db.execute('SELECT id,email FROM clients ORDER BY id')]
   sys.stdout.buffer.write(json.dumps(data,ensure_ascii=False,separators=(',',':')).encode('utf-8'))
else:
 p=json.loads(sys.stdin.buffer.read().decode('utf-8'))
 with closing(sqlite3.connect(DB,timeout=30)) as db:
  db.execute('BEGIN IMMEDIATE')
  check(db)
  assert stable(db)==p['expected']
  if 'expected_visibility' in p:
   assert visibility(db)==p['expected_visibility']
  if op=='apply':
   for item in p['delete_joins']:
    assert db.execute('DELETE FROM client_inbounds WHERE client_id=? AND inbound_id=?',
                      (item['client_id'],item['inbound_id'])).rowcount==1
   for item in p['delete_external']:
    assert db.execute('DELETE FROM client_external_links WHERE id=?',(item,)).rowcount==1
   for row in p['insert_external']:
    insert(db,'client_external_links',row)
  elif op=='restore':
   for item in p['inserted_external_ids']:
    assert db.execute('DELETE FROM client_external_links WHERE id=?',(item,)).rowcount==1
   for row in p['restore_external']:
    insert(db,'client_external_links',row)
   for row in p['restore_joins']:
    insert(db,'client_inbounds',row)
  else:
   raise ValueError('OP')
  for item in p.get('update_sorts',[]):
   before,after=item['before'],item['after']
   expected,wanted=(after,before) if op=='restore' else (before,after)
   assert db.execute('UPDATE client_external_links SET sort_index=? WHERE id=? AND sort_index=?',
                     (wanted,item['id'],expected)).rowcount==1
  for item in p.get('update_visibility',[]):
   before,after=item['before'],item['after']
   expected,wanted=(after,before) if op=='restore' else (before,after)
   assert db.execute('UPDATE inbounds SET exclude_from_sub=? WHERE id=? AND exclude_from_sub=?',
                     (wanted,item['id'],expected)).rowcount==1
  assert stable(db)==p['intended']
  if 'intended_visibility' in p:
   assert visibility(db)==p['intended_visibility']
  check(db)
  db.commit()
  check(db)
 sys.stdout.write('OK')
'''


def need(condition, code):
    if not condition:
        raise RuntimeError(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_dir(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
         stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_DIRECTORY')


def private(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == 0o600, 'PRIVATE_FILE')
    return path.read_bytes()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_atomic(path, raw):
    private_dir(path.parent)
    stage = path.parent / ('.' + path.name + '.' + secrets.token_hex(8))
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(stage, path)
        sync_dir(path.parent)
    finally:
        if stage.exists():
            stage.unlink()


def read_env(path, shell_quoted=False):
    result = {}
    for line in private(path).decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        need(separator and re.fullmatch(r'[A-Z][A-Z0-9_]*', key) and key not in result,
             'ENV_SHAPE')
        if shell_quoted:
            if value:
                values = shlex.split(value)
                need(len(values) == 1, 'ENV_VALUE')
                value = values[0]
        result[key] = value
    return result


def target_and_access():
    target = read_env(TARGET, shell_quoted=True)
    target.setdefault('TARGET_TLS_MODE', 'letsencrypt')
    target.setdefault('TARGET_EGRESS_MODE', 'both')
    target.setdefault('TARGET_PROFILE_SET', 'basic')
    target.setdefault('TARGET_PROFILE_IDS', '')
    target.setdefault('TARGET_PROFILE_ORDER', 'legacy')
    need(target['TARGET_TLS_MODE'] in ('letsencrypt', 'none') and
         target['TARGET_EGRESS_MODE'] in ('warp', 'direct', 'both') and
         target['TARGET_PROFILE_SET'] in ('basic', 'dpi', 'all', 'custom') and
         target['TARGET_PROFILE_ORDER'] in ('legacy', 'priority') and
         bool(target['TARGET_PROFILE_IDS']) == (target['TARGET_PROFILE_SET'] == 'custom') and
         (target['TARGET_TLS_MODE'] == 'letsencrypt' or
          target['TARGET_PROFILE_SET'] == 'basic'), 'TARGET_SELECTION')
    address = str(ipaddress.IPv4Address(target['TARGET_IPV4']))
    need(ipaddress.IPv4Address(address).is_global, 'TARGET_IPV4')
    access = read_env(ACCESS)
    url = urlsplit(access['SUBSCRIPTION_URL'])
    scheme = 'https' if target['TARGET_TLS_MODE'] == 'letsencrypt' else 'http'
    need(url.scheme == scheme and url.hostname == target['TARGET_FQDN'] and
         url.port == 2096 and url.username is None and url.password is None and
         not url.query and not url.fragment and
         re.fullmatch(r'/[A-Za-z0-9_-]{16,128}/[a-f0-9]{64}', url.path),
         'SUBSCRIPTION_URL_SHAPE')
    return target, url


def db_worker(op, payload=None, timeout=90):
    import pwd
    need(DB.is_file() and not DB.is_symlink() and
         DB.stat().st_uid == pwd.getpwnam('xui').pw_uid and
         stat.S_IMODE(DB.stat().st_mode) == 0o600,
         'DATABASE_OWNERSHIP')
    result = subprocess.run(['runuser', '-u', 'xui', '--', 'python3', '-I', '-B',
                             '-c', WORKER, op],
                            input=None if payload is None else canonical(payload),
                            capture_output=True, timeout=timeout, env=SAFE_ENV)
    need(result.returncode == 0, 'DATABASE_WORKER')
    return result.stdout


def db_read():
    data = json.loads(db_worker('read'))
    need(set(data) == {'joins', 'external', 'clients'}, 'DATABASE_READ')
    return data


def db_visibility():
    data = json.loads(db_worker('visibility'))
    need(isinstance(data, list) and all(
        isinstance(row, dict) and set(row) == {'id', 'port', 'protocol', 'enable', 'exclude_from_sub'}
        and type(row['id']) is int and type(row['port']) is int
        and row['enable'] in (0, 1) and row['exclude_from_sub'] in (0, 1)
        for row in data), 'DATABASE_VISIBILITY')
    return data


def visibility_payload(state, restore=False):
    if 'visibility_before' not in state:
        need('visibility_after' not in state and 'update_visibility' not in state,
             'VISIBILITY_JOURNAL')
        return {}
    return {'expected_visibility': state['visibility_after'] if restore else state['visibility_before'],
            'intended_visibility': state['visibility_before'] if restore else state['visibility_after'],
            'update_visibility': state['update_visibility']}


def verify_visibility(state, stage):
    if 'visibility_before' in state:
        need(db_visibility() == state['visibility_' + stage], 'PUBLISHED_VISIBILITY')


def restart_xui(target):
    result = subprocess.run(['systemctl', 'restart', 'x-ui.service'],
                            capture_output=True, timeout=90, env=SAFE_ENV)
    need(result.returncode == 0, 'XUI_RESTART')
    for _ in range(30):
        active = subprocess.run(['systemctl', 'is-active', '--quiet', 'x-ui.service'],
                                capture_output=True, timeout=10, env=SAFE_ENV)
        if active.returncode == 0:
            try:
                with socket.create_connection((target['TARGET_IPV4'], 2096), timeout=2):
                    return
            except OSError:
                pass
        time.sleep(1)
    raise RuntimeError('XUI_NOT_READY')


def feed_one(url, agent):
    connection = (http.client.HTTPSConnection(url.hostname, url.port,
                   context=ssl.create_default_context(), timeout=25)
                  if url.scheme == 'https' else
                  http.client.HTTPConnection(url.hostname, url.port, timeout=25))
    try:
        connection.request('GET', url.path, headers={'User-Agent': agent,
                                                      'Cache-Control': 'no-cache'})
        response = connection.getresponse()
        raw = response.read(MAX_FEED + 1)
        if response.status in (502, 503, 504):
            raise RuntimeError('PUBLIC_TRANSIENT_HTTP')
        need(response.status == 200 and 0 < len(raw) <= MAX_FEED, 'PUBLIC_HTTP')
    finally:
        connection.close()
    body = raw.strip().decode('utf-8', 'strict')
    if '://' not in body:
        body = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)).decode('utf-8')
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    need(len(lines) == len(set(lines)), 'PUBLIC_DUPLICATE')
    return lines


def feeds(url, ready_timeout=0):
    deadline = time.monotonic() + ready_timeout
    while True:
        try:
            result = [feed_one(url, agent) for agent in UAS]
            need(all(item == result[0] for item in result[1:]),
                 'PUBLIC_UA_DIFFERENCE')
            return result[0]
        except (OSError, http.client.HTTPException) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError('PUBLIC_NETWORK') from error
        except RuntimeError as error:
            if str(error) != 'PUBLIC_TRANSIENT_HTTP' or time.monotonic() >= deadline:
                raise
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def verify_native_runtime(target, mode=None):
    """Read back native credentials after x-ui has rebuilt Xray from the joins."""
    selected_clients = None
    if mode is None and target['TARGET_PROFILE_SET'] == 'custom':
        names = {row['name'] for row in custom_rows(target) if row['baseline_reuse']}
        selected_clients = {email for email, name in baseline_client_names(target).items()
                            if name in names}
    mode = mode or target['TARGET_EGRESS_MODE']
    need(mode in ('warp', 'direct', 'both'), 'RUNTIME_EGRESS')
    raw = XRAY_RUNTIME.read_bytes()
    need(len(raw) <= 4 * 1024 * 1024, 'RUNTIME_SIZE')
    config = json.loads(raw)
    inbounds = {item.get('tag'): item for item in config['inbounds']
                if item.get('tag') in ('in-443-tcp', 'in-443-udp')}
    expected_tags = {'in-443-tcp'}
    if target['TARGET_TLS_MODE'] == 'letsencrypt':
        expected_tags.add('in-443-udp')
    need(set(inbounds) == expected_tags, 'RUNTIME_INBOUNDS')
    roles = (('warp', 'direct') if mode == 'both' else (mode,))
    for tag, suffix in (('in-443-tcp', 'reality'),
                        ('in-443-udp', 'hysteria2')):
        if tag not in expected_tags:
            continue
        inbound = inbounds[tag]
        actual = [client['email'] for client in inbound['settings']['clients']]
        expected = [('germany-warp-' + suffix if role == 'warp' else
                     'germany-' + suffix) for role in roles]
        if selected_clients is not None:
            expected = [email for email in expected if email in selected_clients]
        need(len(actual) == len(set(actual)) and set(actual) == set(expected),
             'RUNTIME_CLIENTS')
        if selected_clients is not None and suffix == 'hysteria2' and not expected:
            # Xray can fall back to transport-level auth with an empty user list.
            hysteria = inbound.get('streamSettings', {}).get('hysteriaSettings', {})
            need(not hysteria.get('auth'), 'RUNTIME_HYSTERIA_AUTH')


def wait_native_runtime(target, mode=None):
    deadline = time.monotonic() + 30
    while True:
        try:
            verify_native_runtime(target, mode=mode)
            return
        except (OSError, ValueError, KeyError, RuntimeError) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError('RUNTIME_READBACK') from error
            time.sleep(1)


def uri_name(uri):
    if uri.startswith('vmess://'):
        payload = uri.removeprefix('vmess://')
        data = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        return data['ps']
    return unquote(urlsplit(uri).fragment)


def uri_signature(uri):
    """Ignore only 3X-UI's documented remark re-encoding on external links."""
    if uri.startswith('vmess://'):
        payload = uri.removeprefix('vmess://')
        decoded = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        need(isinstance(decoded, dict), 'URI_VMESS_SHAPE')
        return {'kind': 'vmess', 'value': decoded}
    parsed = urlsplit(uri)
    need(parsed.scheme in ('vless', 'trojan', 'hysteria2', 'hy2'), 'URI_SCHEME')
    return {'kind': parsed.scheme, 'head': parsed._replace(fragment='').geturl(),
            'name': unquote(parsed.fragment)}


def baseline_client_names(target):
    protocols = ('REALITY', 'HYSTERIA2', 'XHTTP') if target['TARGET_TLS_MODE'] == 'letsencrypt' else ('REALITY', 'XHTTP')
    label = target['TARGET_LABEL']
    clients = {}
    if target['TARGET_EGRESS_MODE'] != 'direct':
        clients.update((f'germany-warp-{protocol.lower()}', f'{label} · ☁️ Cloudflare · {protocol}')
                       for protocol in protocols)
    clients.update((f'germany-{protocol.lower()}', f'{label} · 🖥️ IP сервера · {protocol}')
                   for protocol in protocols)
    return clients


def baseline_names(target):
    return list(baseline_client_names(target).values())


def baseline_db(data, target):
    protocols = ('reality', 'hysteria2', 'xhttp') if target['TARGET_TLS_MODE'] == 'letsencrypt' else ('reality', 'xhttp')
    direct_only = target['TARGET_EGRESS_MODE'] == 'direct'
    emails = set(baseline_client_names(target))
    clients = data['clients']
    need(len(clients) == len(emails) and len({row['email'] for row in clients}) == len(emails) and
         {row['email'] for row in clients} == emails, 'BASE_CLIENTS')
    owner_email = 'germany-reality' if direct_only else OWNER_EMAIL
    owners = [row['id'] for row in clients if row['email'] == owner_email]
    need(len(owners) == 1, 'BASE_OWNER')
    owner = owners[0]
    by_id = {row['id']: row['email'] for row in clients}
    joins = data['joins']
    need(len(joins) == len(emails) and all('client_id' in row and 'inbound_id' in row and
         row['client_id'] in by_id for row in joins) and
         {by_id[row['client_id']] for row in joins} == emails, 'BASE_JOINS')
    if direct_only:
        expected_external = [(0, target['TARGET_LABEL'] + ' · 🖥️ IP сервера · XHTTP')]
    else:
        expected_external = [(-1, target['TARGET_LABEL'] + ' · ☁️ Cloudflare · XHTTP')]
        expected_external.extend((index, target['TARGET_LABEL'] + ' · 🖥️ IP сервера · ' + protocol)
                                 for index, protocol in enumerate(protocol.upper() for protocol in protocols))
    external = data['external']
    need(len(external) == len(expected_external), 'BASE_EXTERNAL_COUNT')
    for row, (sort_index, remark) in zip(external, expected_external):
        need(set(row) == set(STABLE_EXTERNAL) and row['client_id'] == owner and
             row['sort_index'] == sort_index and row['remark'] == remark and
             row['kind'] == 'link' and row['enable'] == 1 and
             row['expiry_time'] == 0 and row['name_prefix'] == '',
             'BASE_EXTERNAL_SHAPE')
    return owner, by_id


def custom_rows(target):
    return select_profiles('custom', target['TARGET_EGRESS_MODE'], target['TARGET_LABEL'],
                           target['TARGET_PROFILE_IDS'],
                           profile_order=target.get('TARGET_PROFILE_ORDER', 'legacy'))


def priority_rows(target):
    rows = select_profiles(target['TARGET_PROFILE_SET'], target['TARGET_EGRESS_MODE'],
                           target['TARGET_LABEL'], target.get('TARGET_PROFILE_IDS', ''),
                           profile_order='priority')
    if target['TARGET_TLS_MODE'] == 'none':
        rows = [row for row in rows if row['protocol'] != 'hysteria2']
    return rows


def selected_recipe(target):
    mode = target['TARGET_EGRESS_MODE']
    profile_set = target['TARGET_PROFILE_SET']
    if target['TARGET_TLS_MODE'] == 'none':
        need(profile_set == 'basic', 'CERTLESS_PORTFOLIO')
        return []
    if profile_set == 'custom':
        return [row for row in custom_rows(target) if not row['baseline_reuse']]
    rows = select_profiles(profile_set, mode, target['TARGET_LABEL'],
                           profile_order=target.get('TARGET_PROFILE_ORDER', 'legacy'))
    expected = {'basic': 3, 'dpi': 49, 'all': 73}[profile_set]
    if mode == 'both':
        expected *= 2
    need(len(rows) == expected, 'CATALOG_SELECTED_COUNT')
    return [row for row in rows if not row['baseline_reuse']]


def read_extras(target, selected):
    if not selected:
        return [], None
    private_dir(EXTRAS.parent)
    raw = private(EXTRAS)
    need(len(raw) <= MAX_FEED, 'EXTRA_MANIFEST_SIZE')
    manifest = json.loads(raw)
    need(set(manifest) == {'version', 'target', 'entries'} and
         manifest['version'] == 1 and manifest['target'] == target['TARGET_IPV4'] and
         isinstance(manifest['entries'], list) and len(manifest['entries']) == len(selected),
         'EXTRA_MANIFEST')
    for entry, recipe in zip(manifest['entries'], selected):
        need(set(entry) == {'id', 'remark', 'uri', 'port', 'egress'} and
             entry['id'] == recipe['id'] and entry['remark'] == recipe['name'] and
             entry['egress'] == ('WARP_CF' if recipe['egress'] == 'warp' else 'DIRECT') and
             isinstance(entry['port'], int) and entry['port'] == 30000 + recipe['port_offset'] and
             isinstance(entry['uri'], str) and 0 < len(entry['uri']) <= 4096 and
             not any(char in entry['uri'] for char in '\r\n'), 'EXTRA_ENTRY')
        uri = entry['uri']
        if uri.startswith('vmess://'):
            need(recipe['protocol'] == 'vmess', 'EXTRA_SCHEME')
            payload = uri.removeprefix('vmess://')
            decoded = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
            need(decoded.get('add') == target['TARGET_FQDN'] and
                 str(decoded.get('port')) == str(entry['port']) and
                 decoded.get('ps') == entry['remark'], 'EXTRA_URI')
        else:
            parsed = urlsplit(uri)
            need(parsed.scheme == recipe['protocol'] and
                 parsed.hostname == target['TARGET_FQDN'] and
                 parsed.port == entry['port'] and
                 unquote(parsed.fragment) == entry['remark'], 'EXTRA_URI')
    need(len({entry['uri'] for entry in manifest['entries']}) == len(selected), 'EXTRA_DUPLICATE')
    return manifest['entries'], digest(raw)


def priority_plan(data, target, extras, initial, owner, by_id):
    """Publish every selected link externally while keeping its runtime identity.

    Native inbounds remain operational; only their subscription export is hidden.
    Captured native links and retained external links are never regenerated.
    """
    rows = priority_rows(target)
    recipes = [row for row in rows if not row['baseline_reuse']]
    need([entry['id'] for entry in extras] == [row['id'] for row in recipes] and
         [entry['remark'] for entry in extras] == [row['name'] for row in recipes],
         'PRIORITY_PUBLIC_ORDER')
    before_visibility = data.get('visibility')
    need(isinstance(before_visibility, list), 'BASE_VISIBILITY_MISSING')
    expected = {(443, 'vless', 1), (8443, 'vless', 0)}
    if target['TARGET_TLS_MODE'] == 'letsencrypt':
        expected.add((443, 'hysteria', 1))
    need(len(before_visibility) == len(expected) and
         len({row['id'] for row in before_visibility}) == len(expected) and
         {(row['port'], row['protocol'], row['enable']) for row in before_visibility} == expected and
         all(type(row['id']) is int and row['id'] > 0 and row['exclude_from_sub'] == 0
             for row in before_visibility), 'BASE_VISIBILITY_SHAPE')
    update_visibility = [{'id': row['id'], 'before': 0, 'after': 1}
                         for row in before_visibility if row['port'] == 443]
    hidden = {row['id'] for row in update_visibility}
    after_visibility = [{**row, 'exclude_from_sub': 1 if row['id'] in hidden else 0}
                        for row in before_visibility]
    selected_names = [row['name'] for row in rows]
    selected_baseline = {row['name'] for row in rows if row['baseline_reuse']}
    baseline_by_name = dict(zip(baseline_names(target), initial, strict=True))
    extra_by_id = {entry['id']: entry for entry in extras}
    selected_uris = [baseline_by_name[row['name']] if row['baseline_reuse'] else
                     extra_by_id[row['id']]['uri'] for row in rows]
    need(len(selected_uris) == len(set(selected_uris)) and
         len(selected_names) == len(set(selected_names)), 'SELECTED_DUPLICATE')
    clients = baseline_client_names(target)
    delete_joins = [{'client_id': row['client_id'], 'inbound_id': row['inbound_id']}
                    for row in data['joins']
                    if clients[by_id[row['client_id']]] not in selected_baseline]
    delete_external = [row['id'] for row in data['external']
                       if row['remark'] not in selected_baseline]
    retained = {row['remark']: row for row in data['external']
                if row['id'] not in delete_external}
    positions = {name: index for index, name in enumerate(selected_names)}
    update_sorts = [{'id': row['id'], 'before': row['sort_index'],
                     'after': positions[row['remark']]}
                    for row in retained.values() if row['sort_index'] != positions[row['remark']]]
    new_links = [(row['name'], uri) for row, uri in zip(rows, selected_uris, strict=True)
                 if row['name'] not in retained]
    max_id = max(row['id'] for row in data['external'])
    now = int(time.time() * 1000)
    insert_external = [
        {'id': max_id + index + 1, 'client_id': owner, 'kind': 'link',
         'value': uri, 'remark': name, 'enable': 1, 'expiry_time': 0,
         'name_prefix': '', 'sort_index': positions[name], 'created_at': now + index,
         'last_fetch_at': 0, 'last_fetch_error': ''}
        for index, (name, uri) in enumerate(new_links)]
    after = {
        'joins': [row for row in data['joins']
                  if {'client_id': row['client_id'], 'inbound_id': row['inbound_id']} not in delete_joins],
        'external': sorted(
            [{**row, 'sort_index': positions[row['remark']]} for row in retained.values()] +
            [{key: row[key] for key in STABLE_EXTERNAL} for row in insert_external],
            key=lambda row: (row['sort_index'], row['id']))}
    need([row['remark'] for row in after['external']] == selected_names,
         'PRIORITY_EXTERNAL_ORDER')
    return {'before': {'joins': data['joins'], 'external': data['external']},
            'after': after, 'delete_joins': delete_joins, 'delete_external': delete_external,
            'insert_external': insert_external, 'update_sorts': update_sorts,
            'visibility_before': before_visibility, 'visibility_after': after_visibility,
            'update_visibility': update_visibility,
            'uri_hashes': [digest(canonical(uri_signature(uri))) for uri in selected_uris],
            'names': selected_names}


def plan(data, target, extras, initial):
    owner, by_id = baseline_db(data, target)
    baseline_clients = baseline_client_names(target)
    names = list(baseline_clients.values())
    need(len(initial) == len(names) and [uri_name(uri) for uri in initial] == names,
         'BASE_PUBLIC_ORDER')
    if target.get('TARGET_PROFILE_ORDER', 'legacy') == 'priority':
        return priority_plan(data, target, extras, initial, owner, by_id)
    mode = target['TARGET_EGRESS_MODE']
    custom = target['TARGET_PROFILE_SET'] == 'custom'
    if custom:
        rows = custom_rows(target)
        selected_baseline = {row['name'] for row in rows if row['baseline_reuse']}
    else:
        selected_baseline = set(names[:len(names) // 2] if mode == 'warp' else names)
    baseline = [uri for name, uri in zip(names, initial, strict=True) if name in selected_baseline]
    selected_names = [uri_name(uri) for uri in baseline] + [entry['remark'] for entry in extras]
    selected_uris = baseline + [entry['uri'] for entry in extras]
    reorder_external = False
    if custom:
        recipes = [row for row in rows if not row['baseline_reuse']]
        need([entry['id'] for entry in extras] == [row['id'] for row in recipes] and
             [entry['remark'] for entry in extras] == [row['name'] for row in recipes],
             'CUSTOM_PUBLIC_ORDER')
        intended_names = [row['name'] for row in rows]
        reorder_external = intended_names != selected_names
        if reorder_external:
            # 3X-UI emits native links before all external links. The selector
            # retains the established order whenever native links are selected;
            # only an entirely external selection can be reordered here.
            external_names = {entry['remark'] for entry in data['external']}
            need(selected_baseline <= external_names, 'CUSTOM_NATIVE_ORDER')
            baseline_by_name = dict(zip(names, initial, strict=True))
            extras_by_id = {entry['id']: entry['uri'] for entry in extras}
            selected_uris = [baseline_by_name[row['name']] if row['baseline_reuse'] else
                             extras_by_id[row['id']] for row in rows]
        selected_names = intended_names
    need(len(selected_uris) == len(set(selected_uris)) and
         len(selected_names) == len(set(selected_names)), 'SELECTED_DUPLICATE')
    delete_joins = [
        {'client_id': row['client_id'], 'inbound_id': row['inbound_id']}
        for row in data['joins']
        if baseline_clients[by_id[row['client_id']]] not in selected_baseline]
    delete_external = [row['id'] for row in data['external']
                       if row['remark'] not in selected_baseline]
    max_id = max(row['id'] for row in data['external'])
    now = int(time.time() * 1000)
    positions = {name: index for index, name in enumerate(selected_names)}
    update_sorts = [{'id': row['id'], 'before': row['sort_index'], 'after': positions[row['remark']]}
                    for row in data['external'] if reorder_external and
                    row['id'] not in set(delete_external) and row['sort_index'] != positions[row['remark']]]
    changed_sorts = {row['id']: row['after'] for row in update_sorts}
    insert_external = [
        {'id': max_id + index + 1, 'client_id': owner, 'kind': 'link',
         'value': entry['uri'], 'remark': entry['remark'], 'enable': 1,
         'expiry_time': 0, 'name_prefix': '',
         'sort_index': positions[entry['remark']] if reorder_external else 3 + index,
         'created_at': now + index, 'last_fetch_at': 0, 'last_fetch_error': ''}
        for index, entry in enumerate(extras)]
    after = {
        'joins': [row for row in data['joins']
                  if {'client_id': row['client_id'], 'inbound_id': row['inbound_id']} not in delete_joins],
        'external': sorted([{**row, 'sort_index': changed_sorts.get(row['id'], row['sort_index'])}
                            for row in data['external'] if row['id'] not in set(delete_external)] +
                           [{key: row[key] for key in STABLE_EXTERNAL} for row in insert_external],
                           key=lambda row: (row['sort_index'], row['id']))}
    if reorder_external:
        need([entry['remark'] for entry in after['external']] == selected_names,
             'CUSTOM_EXTERNAL_ORDER')
    result = {'before': {'joins': data['joins'], 'external': data['external']},
              'after': after, 'delete_joins': delete_joins,
              'delete_external': delete_external, 'insert_external': insert_external,
              'uri_hashes': [digest(canonical(uri_signature(uri))) for uri in selected_uris],
              'names': selected_names}
    # Omit the optional field for existing plans and journals whose sort order
    # does not change; recovery accepts both the old and the extended shape.
    if update_sorts:
        result['update_sorts'] = update_sorts
    return result


def snapshot():
    if not BACKUPS.exists():
        BACKUPS.mkdir(mode=0o700, parents=True)
    private_dir(BACKUPS)
    path = BACKUPS / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) +
                      '-' + secrets.token_hex(6))
    path.mkdir(mode=0o700)
    raw = db_worker('backup')
    need(0 < len(raw) <= 64 * 1024 * 1024, 'SNAPSHOT_SIZE')
    database = path / 'x-ui.db'
    write_atomic(database, raw)
    with closing(sqlite3.connect('file:' + str(database) + '?mode=ro&immutable=1', uri=True)) as copy:
        need(copy.execute('PRAGMA quick_check').fetchone() == ('ok',), 'SNAPSHOT_INTEGRITY')
    return path, digest(raw)


def backup_rows(state):
    path = Path(state['backup'])
    need(path.parent == BACKUPS and re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}', path.name),
         'SNAPSHOT_PATH')
    private_dir(path)
    raw = private(path / 'x-ui.db')
    need(digest(raw) == state['backup_sha256'], 'SNAPSHOT_DIGEST')
    with closing(sqlite3.connect('file:' + str(path / 'x-ui.db') + '?mode=ro&immutable=1', uri=True)) as copy:
        copy.row_factory = sqlite3.Row
        need(copy.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'SNAPSHOT_INTEGRITY')
        joins = [dict(row) for row in copy.execute('SELECT * FROM client_inbounds ORDER BY client_id,inbound_id')]
        external = [dict(row) for row in copy.execute('SELECT * FROM client_external_links ORDER BY id')]
        if 'visibility_before' in state:
            visibility = [dict(row) for row in copy.execute(
                'SELECT id,port,protocol,enable,exclude_from_sub FROM inbounds ORDER BY id')]
            need(visibility == state['visibility_before'], 'SNAPSHOT_VISIBILITY')
    stable_ext = [{key: row[key] for key in STABLE_EXTERNAL} for row in external]
    stable_ext.sort(key=lambda row: (row['sort_index'], row['id']))
    need({'joins': joins, 'external': stable_ext} == state['before'], 'SNAPSHOT_BASELINE')
    return joins, external


def state_read():
    private_dir(STATE.parent)
    if not STATE.exists():
        need(not STATE.is_symlink(), 'STATE_PATH')
        return None
    raw = private(STATE)
    data = json.loads(raw)
    need(raw == canonical(data) and data.get('version') == 1 and
         data.get('status') in ('prepared', 'committed', 'rolled_back'), 'STATE_SHAPE')
    return data


def state_write(data):
    write_atomic(STATE, canonical(data))


def state_matches_target(state, target):
    return (state.get('target') == target['TARGET_IPV4'] and
            state.get('egress') == target['TARGET_EGRESS_MODE'] and
            state.get('profile_set') == target['TARGET_PROFILE_SET'] and
            state.get('profile_order', 'legacy') == target.get('TARGET_PROFILE_ORDER', 'legacy') and
            state.get('profile_ids', '') == target.get('TARGET_PROFILE_IDS', ''))


def verify_public(state, target, url):
    if target.get('TARGET_PROFILE_ORDER', 'legacy') == 'priority':
        need(state['names'] == [row['name'] for row in priority_rows(target)], 'PUBLISHED_SELECTION')
        need('visibility_before' in state, 'PUBLISHED_VISIBILITY_JOURNAL')
    elif target['TARGET_PROFILE_SET'] == 'custom':
        need(state['names'] == [row['name'] for row in custom_rows(target)], 'PUBLISHED_SELECTION')
    current = db_read()
    need({'joins': current['joins'], 'external': current['external']} == state['after'],
         'PUBLISHED_DATABASE')
    verify_visibility(state, 'after')
    wait_native_runtime(target)
    if state['manifest_sha256'] is not None:
        private_dir(EXTRAS.parent)
        need(digest(private(EXTRAS)) == state['manifest_sha256'], 'PUBLISHED_MANIFEST')
    lines = feeds(url, ready_timeout=40)
    need(len(lines) == len(state['names']) and
         [uri_name(uri) for uri in lines] == state['names'] and
         [digest(canonical(uri_signature(uri))) for uri in lines] == state['uri_hashes'],
         'PUBLISHED_FEED')
    need(len(lines) == len(set(lines)), 'PUBLISHED_DUPLICATE')


def restore_prepared(state, target):
    baseline_mode = 'direct' if target['TARGET_EGRESS_MODE'] == 'direct' else 'both'
    current = db_read()
    present = {'joins': current['joins'], 'external': current['external']}
    if present == state['before']:
        verify_visibility(state, 'before')
        restart_xui(target)
        wait_native_runtime(target, mode=baseline_mode)
        state_write({**state, 'status': 'rolled_back'})
        return
    need(present == state['after'], 'RECOVERY_FOREIGN_DRIFT')
    verify_visibility(state, 'after')
    joins, external = backup_rows(state)
    restore_joins = [row for row in joins
                     if {'client_id': row['client_id'], 'inbound_id': row['inbound_id']}
                     in state['delete_joins']]
    restore_external = [row for row in external if row['id'] in set(state['delete_external'])]
    payload = {'expected': state['after'], 'intended': state['before'],
               'inserted_external_ids': [row['id'] for row in state['insert_external']],
               'restore_joins': restore_joins, 'restore_external': restore_external,
               'update_sorts': state.get('update_sorts', []),
               **visibility_payload(state, restore=True)}
    need(db_worker('restore', payload) == b'OK', 'ROLLBACK_WORKER')
    restart_xui(target)
    wait_native_runtime(target, mode=baseline_mode)
    current = db_read()
    need({'joins': current['joins'], 'external': current['external']} == state['before'],
         'ROLLBACK_READBACK')
    verify_visibility(state, 'before')
    state_write({**state, 'status': 'rolled_back'})


def apply(target, url):
    old = state_read()
    if old is not None:
        need(state_matches_target(old, target), 'STATE_TARGET')
        if old['status'] == 'committed':
            verify_public(old, target, url)
            print('PORTFOLIO_SUBSCRIPTION_OK=' + str(len(old['names'])))
            return
        if old['status'] == 'prepared':
            restore_prepared(old, target)
    data = db_read()
    if target.get('TARGET_PROFILE_ORDER', 'legacy') == 'priority':
        data['visibility'] = db_visibility()
    baseline_db(data, target)
    initial = feeds(url)
    recipes = selected_recipe(target)
    extras, manifest_sha = read_extras(target, recipes)
    intent = plan(data, target, extras, initial)
    backup, backup_sha = snapshot()
    state = {'version': 1, 'status': 'prepared', 'target': target['TARGET_IPV4'],
             'egress': target['TARGET_EGRESS_MODE'],
             'profile_set': target['TARGET_PROFILE_SET'],
             'tls': target['TARGET_TLS_MODE'],
             'manifest_sha256': manifest_sha,
             'backup': str(backup), 'backup_sha256': backup_sha, **intent}
    if target['TARGET_PROFILE_SET'] == 'custom':
        state['profile_ids'] = target['TARGET_PROFILE_IDS']
    if target.get('TARGET_PROFILE_ORDER', 'legacy') == 'priority':
        state['profile_order'] = 'priority'
    backup_rows(state)
    state_write(state)
    try:
        payload = {'expected': state['before'], 'intended': state['after'],
                   'delete_joins': state['delete_joins'],
                   'delete_external': state['delete_external'],
                   'insert_external': state['insert_external'],
                   'update_sorts': state.get('update_sorts', []),
                   **visibility_payload(state)}
        need(db_worker('apply', payload) == b'OK', 'APPLY_WORKER')
        restart_xui(target)
        verify_public(state, target, url)
        state_write({**state, 'status': 'committed'})
    except BaseException:
        try:
            restore_prepared(state, target)
        except BaseException as error:
            raise RuntimeError('ROLLBACK_REQUIRES_RECOVERY') from error
        raise
    print('PORTFOLIO_SUBSCRIPTION_OK=' + str(len(state['names'])))


def main(argv=None):
    import fcntl
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--verify', action='store_true')
    args = parser.parse_args(argv)
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    os.umask(0o077)
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        lock_info = os.fstat(fd)
        need(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == 0 and
             stat.S_IMODE(lock_info.st_mode) == 0o600, 'LOCK_OWNERSHIP')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        target, url = target_and_access()
        if args.apply:
            apply(target, url)
        else:
            state = state_read()
            need(state is not None and state['status'] == 'committed' and
                 state_matches_target(state, target), 'STATE_NOT_COMMITTED')
            verify_public(state, target, url)
            print('PORTFOLIO_SUBSCRIPTION_OK=' + str(len(state['names'])))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = str(error)
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{2,80}', code):
            code = 'PUBLICATION_FAILED'
        print('PORTFOLIO_PUBLICATION_ERROR=' + code, file=sys.stderr)
        raise SystemExit(1)
