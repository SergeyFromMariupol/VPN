#!/usr/bin/env python3
"""Change an installed REALITY mode/SNI without rotating client credentials.

The request is a bounded JSON object on stdin. All snapshots and candidate
configurations remain root-private; stdout contains fixed status codes only.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import closing
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qsl, quote, unquote, unquote_plus, urlsplit


_spec = importlib.util.spec_from_file_location(
    'management_xhttp', Path(__file__).with_name('finalize-xhttp.py'))
x = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(x)

TARGET = Path('/etc/germanyvpn-target.env')
DB = Path('/etc/x-ui/x-ui.db')
MAIN = Path('/usr/local/x-ui/bin/config.json')
PROMOTION = Path('/etc/germanyvpn-xhttp-test/promotion.json')
DIRECT = PROMOTION.with_name('config.json')
BASELINE = PROMOTION.with_name('baseline.json')
WARP = Path('/etc/germanyvpn-xhttp-warp/config.json')
PORTFOLIO = Path('/etc/germanyvpn-portfolio/config.json')
LINKS = PORTFOLIO.with_name('links.json')
PORTFOLIO_STATE = PORTFOLIO.with_name('state.json')
PUBLICATION = Path('/var/lib/vpn-installer/portfolio-publication.json')
SERVER_ENV = Path('/etc/krysyuk-standalone/server.env')
SOURCE = Path('/opt/vpn-installer')
BUNDLE = Path('/var/lib/vpn-installer/bundle')
BACKUPS = Path('/var/backups/vpn-reality-management')
PENDING = Path('/var/lib/vpn-installer/reality-management.pending')
DECOY_PATHS = tuple(map(Path, (
    '/etc/nginx/conf.d/vpn-reality-decoy.conf',
    '/etc/letsencrypt/renewal-hooks/deploy/55-vpn-reality-decoy',
    '/etc/vpn-reality-decoy/snapshot', '/etc/vpn-reality-decoy/COMMITTED')))
DECOY_DIRS = (Path('/etc/vpn-reality-decoy'), Path('/var/www/vpn-decoy'))
SAFE_ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'LC_ALL': 'C', 'LANG': 'C', 'LANGUAGE': 'C'}
FIELDS = {'inbounds': {'stream_settings'}, 'hosts': {'sni'},
          'client_external_links': {'value'}}


def need(value, code):
    if not value:
        raise RuntimeError('MANAGE_REALITY_' + code)


def request_target(current, request):
    need(isinstance(request, dict) and set(request) <= {'mode', 'sni'} and
         isinstance(request.get('mode'), str), 'REQUEST')
    intended = dict(current, TARGET_REALITY_MODE=request['mode'])
    sni = request.get('sni', '')
    need(isinstance(sni, str), 'REQUEST')
    intended['TARGET_REALITY_SNI'] = (current['TARGET_FQDN'] if
        request['mode'] == 'self-steal' and not sni else sni)
    x.reality_destination(intended)  # Explicit validation, including IP/self-steal.
    return intended


def serialize(env):
    return ''.join(f'{key}={shlex.quote(value)}\n' for key, value in env.items()
                   if key not in ('TARGET_REALITY_DEST', 'TARGET_REALITY_TARGET_SNI')).encode('utf-8')


def rewrite_uri(uri, before, after):
    """Replace only the sni value, retaining credentials and every other byte."""
    parsed = urlsplit(uri)
    if parsed.scheme not in ('vless', 'trojan'):
        return uri
    pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    values = dict(pairs)
    need(len(values) == len(pairs), 'DUPLICATE_URI_FIELD')
    if values.get('security') != 'reality':
        return uri
    need(parsed.hostname in (before['TARGET_FQDN'], before['TARGET_IPV4']) and
         values.get('sni') == before['TARGET_REALITY_SNI'], 'URI_BEFORE')
    query = parsed.query.split('&')
    indices = [i for i, part in enumerate(query) if unquote_plus(part.partition('=')[0]) == 'sni']
    need(len(indices) == 1, 'URI_SNI')
    index = indices[0]
    query[index] = query[index].partition('=')[0] + '=' + quote(after['TARGET_REALITY_SNI'], safe='')
    return parsed._replace(query='&'.join(query)).geturl()


def signature(uri):
    if uri.startswith('vmess://'):
        raw = uri[8:]
        return {'kind': 'vmess', 'value': json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))}
    parsed = urlsplit(uri)
    return {'kind': parsed.scheme, 'head': parsed._replace(fragment='').geturl(),
            'name': unquote(parsed.fragment)}


def uri_hashes(uris):
    return [x.sha(x.canonical(signature(uri))) for uri in uris]


def rewrite_stream(stream, before, after):
    result = copy.deepcopy(stream)
    if result.get('security') == 'reality':
        settings = result.get('realitySettings')
        need(x.reality_settings_match(settings, before), 'RUNTIME_BEFORE')
        settings.pop('dest', None)
        settings.update(target=x.reality_destination(after),
                        serverNames=[after['TARGET_REALITY_SNI']], xver=0)
    return result


def rewrite_config(config, before, after):
    result = copy.deepcopy(config)
    for inbound in result.get('inbounds', []):
        if 'streamSettings' in inbound:
            inbound['streamSettings'] = rewrite_stream(inbound['streamSettings'], before, after)
    return result


def db_edits(connection, before, after):
    connection.row_factory = sqlite3.Row
    need(connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'DATABASE_CHECK')
    result, ids = [], set()
    for row in connection.execute('SELECT id,node_id,stream_settings FROM inbounds ORDER BY id'):
        stream = x.strict_json(row['stream_settings'])
        if stream.get('security') != 'reality':
            continue
        need(row['node_id'] is None, 'REMOTE_INBOUND')
        changed = json.dumps(rewrite_stream(stream, before, after), ensure_ascii=False,
                             sort_keys=True, separators=(',', ':'))
        result.append(['inbounds', row['id'], 'stream_settings', row['stream_settings'], changed])
        ids.add(row['id'])
    need(bool(ids), 'NO_MANAGED_REALITY')
    for row in connection.execute('SELECT id,inbound_id,security,sni FROM hosts ORDER BY id'):
        if row['inbound_id'] in ids and row['security'] == 'reality':
            need(row['sni'] == before['TARGET_REALITY_SNI'], 'HOST_BEFORE')
            result.append(['hosts', row['id'], 'sni', row['sni'], after['TARGET_REALITY_SNI']])
    for row in connection.execute('SELECT id,kind,value FROM client_external_links ORDER BY id'):
        if row['kind'] == 'link':
            changed = rewrite_uri(row['value'], before, after)
            if changed != row['value']:
                result.append(['client_external_links', row['id'], 'value', row['value'], changed])
    return result


def edit_database(connection, edits, *, restore=False):
    for table, row, column, old, new in edits:
        need(table in FIELDS and column in FIELDS[table] and isinstance(row, int), 'DATABASE_EDIT')
        previous, intended = (new, old) if restore else (old, new)
        if restore:
            current = connection.execute(f'SELECT {column} FROM {table} WHERE id=?', (row,)).fetchone()
            if current is not None and current[0] == intended:
                continue
        changed = connection.execute(f'UPDATE {table} SET {column}=? WHERE id=? AND {column}=?',
                                     (intended, row, previous)).rowcount
        need(changed == 1, 'DATABASE_CONCURRENT_WRITE')
    need(connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'DATABASE_CHECK')


class Plan:
    def __init__(self, before, after, initial):
        self.before, self.after = before, after
        self.expected = [rewrite_uri(uri, before, after) for uri in initial]
        self.files, self.configs, self.database = {}, {}, []
        self.main = None

    def build(self, root=Path('/')):
        def path(absolute):
            return root / absolute.as_posix().lstrip('/')

        def read(absolute):
            return path(absolute).read_bytes()

        with closing(sqlite3.connect(path(DB).as_uri() + '?mode=ro', uri=True)) as connection:
            self.database = db_edits(connection, self.before, self.after)
        before_main = read(MAIN)
        self.main = x.canonical(rewrite_config(x.strict_json(before_main), self.before, self.after))
        self.configs[MAIN] = self.main
        marker = x.strict_json(read(PROMOTION))
        need(marker.get('status') == 'committed' and marker.get('version') in (2, 3) and
             marker.get('target') == self.before['TARGET_IPV4'], 'PROMOTION_STATE')
        publication = x.strict_json(read(PUBLICATION)) if path(PUBLICATION).exists() else None
        original_main_hash = x.sha(x.canonical(x.strict_json(before_main)))
        if marker['main_runtime_sha256'] == original_main_hash:
            marker['main_runtime_sha256'] = x.sha(self.main)
        else:
            # Selected portfolios deliberately retain a historical baseline hash.
            need(publication is not None and publication.get('status') == 'committed', 'PROMOTION_MAIN_HASH')
        for config, field in ((DIRECT, 'direct_config_sha256'), (WARP, 'warp_config_sha256')):
            if config == WARP and marker['version'] == 3:
                continue
            raw = read(config)
            need(x.sha(raw) == marker[field], 'PROMOTION_HASH')
            changed = x.canonical(rewrite_config(x.strict_json(raw), self.before, self.after))
            self.files[config] = self.configs[config] = changed
            marker[field] = x.sha(changed)
        if marker['version'] == 3:
            raw = read(BASELINE)
            need(x.sha(raw) == marker['baseline_sha256'], 'BASELINE_HASH')
            baseline = x.strict_json(raw)
            baseline['links'] = [rewrite_uri(uri, self.before, self.after) for uri in baseline['links']]
            self.files[BASELINE] = x.canonical(baseline)
            marker['baseline_sha256'] = x.sha(self.files[BASELINE])
        self.files[PROMOTION] = x.canonical(marker)
        if path(PORTFOLIO_STATE).exists():
            state = x.strict_json(read(PORTFOLIO_STATE))
            need(state.get('phase') == 'committed' and state.get('target') == self.before['TARGET_IPV4'],
                 'PORTFOLIO_STATE')
            for absolute, field in ((PORTFOLIO, 'config_sha256'), (LINKS, 'links_sha256')):
                raw = read(absolute)
                need(x.sha(raw) == state[field], 'PORTFOLIO_HASH')
                data = x.strict_json(raw)
                if absolute == PORTFOLIO:
                    data = rewrite_config(data, self.before, self.after)
                else:
                    for entry in data['entries']:
                        entry['uri'] = rewrite_uri(entry['uri'], self.before, self.after)
                self.files[absolute] = x.canonical(data)
                state[field] = x.sha(self.files[absolute])
            self.configs[PORTFOLIO] = self.files[PORTFOLIO]
            self.files[PORTFOLIO_STATE] = x.canonical(state)
        if publication is not None:
            need(publication.get('status') == 'committed' and
                 publication.get('target') == self.before['TARGET_IPV4'] and
                 publication['uri_hashes'] == uri_hashes(self.expected_before()), 'PUBLICATION_STATE')
            for row in publication['after']['external']:
                if row['kind'] == 'link':
                    row['value'] = rewrite_uri(row['value'], self.before, self.after)
            publication['uri_hashes'] = uri_hashes(self.expected)
            if publication['manifest_sha256'] is not None:
                need(LINKS in self.files and publication['manifest_sha256'] == x.sha(read(LINKS)),
                     'PUBLICATION_MANIFEST')
                publication['manifest_sha256'] = x.sha(self.files[LINKS])
            self.files[PUBLICATION] = x.canonical(publication)
        self.files[TARGET] = serialize(self.after)
        return self

    def expected_before(self):
        return [rewrite_uri(uri, self.after, self.before) for uri in self.expected]


WORKER = r'''
import json,sqlite3,sys
from contextlib import closing
p=json.load(sys.stdin)
allowed={'inbounds':{'stream_settings'},'hosts':{'sni'},'client_external_links':{'value'}}
with closing(sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=rw',uri=True,timeout=20)) as db,db:
 db.execute('BEGIN IMMEDIATE')
 for table,row,column,old,new in p['edits']:
  if table not in allowed or column not in allowed[table] or not isinstance(row,int):raise RuntimeError('EDIT')
  previous,intended=(new,old) if p['restore'] else (old,new)
  if p['restore'] and db.execute(f'SELECT {column} FROM {table} WHERE id=?',(row,)).fetchone()==(intended,):continue
  if db.execute(f'UPDATE {table} SET {column}=? WHERE id=? AND {column}=?',(intended,row,previous)).rowcount!=1:raise RuntimeError('CAS')
 if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise RuntimeError('CHECK')
'''


def command(args, *, timeout=60, data=None, env=None, combined=False, step='COMMAND'):
    need(re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', step), 'COMMAND_STEP')
    failure = 'MANAGE_REALITY_' + step
    process = None
    try:
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, env=env or SAFE_ENV)
        stdout, stderr = process.communicate(input=data, timeout=timeout)
        if process.returncode:
            raise RuntimeError(failure)
        return stdout + (stderr if combined else b'')
    except BaseException as error:
        if process is not None:
            # Give a transactional shell its TERM trap before ever killing it.
            # Kill/wait the whole group, so a child cannot keep mutating after
            # the manager begins its own rollback.
            if os.name == 'posix':
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            elif process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                if os.name == 'posix':
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.communicate()
        if isinstance(error, (InterruptedError, KeyboardInterrupt, SystemExit)):
            raise
        raise RuntimeError(failure) from None


def database(edits, *, restore=False):
    command(['runuser', '-u', 'xui', '--', 'python3', '-I', '-B', '-c', WORKER],
            data=x.canonical({'edits': edits, 'restore': restore}),
            step='DATABASE_RESTORE' if restore else 'DATABASE_APPLY')


def private(path, *, root=True):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022 and
         (not root or (info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600)), 'FILE_OWNERSHIP')
    return path.read_bytes()


def atomic(path, raw, mode=0o600, uid=0, gid=0):
    fd, name = tempfile.mkstemp(prefix='.reality-management-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def file_state(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022,
         'FILE_OWNERSHIP')
    return {'data': base64.b64encode(path.read_bytes()).decode(), 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}


def directory_state(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
         'DIRECTORY_OWNERSHIP')
    return [info.st_dev, info.st_ino]


def publish(path, saved):
    if saved is None:
        path.unlink(missing_ok=True)
    else:
        atomic(path, base64.b64decode(saved['data']), saved['mode'], saved['uid'], saved['gid'])


class Journal:
    def __init__(self, directory, record):
        self.directory, self.record = directory, record

    def save(self):
        atomic(self.directory / 'journal.json', x.canonical(self.record))

    def change(self, path, raw):
        before = file_state(path)
        need(before is not None, 'MISSING_MANAGED_FILE')
        after = dict(before, data=base64.b64encode(raw).decode())
        if before == after:
            return
        self.record['files'].append([str(path), before, after])
        self.save()
        need(file_state(path) == before, 'FILE_CONCURRENT_WRITE')
        publish(path, after)

    def record_backend(self, before):
        for path, previous in before.items():
            current = file_state(path)
            if current != previous:
                self.record['files'].append([str(path), previous, current])
        self.save()

    def rollback(self):
        for raw, before, after in reversed(self.record['files']):
            path = Path(raw)
            actual = file_state(path)
            if actual == before:
                continue
            # X-UI is allowed to serialize the managed main JSON differently.
            if path == MAIN and actual is not None and after is not None:
                try:
                    logical = x.canonical(x.strict_json(base64.b64decode(actual['data'])))
                    wanted = x.canonical(x.strict_json(base64.b64decode(after['data'])))
                    if (logical == wanted and all(actual[key] == after[key] for key in ('uid', 'gid', 'mode'))):
                        actual = after
                except (ValueError, TypeError):
                    pass
            need(actual == after, 'ROLLBACK_FOREIGN_FILE')
            publish(path, before)


def running(unit):
    return subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                          capture_output=True, timeout=15, env=SAFE_ENV).returncode == 0


def quiescent(unit):
    properties = command(['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState',
                          '-p', 'MainPID', '-p', 'Job']).decode().splitlines()
    state = dict(line.split('=', 1) for line in properties if '=' in line)
    return (state.get('LoadState') == 'loaded' and state.get('MainPID') == '0' and
            state.get('ActiveState') in ('inactive', 'failed') and state.get('Job', '') in ('', '0'))


def start(units):
    for unit in units:
        command(['systemctl', 'start', unit])


def stop(units):
    for unit in reversed(units):
        command(['systemctl', 'stop', unit])


def verify_runtime(expected):
    for attempt in range(25):
        try:
            if x.canonical(x.strict_json(MAIN.read_bytes())) == expected:
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.2)
    need(False, 'LIVE_RUNTIME_READBACK')


def snapshot(plan, units):
    BACKUPS.mkdir(mode=0o700, exist_ok=True)
    info = BACKUPS.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
         'SNAPSHOT_DIRECTORY')
    directory = Path(tempfile.mkdtemp(prefix='change-', dir=BACKUPS))
    os.chmod(directory, 0o700)
    with closing(sqlite3.connect(DB.as_uri() + '?mode=ro', uri=True)) as source:
        with closing(sqlite3.connect(directory / 'x-ui.db')) as destination:
            source.backup(destination)
            need(destination.execute('PRAGMA quick_check').fetchone() == ('ok',), 'SNAPSHOT_DATABASE')
    os.chmod(directory / 'x-ui.db', 0o600)
    paths = ['etc/x-ui', 'usr/local/x-ui', 'etc/krysyuk-standalone', 'etc/systemd/system',
             'etc/nginx', 'etc/letsencrypt', 'etc/ufw']
    command(['tar', '--acls', '--xattrs', '--numeric-owner', '--exclude=etc/x-ui/x-ui.db',
             '--exclude=etc/x-ui/x-ui.db-wal', '--exclude=etc/x-ui/x-ui.db-shm',
             '-cpf', str(directory / 'managed-before.tar'), '-C', '/', *paths], timeout=180)
    command(['tar', '-tf', str(directory / 'managed-before.tar')], timeout=60)
    for name, args in (('nft-before.txt', ['nft', '-s', 'list', 'ruleset']),
                       ('ufw-before.txt', ['ufw', 'show', 'added'])):
        atomic(directory / name, command(args))
    manifest = {p.name: x.sha(p.read_bytes()) for p in directory.iterdir() if p.is_file()}
    atomic(directory / 'manifest.json', x.canonical(manifest))
    need(all(x.sha((directory / name).read_bytes()) == digest for name, digest in manifest.items()),
         'SNAPSHOT_READBACK')
    record = {'version': 1, 'status': 'prepared', 'units': units, 'files': [],
              'database': plan.database, 'database_applied': False,
              'before_target': plan.before, 'after_target': plan.after,
              'before_feed': plan.expected_before(), 'after_feed': plan.expected,
              'paused_timers': [], 'runtime_touched': False}
    journal = Journal(directory, record)
    journal.save()
    return journal


def validate_candidates(plan, directory):
    for number, (path, raw) in enumerate(plan.configs.items()):
        candidate = directory / f'xray-candidate-{number}.json'
        atomic(candidate, raw)
        binary = (MAIN.parent / 'xray-linux-amd64' if path == MAIN else
                  Path('/usr/local/lib/germanyvpn-xhttp-test/xray'))
        need(x.sha(binary.read_bytes()) == x.XRAY_SHA, 'XRAY_PIN')
        command([str(binary), 'run', '-test', '-config', str(candidate)],
                env={**SAFE_ENV, 'XRAY_LOCATION_ASSET': str(binary.parent)}, step='XRAY_PREFLIGHT')


def payload_checks(uris, target, secret, extra_entries):
    roles = {x.sha(x.canonical(signature(entry['uri']))): entry['egress'] == 'WARP_CF'
             for entry in extra_entries}
    warp_ids = {secret.get('WARP_REALITY_UUID'), secret.get('WARP_XHTTP_UUID')}
    checked, unsupported = 0, 0
    for uri in uris:
        parsed, values = x.query(uri) if not uri.startswith('vmess://') else (None, {})
        if values.get('security') != 'reality':
            continue
        if (parsed.scheme != 'vless' or values.get('type') not in ('grpc', 'xhttp') or
                values.get('flow') or values.get('encryption', 'none') != 'none'):
            unsupported += 1
            continue
        warp = roles.get(x.sha(x.canonical(signature(uri))), parsed.username in warp_ids)
        x.payload(uri, warp, target['TARGET_IPV4'])
        checked += 1
    return checked, unsupported


def rollback(journal, secret, initial=None):
    record = journal.record
    need(not record.get('backend_unverified', False), 'BACKEND_RECOVERY_REQUIRED')
    units = record['units']
    touched = record.get('runtime_touched', True)
    if touched:
        stop(units)
    if record['database_applied']:
        database(record['database'], restore=True)
    journal.rollback()
    for raw, identity in reversed(record.get('backend_created_dirs', [])):
        path = Path(raw)
        if path.exists() or path.is_symlink():
            need(path in DECOY_DIRS and directory_state(path) == identity, 'ROLLBACK_FOREIGN_DIRECTORY')
            destination = journal.directory / ('backend-failed-' + path.name)
            need(not destination.exists() and not destination.is_symlink(), 'ROLLBACK_DIRECTORY_EXISTS')
            # Retain the entire new website, including any files added during
            # the failed operation, in the private snapshot. Never recurse-delete.
            path.rename(destination)
    command(['nginx', '-t'])
    command(['systemctl', 'reload', 'nginx.service'])
    if touched:
        start(units)
    start(record.get('paused_timers', []))
    initial = initial if initial is not None else record['before_feed']
    recovered = x.native(record['before_target'], secret, expected_count=len(initial))
    need(uri_hashes(recovered) == uri_hashes(initial), 'ROLLBACK_FEED')
    record['status'] = 'rolled_back'
    journal.save()
    PENDING.unlink(missing_ok=True)


def adopt_backend(journal, before):
    """Register a completed backend even when a signal interrupted its caller."""
    record = journal.record
    recorded = {entry[0] for entry in record['files']}
    missing_files = {path: previous for path, previous in before.items()
                     if str(path) not in recorded and file_state(path) != previous}
    registered_dirs = {entry[0] for entry in record.get('backend_created_dirs', [])}
    missing_dirs = [path for path in DECOY_DIRS if
                    record.get('backend_dirs_before', {}).get(str(path)) is None and
                    path.exists() and str(path) not in registered_dirs]
    if not missing_files and not missing_dirs:
        if record.get('backend_unverified'):
            command(['bash', str(BUNDLE / 'base/install-reality-decoy.sh'), '--check-only'])
            record['backend_unverified'] = False
            journal.save()
        return
    record['backend_unverified'] = True
    journal.save()
    # An incomplete backend without COMMITTED cannot be silently adopted. Its
    # own private snapshot is retained for a reviewed recovery after SIGKILL.
    command(['bash', str(BUNDLE / 'base/install-reality-decoy.sh'), '--check-only'], step='LOCAL_TARGET_VERIFY')
    journal.record_backend(missing_files)
    record.setdefault('backend_created_dirs', []).extend(
        [[str(path), directory_state(path)] for path in missing_dirs])
    record['backend_unverified'] = False
    journal.save()


def apply(plan, initial, secret):
    units = ['x-ui.service', 'germanyvpn-xhttp-test.service']
    if WARP.exists():
        units.append('germanyvpn-xhttp-warp.service')
    if PORTFOLIO.exists():
        units.append('germanyvpn-portfolio.service')
    need(all(running(unit) for unit in units), 'BASELINE_SERVICE')
    journal = snapshot(plan, units)
    validate_candidates(plan, journal.directory)
    atomic(PENDING, str(journal.directory).encode())
    try:
        # Certificate hooks may restart the same services. Pause only their
        # timers, retain their enable state, and refuse an already running job.
        for timer in ('certbot.timer', 'vpn-cert-reconcile.timer'):
            if running(timer):
                journal.record['paused_timers'].append(timer)
                journal.save()
                command(['systemctl', 'stop', timer])
        if plan.before.get('TARGET_TLS_MODE', 'letsencrypt') == 'letsencrypt':
            need(quiescent('certbot.service') and quiescent('vpn-cert-reconcile.service'),
                 'CERTIFICATE_JOB_BUSY')
        journal.record['runtime_touched'] = True
        journal.save()
        stop(units)
        journal.record['database_applied'] = 'intent'
        journal.save()
        database(plan.database)
        journal.record['database_applied'] = True
        journal.save()
        journal.change(TARGET, plan.files[TARGET])
        if plan.after.get('TARGET_REALITY_MODE') != 'external':
            before = {path: file_state(path) for path in DECOY_PATHS}
            journal.record['backend_before'] = {str(path): state for path, state in before.items()}
            journal.record['backend_dirs_before'] = {str(path): directory_state(path) for path in DECOY_DIRS}
            journal.save()
            try:
                command(['bash', str(BUNDLE / 'base/install-reality-decoy.sh'), '--manage-apply'], timeout=240,
                        step='LOCAL_TARGET_PREPARE')
            finally:
                # The child has exited or its entire process group has been
                # stopped. Defer signals only during this short registration.
                with x.defer_interruptions():
                    adopt_backend(journal, before)
        for path, raw in plan.files.items():
            if path != TARGET:
                journal.change(path, raw)
        journal.change(MAIN, plan.main)
        start(units)
        verify_runtime(plan.main)
        feeds = x.native(plan.after, secret, expected_count=len(plan.expected))
        need(uri_hashes(feeds) == uri_hashes(plan.expected), 'PUBLIC_FEED_READBACK')
        for path, raw in plan.configs.items():
            need(x.canonical(x.strict_json(path.read_bytes())) == raw, 'CONFIG_READBACK')
        extras = x.strict_json(LINKS.read_bytes())['entries'] if LINKS.exists() else []
        tested, pending = payload_checks(feeds, plan.after, secret, extras)
        start(journal.record['paused_timers'])
        command(['bash', str(SOURCE / 'tools/verify.sh')], timeout=900, step='FINAL_VERIFY')
        journal.record['status'] = 'committed'
        journal.save()
        PENDING.unlink()
    except BaseException:
        try:
            rollback(journal, secret, initial)
        except BaseException:
            raise RuntimeError('MANAGE_REALITY_ROLLBACK_REQUIRED') from None
        raise
    print(f'REALITY_AUTH_E2E_CHECKED={tested} UNSUPPORTED_PENDING={pending}')
    print(f'REALITY_MANAGEMENT_COMMITTED=1 SNAPSHOT={journal.directory}')


def recover():
    directory = Path(private(PENDING).decode())
    need(directory.parent == BACKUPS and re.fullmatch(r'change-[a-zA-Z0-9_-]+', directory.name),
         'RECOVERY_DIRECTORY')
    info = directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
         'RECOVERY_DIRECTORY')
    manifest = x.strict_json(private(directory / 'manifest.json'))
    need(set(manifest) == {'x-ui.db', 'managed-before.tar', 'nft-before.txt', 'ufw-before.txt'} and
         all(name in ('x-ui.db', 'managed-before.tar', 'nft-before.txt', 'ufw-before.txt') and
             x.sha(private(directory / name)) == digest for name, digest in manifest.items()),
         'RECOVERY_SNAPSHOT')
    record = x.strict_json(private(directory / 'journal.json'))
    need(record.get('version') == 1 and record.get('status') in ('prepared', 'committed', 'rolled_back'),
         'RECOVERY_RECORD')
    if record['status'] == 'committed':
        command(['bash', str(SOURCE / 'tools/verify.sh')], timeout=900, step='RECOVERY_VERIFY')
        PENDING.unlink()
        print('REALITY_MANAGEMENT_RECOVERED=committed')
        return
    journal = Journal(directory, record)
    if 'backend_before' in record:
        # A kill can occur after the backend committed and before its files
        # were added to this journal. Adopt only a fully verified backend.
        paths = {Path(path): previous for path, previous in record['backend_before'].items()}
        adopt_backend(journal, paths)
    rollback(journal, x.parse_env(private(SERVER_ENV)))
    print('REALITY_MANAGEMENT_RECOVERED=rolled_back')


def main(argv=None):
    import fcntl
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check-only', action='store_true')
    modes.add_argument('--apply', action='store_true')
    modes.add_argument('--recover', action='store_true')
    args = parser.parse_args(argv)
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    os.umask(0o077)
    with open('/run/vpn-installer.lock', 'a') as lock:
        info = os.fstat(lock.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and
             info.st_nlink == 1, 'LOCK_OWNERSHIP')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.recover:
            recover()
            return
        need(not PENDING.exists() and not PENDING.is_symlink(), 'PENDING_RECOVERY_REQUIRED')
        raw = sys.stdin.buffer.read(4097)
        need(len(raw) <= 4096, 'REQUEST_SIZE')
        request = x.strict_json(raw)
        before = x.parse_env(private(TARGET))
        after = request_target(before, request)
        secret = x.parse_env(private(SERVER_ENV))
        command(['bash', str(SOURCE / 'tools/verify.sh')], timeout=900, step='BASELINE_VERIFY')
        if (before.get('TARGET_REALITY_MODE', 'external') == after['TARGET_REALITY_MODE'] and
                before['TARGET_REALITY_SNI'] == after['TARGET_REALITY_SNI']):
            print('REALITY_MANAGEMENT_UNCHANGED=1')
            return
        count = (len(x.strict_json(private(PUBLICATION))['names']) if PUBLICATION.exists()
                 else x.profile_count(before))
        initial = x.native(before, secret, expected_count=count)
        plan = Plan(before, after, initial).build()
        if after.get('TARGET_REALITY_MODE') == 'external':
            identity = after['TARGET_REALITY_SNI']
            proof = command(['timeout', '20', 'openssl', 's_client', '-connect', x.reality_destination(after),
                             '-servername', identity, '-verify_hostname', identity, '-verify_return_error',
                             '-tls1_3', '-alpn', 'h2'], data=b'', combined=True)
            need(b'ALPN protocol: h2' in proof and b'Verification: OK' in proof, 'EXTERNAL_TLS')
        if args.check_only:
            print('REALITY_MANAGEMENT_PREFLIGHT=PASS')
        else:
            apply(plan, initial, secret)


if __name__ == '__main__':
    try:
        def interrupted(signum, frame):
            raise InterruptedError('MANAGE_REALITY_INTERRUPTED')
        for item in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(item, interrupted)
        main()
    except BaseException as error:
        code = str(error) if re.fullmatch(r'MANAGE_REALITY_[A-Z0-9_]+', str(error)) else 'MANAGE_REALITY_FAILED'
        print('VPN_ERROR_CODE=' + code, file=sys.stderr)
        if code == 'MANAGE_REALITY_BASELINE_VERIFY':
            print('Текущее состояние VPN не прошло проверку; настройки не изменены. Выполните vpn verify.',
                  file=sys.stderr)
        raise SystemExit(1)
