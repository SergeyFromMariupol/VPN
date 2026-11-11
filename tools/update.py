"""Update only compatible v1.5.x source/runtime trees; never migrate VPN data.

The root launcher owns installer FD 9. Snapshots and the durable journal stay
private. Recovery is callable from a fresh downloaded source if a killed rename
left the installed source temporarily absent.
"""
from __future__ import annotations

import argparse
import ast
from contextlib import closing, contextmanager
import ctypes
from datetime import datetime, timezone
import hashlib
import importlib.util
import ipaddress
import io
import json
import marshal
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import types


ADMIN_UID = ADMIN_GID = 0
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'LC_ALL': 'C', 'LANG': 'C', 'LANGUAGE': 'C'}
TIMERS = ('certbot.timer', 'vpn-cert-reconcile.timer')
JOBS = ('certbot.service', 'vpn-cert-reconcile.service')
TESTS = ('test-e2e-local.sh', 'test-invalid.sh')
VOLATILE = {'up', 'down', 'all_time', 'last_online', 'online', 'online_at', 'updated_at',
            'last_traffic_reset_time', 'last_fetch_at', 'last_fetch_error'}
DB_TABLES = ('users', 'settings', 'inbounds', 'clients', 'client_inbounds', 'client_external_links')


class Layout:
    def __init__(self, root=Path('/')):
        self.root = root
        self.source = root / 'opt/vpn-installer'
        self.state = root / 'var/lib/vpn-installer'
        self.runtime = self.state / 'bundle'
        self.pending = self.state / 'update.pending'
        self.backups = root / 'var/backups/vpn-source-update'
        self.warp_tests = root / 'opt/krysyuk-warp-egress/tests'
        self.db = root / 'etc/x-ui/x-ui.db'
        self.target = root / 'etc/germanyvpn-target.env'
        self.protected = (self.target, root / 'etc/krysyuk-standalone/server.env',
                          root / 'etc/krysyuk-standalone/access.env')


def need(condition, code):
    if not condition:
        raise RuntimeError('VPN_UPDATE_' + code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


@contextmanager
def defer_interruptions():
    numbers = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous = {number: signal.getsignal(number) for number in numbers}
    pending = []
    for number in numbers:
        signal.signal(number, lambda value, frame: pending.append((value, frame)))
    try:
        yield
    finally:
        for number, handler in previous.items(): signal.signal(number, handler)
        if pending:
            number, frame = pending[0]
            handler = previous[number]
            if callable(handler): handler(number, frame)
            elif handler != signal.SIG_IGN: raise InterruptedError('VPN_UPDATE_INTERRUPTED')


def run(args, *, timeout=180, env=None):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=env or ENV)
    need(result.returncode == 0, 'COMMAND_' + Path(args[0]).name.upper().replace('-', '_'))
    return result.stdout


def sync(directory):
    descriptor = os.open(directory, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def identity(path):
    info = path.lstat()
    return [info.st_dev, info.st_ino]


def directory(path, *, private=False):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == ADMIN_UID and info.st_gid == ADMIN_GID and
         not info.st_mode & 0o022 and (not private or stat.S_IMODE(info.st_mode) == 0o700), 'DIRECTORY_ACL')


def file_state(path, *, private=False):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022 and
         (not private or (info.st_uid == ADMIN_UID and info.st_gid == ADMIN_GID and
                          stat.S_IMODE(info.st_mode) == 0o600)), 'FILE_ACL')
    return {'sha256': digest(path.read_bytes()), 'uid': info.st_uid, 'gid': info.st_gid,
            'mode': stat.S_IMODE(info.st_mode), 'links': info.st_nlink}


def atomic(path, data, *, replace=True):
    descriptor, name = tempfile.mkstemp(prefix='.vpn-update-', dir=path.parent)
    staged = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchown(stream.fileno(), ADMIN_UID, ADMIN_GID)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        move(staged, path, replace=replace)
    finally:
        staged.unlink(missing_ok=True)


def move(source, destination, *, replace=False):
    if replace:
        os.replace(source, destination)
    else:
        library = ctypes.CDLL(None, use_errno=True)
        result = library.renameat2(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
        if result:
            raise OSError(ctypes.get_errno(), 'VPN_UPDATE_NOREPLACE')
    for parent in {source.parent, destination.parent}:
        sync(parent)


def normalize(code):
    return code.replace(co_filename='', co_consts=tuple(normalize(value) if isinstance(value, types.CodeType)
                                                       else value for value in code.co_consts))


def safe_cache(path, relative, expected, files):
    parts = PurePosixPath(relative)
    match = re.fullmatch(r'([A-Za-z0-9_.-]+)\.cpython-312(?:\.opt-([12]))?\.pyc', parts.name)
    need(parts.parent.name == '__pycache__' and match is not None, 'UNEXPECTED_CACHE')
    source = str(parts.parent.parent / (match[1] + '.py'))
    need(source in expected, 'CACHE_WITHOUT_SOURCE')
    raw = path.read_bytes()
    need(len(raw) > 16 and raw[:4] == importlib.util.MAGIC_NUMBER and
         int.from_bytes(raw[4:8], 'little') in (0, 1, 3), 'CACHE_HEADER')
    source_bytes = files[source].read_bytes()
    if int.from_bytes(raw[4:8], 'little') & 1:
        need(raw[8:16] == importlib.util.source_hash(source_bytes), 'CACHE_SOURCE_HASH')
    try:
        stream = io.BytesIO(raw[16:])
        code = marshal.load(stream)
        need(not stream.read(1), 'CACHE_TRAILING_BYTES')
        need(isinstance(code, types.CodeType), 'CACHE_CODE')
        compiled = compile(source_bytes, '', 'exec', dont_inherit=True, optimize=int(match[2] or 0))
        need(normalize(code) == normalize(compiled), 'CACHE_CODE')
    except (ValueError, TypeError, EOFError, SyntaxError):
        need(False, 'CACHE_CODE')


def manifest(tree, name, *, caches=False):
    directory(tree, private=True)
    files = {}
    for path in tree.rglob('*'):
        info = path.lstat()
        need(info.st_uid == ADMIN_UID and info.st_gid == ADMIN_GID and not info.st_mode & 0o022 and
             (stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)), 'TREE_ACL')
        if stat.S_ISREG(info.st_mode):
            files[path.relative_to(tree).as_posix()] = path
    need(name in files, 'MANIFEST_MISSING')
    expected = {}
    for line in files[name].read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  ([^\r\n]+)', line)
        need(match is not None, 'MANIFEST_FORMAT')
        relative = PurePosixPath(match[2])
        need(not relative.is_absolute() and '..' not in relative.parts and '\\' not in match[2] and
             ':' not in match[2] and match[2] != name and match[2] not in expected and
             '__pycache__' not in relative.parts and relative.suffix != '.pyc', 'MANIFEST_PATH')
        expected[match[2]] = match[1]
    need(bool(expected) and set(expected) <= set(files), 'MANIFEST_COVERAGE')
    need(all(digest(files[path].read_bytes()) == value for path, value in expected.items()), 'MANIFEST_DIGEST')
    for relative in set(files) - set(expected) - {name}:
        need(caches, 'MANIFEST_EXTRA')
        safe_cache(files[relative], relative, expected, files)
    return expected


def version(source):
    match = re.search(r"^readonly release='(v1[.]5[.](0|[1-9][0-9]*))'$",
                      (source / 'install.sh').read_text(encoding='utf-8'), re.M)
    need(match is not None, 'VERSION_UNSUPPORTED')
    return match[1], int(match[2])


def parse_env(path):
    file_state(path, private=True)
    result = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, raw = line.partition('=')
        words = [''] if raw == '' else shlex.split(raw)
        need(separator and re.fullmatch(r'[A-Z][A-Z0-9_]*', key) and key not in result and len(words) == 1,
             'TARGET_FORMAT')
        result[key] = words[0]
    return result


def checkpoint(path):
    file_state(path, private=True)
    raw = path.read_text(encoding='ascii')
    need(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\n', raw) is not None, 'CHECKPOINT')
    need(datetime.strptime(raw.strip(), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%dT%H:%M:%SZ') == raw.strip(),
         'CHECKPOINT')


def completed(layout, target):
    names = ['base', 'certbot', 'tls', 'direct', 'panel', 'nginx-restart', 'cert-reconcile',
             'xhttp', 'renewal', 'menu', 'verify']
    mode = target.get('TARGET_REALITY_MODE', 'external')
    need(target.get('TARGET_TLS_MODE', 'letsencrypt') == 'letsencrypt' and mode in ('external', 'self-steal', 'decoy'),
         'HTTPS_REQUIRED')
    egress, profiles = target.get('TARGET_EGRESS_MODE', 'both'), target.get('TARGET_PROFILE_SET', 'basic')
    need(egress in ('warp', 'direct', 'both') and profiles in ('basic', 'dpi', 'all', 'custom'), 'TARGET_MODE')
    if mode != 'external': names.append('reality-decoy')
    if egress != 'direct': names += ['warp', 'dual']
    if target.get('TARGET_ADDRESS_MODE', 'domain') == 'ip': names.append('ip-address')
    if profiles != 'basic' or egress != 'both':
        names += ['baseline-verify', 'portfolio-publish']
        publication = layout.state / 'portfolio-publication.json'
        file_state(publication, private=True)
        info = json.loads(publication.read_bytes())
        need(info.get('status') == 'committed' and info.get('target') == target['TARGET_IPV4'], 'PUBLICATION')
    portfolio = layout.root / 'etc/germanyvpn-portfolio/state.json'
    if portfolio.exists():
        file_state(portfolio, private=True)
        info = json.loads(portfolio.read_bytes())
        need(info.get('phase') == 'committed' and info.get('target') == target['TARGET_IPV4'], 'PORTFOLIO')
        names.append('portfolio-runtime')
    for name in names:
        checkpoint(layout.state / (name + '.done'))
    promotion = layout.root / 'etc/germanyvpn-xhttp-test/promotion.json'
    file_state(promotion, private=True)
    need(json.loads(promotion.read_bytes()).get('status') == 'committed', 'PROMOTION')


def pending_conflicts(layout):
    for path in (layout.state / 'reality-management.pending', layout.state / 'profile-name-management.pending',
                 layout.root / 'etc/vpn-ip-addresses/pending'):
        need(not path.exists() and not path.is_symlink(), 'PENDING_RECOVERY')


def database_state(path):
    result = {}
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=20)) as database:
        need(database.execute('PRAGMA quick_check').fetchone() == ('ok',), 'DATABASE_CHECK')
        schema = database.execute("SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
        result['schema'] = schema
        existing = {name for name, _ in schema}
        need({'users', 'settings', 'inbounds', 'clients', 'client_inbounds', 'client_external_links'} <= existing,
             'DATABASE_SCHEMA')
        for table in DB_TABLES:
            columns = [row[1] for row in database.execute('PRAGMA table_info(' + table + ')') if row[1] not in VOLATILE]
            need(columns and all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', column) for column in columns), 'DATABASE_SCHEMA')
            rows = database.execute('SELECT ' + ','.join('"' + column + '"' for column in columns) + ' FROM ' + table).fetchall()
            encode = lambda value: {'blob': value.hex()} if isinstance(value, bytes) else value
            result[table] = sorted([list(map(encode, row)) for row in rows], key=lambda row: canonical(row))
    return digest(canonical(result))


def protected_state(layout):
    values = {str(path): file_state(path, private=True) for path in layout.protected}
    paths = ['usr/local/x-ui/bin/config.json', 'etc/germanyvpn-xhttp-test/config.json',
             'etc/germanyvpn-xhttp-test/promotion.json', 'etc/germanyvpn-xhttp-test/baseline.json',
             'etc/germanyvpn-xhttp-warp/config.json', 'etc/germanyvpn-portfolio/config.json',
             'etc/germanyvpn-portfolio/links.json', 'etc/germanyvpn-portfolio/state.json']
    for relative in paths:
        path = layout.root / relative
        if path.exists() or path.is_symlink(): values[str(path)] = file_state(path)
    return values


def test_states(layout, target):
    if target.get('TARGET_EGRESS_MODE', 'both') == 'direct':
        return {}
    directory(layout.warp_tests)
    result = {}
    for name in TESTS:
        path = layout.warp_tests / name
        value = file_state(path)
        need(value['uid'] == ADMIN_UID and value['gid'] == ADMIN_GID and
             path.read_bytes() == (layout.runtime / 'warp-egress/tests' / name).read_bytes(), 'WARP_TEST_DRIFT')
        result[str(path)] = value
    return result


def check_tests(values):
    need(all(file_state(Path(path)) == value for path, value in values.items()), 'WARP_TEST_CHANGED')


def unit_state(unit):
    process = subprocess.run(['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState',
                              '-p', 'MainPID', '-p', 'Job', '-p', 'UnitFileState'],
                             env=ENV, capture_output=True, timeout=20)
    values = dict(line.split('=', 1) for line in process.stdout.decode().splitlines() if '=' in line)
    need(process.returncode == 0, 'SYSTEMD_STATE')
    return values


def idle_jobs():
    for unit in JOBS:
        values = unit_state(unit)
        need(values.get('LoadState') == 'loaded' and values.get('ActiveState') in ('inactive', 'failed') and
             values.get('MainPID') == '0' and values.get('Job', '') in ('', '0'), 'CERTIFICATE_JOB_BUSY')


class Journal:
    def __init__(self, path, record):
        self.path, self.record = path, record

    def save(self):
        atomic(self.path / 'journal.json', canonical(self.record))

    def phase(self, value, *, best_effort=False):
        self.record['status'] = value
        try:
            self.save()
        except OSError:
            if not best_effort: raise


def stage_copy(source, destination, expected):
    destination.mkdir(mode=0o700)
    for name in sorted({*expected, 'SHA256SUMS'}):
        original, target = source / name, destination / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        data = original.read_bytes()
        mode = 0o700 if original.suffix == '.sh' or data.startswith((b'#!/bin/bash', b'#!/usr/bin/env bash')) else 0o600
        target.write_bytes(data); target.chmod(mode)
    manifest(destination, 'SHA256SUMS')


def syntax(tree):
    for path in tree.rglob('*'):
        if not path.is_file(): continue
        if path.suffix == '.py': ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        elif path.suffix == '.sh' or path.read_bytes().startswith((b'#!/bin/sh', b'#!/bin/bash', b'#!/usr/bin/env bash')):
            run(['bash', '-n', str(path)], timeout=20)


def render(source, destination, expected, target):
    destination.mkdir(mode=0o700)
    for name in expected:
        if not name.startswith('bundle/'): continue
        relative = name.removeprefix('bundle/')
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes((source / name).read_bytes()); path.chmod(0o600)
    run(['python3', '-I', '-B', str(source / 'tools/render.py'), str(destination)],
        env={**ENV, 'TARGET_IPV4': target['TARGET_IPV4'], 'TARGET_INTERFACE': target['TARGET_INTERFACE']})
    return manifest(destination, 'SOURCE_SHA256SUMS')


def snapshot(layout, journal):
    with closing(sqlite3.connect(layout.db.as_uri() + '?mode=ro', uri=True, timeout=20)) as current:
        with closing(sqlite3.connect(journal.path / 'x-ui.db')) as saved:
            current.backup(saved)
            need(saved.execute('PRAGMA quick_check').fetchone() == ('ok',), 'DATABASE_SNAPSHOT')
    (journal.path / 'x-ui.db').chmod(0o600)
    paths = ['opt/vpn-installer', 'var/lib/vpn-installer/bundle', 'etc/x-ui', 'usr/local/x-ui',
             'etc/systemd/system', 'etc/nginx', 'etc/letsencrypt', 'etc/ufw', 'etc/krysyuk-standalone',
             'etc/germanyvpn-target.env', 'etc/vpn-reality-decoy', 'var/www/vpn-decoy',
             'etc/krysyuk-warp-egress', 'opt/krysyuk-warp-egress']
    paths = [name for name in paths if (layout.root / name).exists()]
    run(['tar', '--acls', '--xattrs', '--numeric-owner', '--exclude=etc/x-ui/x-ui.db',
         '--exclude=etc/x-ui/x-ui.db-wal', '--exclude=etc/x-ui/x-ui.db-shm', '-cpf',
         str(journal.path / 'system-before.tar'), '-C', str(layout.root), *paths], timeout=300)
    (journal.path / 'system-before.tar').chmod(0o600)
    run(['tar', '-tf', str(journal.path / 'system-before.tar')])
    for name, args in (('ufw.before', ['ufw', 'show', 'added']), ('nft.before', ['nft', '-s', 'list', 'ruleset'])):
        atomic(journal.path / name, run(args))
    hashes = {name: digest((journal.path / name).read_bytes())
              for name in ('x-ui.db', 'system-before.tar', 'ufw.before', 'nft.before')}
    atomic(journal.path / 'snapshot.json', canonical(hashes))
    need(all(digest((journal.path / name).read_bytes()) == value for name, value in hashes.items()), 'SNAPSHOT_READBACK')
    journal.record['snapshot'] = hashes
    journal.save()


def timer_restore(record):
    for unit, before in record['timers'].items():
        now = unit_state(unit)
        need(now.get('UnitFileState') == before.get('UnitFileState'), 'TIMER_ENABLE_CHANGED')
        if before['ActiveState'] == 'active' and now.get('ActiveState') != 'active':
            run(['systemctl', 'start', unit])
        need(unit_state(unit).get('ActiveState') == before['ActiveState'], 'TIMER_RESTORE')


def pause(record, journal, *, best_effort=False):
    idle_jobs()
    for unit, before in record['timers'].items():
        if before['ActiveState'] == 'active':
            if unit not in record['paused']:
                record['paused'].append(unit)
                try:
                    journal.save()
                except OSError:
                    if not best_effort: raise
            run(['systemctl', 'stop', unit])
    idle_jobs()


def check_item(path, item, which):
    need(identity(path) == item[which], 'SWAP_IDENTITY')
    if item['kind'] == 'tree':
        actual = manifest(path, item['manifest'], caches=which == 'before')
        need(digest(canonical(actual)) == item[which + '_manifest'], 'SWAP_CONTENT')
    else:
        need(file_state(path) == item[which + '_file'], 'SWAP_CONTENT')


def rollback(layout, journal):
    record, okay = journal.record, True
    journal.phase('rolling_back', best_effort=True)
    try:
        pause(record, journal, best_effort=True)
    except BaseException:
        return False
    for item in reversed(record['swaps']):
        live, old, failed = (Path(item[name]) for name in ('live', 'old', 'failed'))
        try:
            if live.exists() or live.is_symlink():
                if identity(live) == item['after']:
                    check_item(live, item, 'after'); move(live, failed)
                else:
                    check_item(live, item, 'before')
            if old.exists() or old.is_symlink():
                check_item(old, item, 'before')
                need(not live.exists() and not live.is_symlink(), 'ROLLBACK_FOREIGN_LIVE')
                move(old, live)
            check_item(live, item, 'before')
        except BaseException:
            okay = False
    try:
        need(protected_state(layout) == record['protected'], 'PROTECTED_CHANGED')
        need(database_state(layout.db) == record['database'], 'DATABASE_CHANGED')
        check_tests(record.get('warp_before', {}))
    except BaseException:
        okay = False
    try:
        timer_restore(record)
    except BaseException:
        okay = False
    if okay:
        try:
            journal.phase('rolled_back')
            layout.pending.unlink(missing_ok=True); sync(layout.state)
        except OSError:
            okay = False
    if not okay: journal.phase('rollback_required', best_effort=True)
    return okay


def apply(layout, candidate):
    directory(layout.state, private=True)
    need(not layout.pending.exists() and not layout.pending.is_symlink(), 'RECOVERY_REQUIRED')
    pending_conflicts(layout)
    old = manifest(layout.source, 'SHA256SUMS', caches=True)
    current = manifest(layout.runtime, 'SOURCE_SHA256SUMS', caches=True)
    new = manifest(candidate, 'SHA256SUMS')
    old_version, old_patch = version(layout.source)
    new_version, new_patch = version(candidate)
    if old_patch == 0: need(len(old) == 209, 'LEGACY_SOURCE_COVERAGE')
    need(new_patch >= old_patch, 'DOWNGRADE_UNSUPPORTED')
    need(old_patch != new_patch or old == new, 'SAME_VERSION_DIFFERENT_SOURCE')
    for name in ('install.sh', 'tools/manage.sh', 'tools/render.py', 'bundle/scripts/target-contract.sh'):
        need(name in old and name in new, 'SOURCE_CONTRACT')
    for name in ('bundle/base/install-pinned-base.sh', 'bundle/base/certbot-requirements.txt'):
        need(name in old and name in new and old[name] == new[name], 'BINARY_MIGRATION_UNSUPPORTED')
    target = parse_env(layout.target)
    need(ipaddress.IPv4Address(target['TARGET_IPV4']).is_global and
         re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', target.get('TARGET_INTERFACE', '')), 'TARGET_ENDPOINT')
    completed(layout, target)
    protected, database = protected_state(layout), database_state(layout.db)
    warp_before = test_states(layout, target)
    if old == new:
        print('VPN_UPDATE_UNCHANGED=1 VERSION=' + old_version)
        return
    for parent in (layout.source.parent, layout.state, layout.backups.parent): directory(parent)
    if not layout.backups.exists(): layout.backups.mkdir(mode=0o700)
    directory(layout.backups, private=True)
    backup = Path(tempfile.mkdtemp(prefix='change-', dir=layout.backups)); backup.chmod(0o700)
    timers = {unit: unit_state(unit) for unit in TIMERS}
    need(all(values.get('LoadState') == 'loaded' and values.get('ActiveState') in ('active', 'inactive')
             for values in timers.values()), 'TIMER_STATE')
    journal = Journal(backup, {'version': 1, 'status': 'prepared', 'from': old_version, 'to': new_version,
        'protected': protected, 'database': database, 'timers': timers, 'paused': [], 'swaps': [], 'snapshot': {},
        'warp_before': warp_before, 'warp_after': dict(warp_before)})
    journal.save(); atomic(layout.pending, str(backup).encode(), replace=False)
    committed = commit_started = False
    try:
        pause(journal.record, journal)
        snapshot(layout, journal)
        expected_old = backup / 'expected-old-runtime'
        need(render(layout.source, expected_old, old, target) == current, 'OLD_RUNTIME_SOURCE_DRIFT')
        source_slot = Path(tempfile.mkdtemp(prefix='.vpn-update-source.', dir=layout.source.parent))
        runtime_slot = Path(tempfile.mkdtemp(prefix='.vpn-update-runtime.', dir=layout.state))
        staged = source_slot / 'new'; stage_copy(candidate, staged, new); syntax(staged)
        runtime = runtime_slot / 'new'; rendered = render(staged, runtime, new, target); syntax(runtime)
        for live, prepared, slot, name, before, after in (
                (layout.source, staged, source_slot, 'SHA256SUMS', old, new),
                (layout.runtime, runtime, runtime_slot, 'SOURCE_SHA256SUMS', current, rendered)):
            need(live.stat().st_dev == slot.stat().st_dev == prepared.stat().st_dev, 'CROSS_FILESYSTEM_SWAP')
            journal.record['swaps'].append({'kind': 'tree', 'live': str(live), 'new': str(prepared),
                'old': str(slot / 'old'), 'failed': str(slot / 'failed'), 'before': identity(live),
                'after': identity(prepared), 'manifest': name, 'before_manifest': digest(canonical(before)),
                'after_manifest': digest(canonical(after))})
        if target.get('TARGET_EGRESS_MODE', 'both') != 'direct':
            directory(layout.warp_tests)
            for name in TESTS:
                live = layout.warp_tests / name
                before = file_state(live)
                need(before['uid'] == ADMIN_UID and before['gid'] == ADMIN_GID and
                     live.read_bytes() == (layout.runtime / 'warp-egress/tests' / name).read_bytes(), 'WARP_TEST_DRIFT')
                if live.read_bytes() == (runtime / 'warp-egress/tests' / name).read_bytes():
                    continue
                slot = Path(tempfile.mkdtemp(prefix='.vpn-update-test.', dir=layout.warp_tests))
                prepared = slot / 'new'; prepared.write_bytes((runtime / 'warp-egress/tests' / name).read_bytes())
                prepared.chmod(before['mode'])
                journal.record['warp_after'][str(live)] = file_state(prepared)
                journal.record['swaps'].append({'kind': 'test', 'live': str(live), 'new': str(prepared),
                    'old': str(slot / 'old'), 'failed': str(slot / 'failed'), 'before': identity(live),
                    'after': identity(prepared), 'before_file': before, 'after_file': file_state(prepared)})
        journal.phase('swapping')
        for item in journal.record['swaps']:
            live, prepared, old_path = (Path(item[name]) for name in ('live', 'new', 'old'))
            check_item(live, item, 'before'); check_item(prepared, item, 'after')
            move(live, old_path); move(prepared, live)
            check_item(live, item, 'after'); check_item(old_path, item, 'before')
            journal.save()
        need(protected_state(layout) == protected, 'PROTECTED_CHANGED')
        need(database_state(layout.db) == database, 'DATABASE_CHANGED')
        check_tests(journal.record['warp_after'])
        journal.phase('verified')
        timer_restore(journal.record)
        commit_started = True
        with defer_interruptions():
            journal.phase('committed')
            committed = True
        layout.pending.unlink(); sync(layout.state)
        print('VPN_UPDATE_OK=1 VERSION=' + new_version + ' SNAPSHOT=' + str(backup))
    except BaseException:
        if committed:
            # Cleanup failure cannot turn a durable accepted update into a
            # rollback. Retain/recreate only our own pointer for --recover.
            if not layout.pending.exists() and not layout.pending.is_symlink():
                try:
                    atomic(layout.pending, str(backup).encode(), replace=False)
                except OSError:
                    pass
            print('VPN_UPDATE_COMMITTED=1 SNAPSHOT=' + str(backup), file=sys.stderr)
            raise RuntimeError('VPN_UPDATE_COMMITTED_RECOVERY_REQUIRED') from None
        if commit_started:
            # A save can fail after replace/fsync. Never undo under a possibly
            # committed disk journal: first persist rollback intent, or hold.
            try:
                with defer_interruptions(): journal.phase('rolling_back')
            except BaseException:
                print('VPN_UPDATE_RECOVERY_REQUIRED=1 SNAPSHOT=' + str(backup), file=sys.stderr)
                raise RuntimeError('VPN_UPDATE_RECOVERY_REQUIRED') from None
        okay = rollback(layout, journal)
        print('VPN_UPDATE_ROLLBACK_OK=' + str(int(okay)) + ' SNAPSHOT=' + str(backup), file=sys.stderr)
        raise


def recover(layout):
    directory(layout.state, private=True)
    pending_conflicts(layout)
    directory(layout.backups, private=True)
    file_state(layout.pending, private=True)
    backup = Path(layout.pending.read_text())
    need(backup.parent == layout.backups and re.fullmatch(r'change-[A-Za-z0-9_-]+', backup.name), 'RECOVERY_PATH')
    directory(backup, private=True)
    file_state(backup / 'journal.json', private=True)
    record = json.loads((backup / 'journal.json').read_bytes())
    need(record.get('version') == 1 and set(record.get('timers', {})) == set(TIMERS), 'RECOVERY_RECORD')
    allowed = {layout.source: (layout.source.parent, '.vpn-update-source.'),
               layout.runtime: (layout.state, '.vpn-update-runtime.')}
    allowed.update({layout.warp_tests / name: (layout.warp_tests, '.vpn-update-test.') for name in TESTS})
    seen = set()
    for item in record.get('swaps', []):
        live = Path(item['live']); need(live in allowed and live not in seen, 'RECOVERY_SWAP')
        seen.add(live)
        parent, prefix = allowed[live]
        directory(parent)
        slot = Path(item['new']).parent
        need(slot.parent == parent and slot.name.startswith(prefix) and
             re.fullmatch(r'[A-Za-z0-9_.-]+', slot.name), 'RECOVERY_SLOT')
        directory(slot, private=True)
        need(all(Path(item[name]) == slot / name for name in ('new', 'old', 'failed')), 'RECOVERY_SLOT')
        if live in (layout.source, layout.runtime):
            need(item.get('kind') == 'tree' and item.get('manifest') ==
                 ('SHA256SUMS' if live == layout.source else 'SOURCE_SHA256SUMS'), 'RECOVERY_SWAP')
        else:
            need(item.get('kind') == 'test', 'RECOVERY_SWAP')
    if record.get('swaps'):
        need(set(record.get('snapshot', {})) == {'x-ui.db', 'system-before.tar', 'ufw.before', 'nft.before'}, 'RECOVERY_SNAPSHOT')
    for name, value in record.get('snapshot', {}).items():
        need(name in ('x-ui.db', 'system-before.tar', 'ufw.before', 'nft.before'), 'RECOVERY_SNAPSHOT')
        file_state(backup / name, private=True)
        need(digest((backup / name).read_bytes()) == value, 'RECOVERY_SNAPSHOT')
    journal = Journal(backup, record)
    if record['status'] == 'committed':
        for item in record['swaps']: check_item(Path(item['live']), item, 'after')
        check_tests(record.get('warp_after', {}))
        need(protected_state(layout) == record['protected'], 'PROTECTED_CHANGED')
        need(database_state(layout.db) == record['database'], 'DATABASE_CHANGED')
        timer_restore(record)
        layout.pending.unlink(); sync(layout.state)
        print('VPN_UPDATE_RECOVERED=committed')
    else:
        need(rollback(layout, journal), 'ROLLBACK_REQUIRED')
        print('VPN_UPDATE_RECOVERED=rolled_back')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--apply', metavar='CANDIDATE_DIR')
    group.add_argument('--recover', action='store_true')
    args = parser.parse_args()
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    lock = os.fstat(9)
    need(stat.S_ISREG(lock.st_mode) and lock.st_uid == lock.st_gid == 0 and
         stat.S_IMODE(lock.st_mode) == 0o600 and lock.st_nlink == 1, 'INSTALLER_LOCK')
    import fcntl
    lock_path = Path('/run/vpn-installer.lock')
    need(not lock_path.is_symlink() and identity(lock_path) == [lock.st_dev, lock.st_ino], 'INSTALLER_LOCK')
    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.umask(0o077)
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, lambda _number, _frame: (_ for _ in ()).throw(InterruptedError()))
    layout = Layout()
    if args.recover: recover(layout)
    else: apply(layout, Path(args.apply).absolute())


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        value = str(error)
        code = value if re.fullmatch(r'VPN_UPDATE_[A-Z0-9_]+', value) else 'VPN_UPDATE_FAILED'
        print('VPN_UPDATE_ERROR=' + code, file=sys.stderr)
        print('Совместимое обновление поддерживает только полностью установленные HTTPS-версии VPN v1.5.x.', file=sys.stderr)
        try:
            pending = Layout().pending.exists() or Layout().pending.is_symlink()
        except OSError:
            pending = False
        if pending:
            print('Осталась незавершённая транзакция. Для безопасного восстановления выполните команду целиком:', file=sys.stderr)
            print('bash <(curl -fsSL https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/install.sh) --recover-update', file=sys.stderr)
        raise SystemExit(1)
