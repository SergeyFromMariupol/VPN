"""Replace only the public index, retaining the previous user page privately."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import signal
import sys
import tempfile


SPEC = importlib.util.spec_from_file_location('decoy_site_core', Path(__file__).with_name('reality-decoy.py'))
CORE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CORE)
INDEX = Path('/var/www/vpn-decoy/public/index.html')


def read_index(path: Path):
    try:
        with open(path, 'rb', opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW)) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('DECOY_PAGE_UNSAFE_INDEX')
            return stream.read(), info
    except FileNotFoundError:
        return None, None


def atomic(path: Path, data: bytes, mode=0o644, owner=None):
    descriptor, filename = tempfile.mkstemp(prefix='.vpn-page-', dir=path.parent)
    staged = Path(filename)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            if owner is not None:
                os.fchown(stream.fileno(), *owner)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, path)
    finally:
        staged.unlink(missing_ok=True)


def reset(path=INDEX, *, backup_root=Path('/var/backups'), verify=None):
    php_path = path.with_name('index.php')
    originals = {entry: read_index(entry) for entry in (path, php_path)}
    backup = Path(tempfile.mkdtemp(prefix='vpn-decoy-page.', dir=backup_root))
    backup.chmod(0o700)
    metadata = {}
    for entry, (old, info) in originals.items():
        if old is not None:
            atomic(backup / entry.name, old, 0o600)
            if hashlib.sha256((backup / entry.name).read_bytes()).digest() != hashlib.sha256(old).digest():
                raise ValueError('DECOY_PAGE_SNAPSHOT')
        metadata[entry.name] = {'existed': old is not None,
            'sha256': hashlib.sha256(old).hexdigest() if old is not None else None,
            'mode': stat.S_IMODE(info.st_mode) if info else None,
            'uid': info.st_uid if info else None, 'gid': info.st_gid if info else None}
    atomic(backup / 'state.json', json.dumps(metadata, sort_keys=True).encode(), 0o600)
    new = CORE.BODY.encode()
    html_attempted = False
    php_attempted = False
    try:
        # Do not overwrite a concurrent edit or newly introduced symlink.
        for entry, (old, info) in originals.items():
            current, current_info = read_index(entry)
            if current != old or ((info is None) != (current_info is None)) or (
                    info and (info.st_dev, info.st_ino) != (current_info.st_dev, current_info.st_ino)):
                raise ValueError('DECOY_PAGE_CONCURRENT_CHANGE')
        html_attempted = True
        atomic(path, new)
        old_php, php_info = originals[php_path]
        if old_php is not None:
            current, current_info = read_index(php_path)
            if current != old_php or current_info.st_ino != php_info.st_ino:
                raise ValueError('DECOY_PAGE_CONCURRENT_CHANGE')
            # Its complete verified copy and original metadata are private in
            # the snapshot. Remove only this exact entrypoint, never assets.
            php_attempted = True
            php_path.unlink()
        if verify is not None:
            verify()
        atomic(backup / 'COMMITTED', b'', 0o600)
        print('REALITY_DECOY_PAGE_RESET=1 SNAPSHOT=' + str(backup))
    except BaseException:
        for entry, attempted in ((php_path, php_attempted), (path, html_attempted)):
            if not attempted:
                continue
            old, info = originals[entry]
            current, _ = read_index(entry)
            if current == old:
                continue
            expected = None if entry == php_path else new
            if current != expected:
                raise ValueError('DECOY_PAGE_ROLLBACK_CONCURRENT_CHANGE')
            if old is None:
                entry.unlink(missing_ok=True)
            else:
                atomic(entry, old, stat.S_IMODE(info.st_mode), (info.st_uid, info.st_gid))
        raise


if __name__ == '__main__':
    if os.geteuid() != 0 or sys.argv[1:] != ['--reset-page']:
        raise SystemExit(2)
    def cancelled(_signum, _frame):
        raise RuntimeError('DECOY_PAGE_INTERRUPTED')
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, cancelled)
    reset(verify=lambda: CORE.probe(os.environ))
