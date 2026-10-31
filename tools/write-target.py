"""Persist validated, non-credential installation input as a shell environment."""
import os
from pathlib import Path
import shlex
import sys

KEYS = ('TARGET_IPV4', 'TARGET_FQDN', 'TARGET_INTERFACE', 'TARGET_SSH_PORT',
        'TARGET_DEVICE_LIMIT', 'TARGET_REALITY_SNI', 'TARGET_LABEL', 'ACME_EMAIL')

if __name__ == '__main__':
    destination = Path(sys.argv[1])
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
        stream.write(''.join(f'{key}={shlex.quote(os.environ[key])}\n' for key in KEYS))
        stream.flush()
        os.fsync(stream.fileno())
