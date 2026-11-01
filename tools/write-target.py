"""Persist validated, non-credential installation input as a shell environment."""
import os
from pathlib import Path
import shlex
import sys

KEYS = ('TARGET_ADDRESS_MODE', 'TARGET_TLS_MODE', 'TARGET_IPV4', 'TARGET_FQDN', 'TARGET_INTERFACE', 'TARGET_SSH_PORT',
        'TARGET_DEVICE_LIMIT', 'TARGET_REALITY_SNI', 'TARGET_LABEL', 'ACME_EMAIL')

def write_target(destination: Path, env: dict) -> None:
    env = dict(env, TARGET_TLS_MODE=env.get('TARGET_TLS_MODE', 'letsencrypt'))
    if env['TARGET_TLS_MODE'] not in ('letsencrypt', 'none'):
        raise ValueError('Invalid certificate mode')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
        stream.write(''.join(f'{key}={shlex.quote(env[key])}\n' for key in KEYS))
        stream.flush()
        os.fsync(stream.fileno())


if __name__ == '__main__':
    write_target(Path(sys.argv[1]), os.environ)
