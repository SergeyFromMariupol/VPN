"""Persist validated, non-credential installation input as a shell environment."""
import os
from pathlib import Path
import re
from runpy import run_path
import shlex
import sys

KEYS = ('TARGET_ADDRESS_MODE', 'TARGET_TLS_MODE', 'TARGET_EGRESS_MODE', 'TARGET_PROFILE_SET',
        'TARGET_PROFILE_IDS',
        'TARGET_IPV4', 'TARGET_FQDN', 'TARGET_INTERFACE', 'TARGET_SSH_PORT',
        'TARGET_DEVICE_LIMIT', 'TARGET_REALITY_SNI', 'TARGET_LABEL', 'ACME_EMAIL',
        'TARGET_HAPP_PROVIDER_ID')

def write_target(destination: Path, env: dict) -> None:
    env = dict(env, TARGET_TLS_MODE=env.get('TARGET_TLS_MODE', 'letsencrypt'),
               TARGET_EGRESS_MODE=env.get('TARGET_EGRESS_MODE', 'both'),
               TARGET_PROFILE_SET=env.get('TARGET_PROFILE_SET', 'basic'),
               TARGET_PROFILE_IDS=env.get('TARGET_PROFILE_IDS', ''),
               TARGET_HAPP_PROVIDER_ID=env.get('TARGET_HAPP_PROVIDER_ID', ''))
    if env['TARGET_TLS_MODE'] != 'letsencrypt':
        raise ValueError('New installations require Let\'s Encrypt')
    if env['TARGET_EGRESS_MODE'] not in ('warp', 'direct', 'both'):
        raise ValueError('Invalid egress mode')
    if env['TARGET_PROFILE_SET'] == 'custom':
        preflight = Path(__file__).resolve().with_name('preflight.py')
        run_path(str(preflight))['validate_profile_selection'](env)
    elif env['TARGET_PROFILE_SET'] not in ('basic', 'dpi', 'all') or env['TARGET_PROFILE_IDS']:
        raise ValueError('Invalid profile set')
    label = env['TARGET_LABEL']
    if not isinstance(label, str) or not label.strip():
        raise ValueError('Invalid profile name')
    if env['TARGET_HAPP_PROVIDER_ID'] and not re.fullmatch(r'[A-Za-z0-9]{8}', env['TARGET_HAPP_PROVIDER_ID']):
        raise ValueError('Invalid Happ Provider ID')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
        stream.write(''.join(f'{key}={shlex.quote(env[key])}\n' for key in KEYS))
        stream.flush()
        os.fsync(stream.fileno())


if __name__ == '__main__':
    write_target(Path(sys.argv[1]), os.environ)
