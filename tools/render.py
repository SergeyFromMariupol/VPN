"""Replace explicitly enumerated topology placeholders in a private bundle copy."""
import ipaddress
import hashlib
import os
from pathlib import Path
import re
import sys


def render(root: Path) -> None:
    address = str(ipaddress.IPv4Address(os.environ['TARGET_IPV4']))
    interface = os.environ['TARGET_INTERFACE']
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface):
        raise ValueError('Invalid public interface')
    lines = []
    for path in sorted(root.rglob('*')):
        if '__pycache__' in path.parts:
            continue
        if path.is_symlink():
            raise ValueError('Bundle symlinks are not supported')
        if path.is_file():
            if path.name == 'SOURCE_SHA256SUMS':
                continue
            data = path.read_text(encoding='utf-8')
            updated = data.replace('@TARGET_IPV4@', address).replace('@TARGET_INTERFACE@', interface)
            if updated != data:
                path.write_text(updated, encoding='utf-8', newline='\n')
            if path.suffix == '.sh':
                path.chmod(0o700)
            lines.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}\n')
    (root / 'SOURCE_SHA256SUMS').write_text(''.join(lines), encoding='ascii', newline='\n')


if __name__ == '__main__':
    render(Path(sys.argv[1]))
