"""Regenerate the source integrity manifest from publishable files only."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if __name__ == '__main__':
    lines = []
    for path in sorted(ROOT.rglob('*')):
        relative = path.relative_to(ROOT)
        if any(part in ('.git', '__pycache__', '.codex') for part in relative.parts):
            continue
        if not path.is_file() or relative.as_posix() == 'SHA256SUMS':
            continue
        if path.is_symlink() or path.suffix in ('.key', '.pem', '.db', '.log', '.pyc'):
            raise RuntimeError(f'Non-source file: {relative}')
        lines.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative.as_posix()}\n')
    (ROOT / 'SHA256SUMS').write_text(''.join(lines), encoding='ascii', newline='\n')
    print(f'MANIFEST_FILES={len(lines)}')
