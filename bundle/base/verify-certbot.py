#!/usr/bin/env python3
"""Check the installed locked Certbot distributions without importing them."""
import base64
import csv
import hashlib
import importlib.metadata
from pathlib import Path
import re
import sys


def verify(lock_path: Path, venv: Path) -> None:
    assert Path(sys.prefix).resolve() == venv.resolve(), "wrong Certbot virtual environment"
    assert sys.version_info[:2] == (3, 12), "Ubuntu CPython 3.12 is required"
    expected = {}
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([a-z0-9-]+)==([a-zA-Z0-9.]+) --hash=sha256:([a-f0-9]{64})", line)
        assert match, "invalid locked requirement"
        assert match[1] not in expected, "duplicate locked requirement"
        expected[match[1]] = match[2]
    assert expected.get("certbot") == expected.get("acme") == "5.9.0", "unexpected Certbot pin"
    installed = {}
    for dist in importlib.metadata.distributions():
        name = re.sub(r"[-_.]+", "-", dist.metadata["Name"]).lower()
        assert name not in installed, "duplicate installed distribution"
        installed[name] = dist
    # pip is supplied by Ubuntu's python3-venv/ensurepip and is used only to
    # install the explicitly hashed lock. It is not a Certbot runtime module.
    assert set(installed) - {"pip"} == set(expected), "Certbot dependency set drift"
    for name, version in expected.items():
        dist = installed[name]
        assert dist.version == version, f"Certbot dependency version drift: {name}"
        record = dist.read_text("RECORD")
        assert record, f"missing installed wheel record: {name}"
        for relative, checksum, size in csv.reader(record.splitlines()):
            path = Path(dist.locate_file(relative))
            assert path.resolve().is_relative_to(venv.resolve()), "wheel record escapes venv"
            assert path.is_file() and not path.is_symlink(), "missing or symlinked wheel file"
            if checksum:
                kind, encoded = checksum.split("=", 1)
                assert kind == "sha256", "unexpected wheel checksum algorithm"
                digest = base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).rstrip(b"=")
                assert digest.decode("ascii") == encoded, f"installed wheel file changed: {name}"
                assert path.stat().st_size == int(size), "installed wheel size mismatch"
            else:
                assert relative.endswith((".pyc", ".dist-info/RECORD")), "unhashed wheel file"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify-certbot.py LOCK VENV")
    verify(Path(sys.argv[1]), Path(sys.argv[2]))
    print("CERTBOT_LOCKED_DISTRIBUTIONS_OK=1")
