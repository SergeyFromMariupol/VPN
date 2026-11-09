#!/usr/bin/env python3
"""Stage a trusted Let's Encrypt certificate for an exact local IPv4 set."""

import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time


CERTBOT = "/opt/vpn-certbot/bin/certbot"
LE_ROOT = Path("/etc/letsencrypt")
ATTEMPT = Path("/var/lib/vpn-installer/ip-certificate-attempt")
SERVER = "https://acme-v02.api.letsencrypt.org/directory"
MINIMUM_VALIDITY = 86400
RETRY_AFTER = 900
COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class CertificateError(RuntimeError):
    pass


def normalize(addresses):
    ipv4 = []
    for value in addresses:
        if not isinstance(value, str):
            raise ValueError("invalid IPv4 address")
        ipv4.append(ipaddress.IPv4Address(value))
    if (not 1 <= len(ipv4) <= 100 or len(set(ipv4)) != len(ipv4) or
            any(not ip.is_global or ip.is_multicast or ip.is_reserved for ip in ipv4)):
        raise ValueError("invalid public IPv4 certificate set")
    return tuple(str(ip) for ip in sorted(ipv4))


def name_for(addresses):
    identifier_set = "\n".join(normalize(addresses)).encode("ascii")
    return "vpn-ip-" + hashlib.sha256(identifier_set).hexdigest()[:24]


def safe_stat(path, kind):
    info = path.lstat()
    if not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise CertificateError("IP_CERT_PATH")
    return info


def lineage_paths(name):
    return (LE_ROOT / "live" / name, LE_ROOT / "archive" / name,
            LE_ROOT / "renewal" / (name + ".conf"))


def checked_lineage(name):
    live, archive, renewal = lineage_paths(name)
    for directory in (LE_ROOT, live.parent, archive.parent, renewal.parent, live, archive):
        safe_stat(directory, stat.S_ISDIR)
    safe_stat(renewal, stat.S_ISREG)
    for part in ("cert", "chain", "fullchain", "privkey"):
        link = live / (part + ".pem")
        info = link.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise CertificateError("IP_CERT_PATH")
        source = link.resolve(strict=True)
        if source.parent != archive or not re.fullmatch(part + r"[1-9][0-9]*\.pem", source.name):
            raise CertificateError("IP_CERT_PATH")
        source_info = safe_stat(source, stat.S_ISREG)
        if part == "privkey" and source_info.st_mode & 0o077:
            raise CertificateError("IP_CERT_PATH")
    return live


def openssl(*args):
    return subprocess.check_output(
        ["openssl", *args], timeout=10, stderr=subprocess.DEVNULL, env=COMMAND_ENV,
    )


def check_material(live, addresses, *, ignore_time=False):
    cert = str(live / "cert.pem")
    fullchain = str(live / "fullchain.pem")
    key = str(live / "privkey.pem")
    san = openssl("x509", "-in", cert, "-noout", "-ext", "subjectAltName").decode("ascii")
    header, _, values = san.partition("\n")
    expected = sorted("IP Address:" + address for address in addresses)
    if (header.strip() not in ("X509v3 Subject Alternative Name:", "X509v3 Subject Alternative Name: critical")
            or sorted(value.strip() for value in values.split(",")) != expected):
        raise CertificateError("IP_CERT_SAN")
    if openssl("x509", "-in", fullchain, "-outform", "DER") != openssl("x509", "-in", cert, "-outform", "DER"):
        raise CertificateError("IP_CERT_FULLCHAIN")
    if openssl("x509", "-in", cert, "-noout", "-pubkey") != openssl("pkey", "-in", key, "-pubout"):
        raise CertificateError("IP_CERT_KEY")
    verify = ["verify", "-purpose", "sslserver", "-CApath", "/etc/ssl/certs", "-untrusted", fullchain]
    if ignore_time:
        verify.append("-no_check_time")
    else:
        openssl("x509", "-in", cert, "-noout", "-checkend", str(MINIMUM_VALIDITY))
    for address in addresses:
        openssl(*verify, "-verify_ip", address, cert)


def validate(name, addresses):
    addresses = normalize(addresses)
    if name != name_for(addresses) and (len(addresses) != 1 or name != addresses[0]):
        raise CertificateError("IP_CERT_NAME")
    try:
        check_material(checked_lineage(name), addresses)
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise CertificateError("IP_CERT_VERIFY") from exc


def issuance_command(name, addresses, email):
    if email and not re.fullmatch(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", email):
        raise CertificateError("IP_CERT_CONTACT")
    command = [
        CERTBOT, "certonly", "--config", "/dev/null", "--standalone", "--non-interactive",
        "--agree-tos", "--no-eff-email", "--server", SERVER,
        "--preferred-challenges", "http", "--http-01-address", "0.0.0.0",
        "--required-profile", "shortlived", "--no-directory-hooks", "--keep-until-expiring",
        "--pre-hook", "", "--post-hook", "", "--deploy-hook", "",
        "--cert-name", name,
    ]
    command.extend(("--email", email) if email else ("--register-unsafely-without-email",))
    for address in addresses:
        command.extend(("--ip-address", address))
    return command


def record_attempt():
    # The reconciler holds its exclusive lock and quiesces the Certbot timer.
    safe_stat(ATTEMPT.parent, stat.S_ISDIR)
    now = int(time.time())
    if os.path.lexists(ATTEMPT):
        info = safe_stat(ATTEMPT, stat.S_ISREG)
        if stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 20:
            raise CertificateError("IP_CERT_ATTEMPT_STATE")
        then = int(ATTEMPT.read_text(encoding="ascii"))
        if 0 <= now - then < RETRY_AFTER:
            raise CertificateError("IP_CERT_RETRY_LATER")
    staged = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=ATTEMPT.parent, delete=False) as temp:
            staged = Path(temp.name)
            temp.write(str(now) + "\n")
            temp.flush()
            os.fsync(temp.fileno())
        os.replace(staged, ATTEMPT)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def issue(addresses, email=""):
    addresses = normalize(addresses)
    name = name_for(addresses)
    command = issuance_command(name, addresses, email)
    try:
        if any(os.path.lexists(path) for path in lineage_paths(name)):
            live = checked_lineage(name)
            try:
                check_material(live, addresses)
                return name
            except subprocess.CalledProcessError:
                # A valid but expiring lineage can be renewed. Reject unrelated,
                # partially created, or untrusted lineages with the same name.
                check_material(live, addresses, ignore_time=True)
        record_attempt()
        subprocess.run(command, check=True, timeout=300, env=COMMAND_ENV,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as exc:
        raise CertificateError("IP_CERT_ISSUE") from exc
    validate(name, addresses)
    return name
