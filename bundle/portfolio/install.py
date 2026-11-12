#!/usr/bin/env python3
"""Install the accepted extra portfolio as an isolated, fail-closed Xray plane.

Only a fresh installer invokes --apply. Private credentials, links and snapshots
stay on the VPS; stdout contains counts and status codes only.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import closing
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import sqlite3
import stat
import subprocess
import sys
import tempfile
import uuid
from urllib.parse import parse_qsl, unquote, urlsplit

# The installer invokes this script with Python -I; keep reviewed sibling
# modules importable without accepting a caller-controlled PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from plan import PORT_BASE, build
from portfolio_catalog import select_profiles
from renderer import reality_destination, reality_settings_match


ROOT = Path("/etc/germanyvpn-portfolio")
CONF = ROOT / "config.json"
LINKS = ROOT / "links.json"
STATE = ROOT / "state.json"
UNIT_NAME = "germanyvpn-portfolio.service"
UNIT = Path("/etc/systemd/system") / UNIT_NAME
HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/80-germanyvpn-portfolio")
TLS_MARKER = ROOT / "tls-deployed.sha256"
ACCOUNT = "vpnportfolio"
XRAY = Path("/usr/local/lib/germanyvpn-xhttp-test/xray")
ASSETS = XRAY.parent
XRAY_SHA256 = "a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e"
MAIN = Path("/usr/local/x-ui/bin/config.json")
TARGET_ENV = Path("/etc/germanyvpn-target.env")
BASELINE_DONE = Path("/var/lib/vpn-installer/xhttp.done")
CATALOG = Path(__file__).with_name("catalog.json")
BACKUPS = Path("/var/backups/vpn-portfolio")
TLS_CERT = Path("/etc/krysyuk-standalone/tls/fullchain.pem")
TLS_KEY = Path("/etc/krysyuk-standalone/tls/privkey.pem")

SQLITE_SNAPSHOT_WORKER = r'''
import sqlite3, sys
from contextlib import closing
with closing(sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro', uri=True, timeout=20)) as source:
    assert source.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
    with closing(sqlite3.connect(':memory:')) as destination:
        source.backup(destination)
        assert destination.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        sys.stdout.buffer.write(destination.serialize())
'''


def need(value, code):
    if not value:
        raise InvariantFailure(code)


class InvariantFailure(RuntimeError):
    def __init__(self, code):
        safe = code if re.fullmatch(r"PORTFOLIO_[A-Z0-9_]{1,80}", code) else \
            "PORTFOLIO_INVARIANT_UNKNOWN"
        super().__init__(safe)


class CommandFailure(RuntimeError):
    def __init__(self, step):
        need(re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", step),
             "PORTFOLIO_INVALID_STEP")
        super().__init__("PORTFOLIO_STEP_" + step)


class RollbackFailure(RuntimeError):
    def __init__(self, original, rollback_error):
        self.original_code = safe_error_code(original)
        self.rollback_code = safe_error_code(rollback_error)
        super().__init__("PORTFOLIO_ROLLBACK_FAILED")


def safe_error_code(error):
    # Exception messages from subprocesses and libraries can include credentials.
    # Only our own fixed codes are allowed into the private phase log or UI.
    if isinstance(error, (CommandFailure, InvariantFailure)):
        return str(error)
    return "PORTFOLIO_UNEXPECTED"


def report_failure(error, stream=None):
    stream = stream if stream is not None else sys.stderr
    if isinstance(error, RollbackFailure):
        print("PORTFOLIO_ERROR=" + error.original_code, file=stream)
        print("PORTFOLIO_ROLLBACK_ERROR=" + error.rollback_code, file=stream)
    else:
        print("PORTFOLIO_ERROR=" + safe_error_code(error), file=stream)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run_command(args, *, step, timeout=60, input_data=None, check=True):
    environment = {key: value for key, value in os.environ.items()
                   if key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
    environment.update(LC_ALL="C", LANG="C", LANGUAGE="C",
                       XRAY_LOCATION_ASSET=str(ASSETS))
    try:
        return subprocess.run(args, input=input_data, check=check,
                              capture_output=True, timeout=timeout,
                              env=environment)
    except (OSError, subprocess.SubprocessError):
        raise CommandFailure(step) from None


def command(args, *, step, timeout=60, input_data=None):
    return run_command(args, step=step, timeout=timeout,
                       input_data=input_data).stdout


def private(path, owner=0):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == owner and
         stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
         "PORTFOLIO_PRIVATE_FILE")
    return path.read_bytes()


def safe_directory(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
         stat.S_IMODE(info.st_mode) == 0o700, "PORTFOLIO_PRIVATE_DIR")


def target():
    result = {}
    for line in private(TARGET_ENV).decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        need("=" in line, "PORTFOLIO_TARGET_ENV")
        key, raw = line.split("=", 1)
        need(re.fullmatch(r"[A-Z][A-Z0-9_]*", key) and key not in result,
             "PORTFOLIO_TARGET_ENV")
        values = [""] if raw == "" else shlex.split(raw)
        need(len(values) == 1, "PORTFOLIO_TARGET_ENV")
        result[key] = values[0]
    result.setdefault("TARGET_EGRESS_MODE", "both")
    result.setdefault("TARGET_PROFILE_SET", "basic")
    result.setdefault("TARGET_PROFILE_ORDER", "legacy")
    need(result.get("TARGET_TLS_MODE", "letsencrypt") == "letsencrypt" and
         result["TARGET_PROFILE_SET"] in ("dpi", "all", "custom") and
         result["TARGET_EGRESS_MODE"] in ("warp", "direct", "both"),
         "PORTFOLIO_TARGET_MODE")
    need(result["TARGET_PROFILE_ORDER"] in ("legacy", "priority"),
         "PORTFOLIO_TARGET_ORDER")
    need(result.get("TARGET_IPV4") and result.get("TARGET_FQDN") and
         result.get("TARGET_REALITY_SNI") and result.get("TARGET_LABEL") and
         result.get("TARGET_INTERFACE"), "PORTFOLIO_TARGET_FIELDS")
    try:
        reality_destination(result)
    except ValueError:
        raise InvariantFailure("PORTFOLIO_REALITY_MODE") from None
    return result


def rows_for(target_info):
    rows = select_profiles(target_info["TARGET_PROFILE_SET"],
                           target_info["TARGET_EGRESS_MODE"],
                           target_info["TARGET_LABEL"],
                           target_info.get("TARGET_PROFILE_IDS", ""),
                           target_info.get("TARGET_PROFILE_ORDER", "legacy"))
    rows = [row for row in rows if not row["baseline_reuse"]]
    profile_set = target_info["TARGET_PROFILE_SET"]
    if profile_set != "custom":
        count = {"dpi": 46, "all": 70}[profile_set]
        if target_info["TARGET_EGRESS_MODE"] == "both":
            count *= 2
        need(len(rows) == count, "PORTFOLIO_SELECTED_COUNT")
    need(bool(rows), "PORTFOLIO_SELECTED_COUNT")
    return rows


def same_target(info, state):
    return (state["target"] == info["TARGET_IPV4"] and
            state["interface"] == info["TARGET_INTERFACE"] and
            state["profile_set"] == info["TARGET_PROFILE_SET"] and
            state["egress_mode"] == info["TARGET_EGRESS_MODE"] and
            state.get("profile_ids", "") == info.get("TARGET_PROFILE_IDS", "") and
            state.get("profile_order", "legacy") == info.get("TARGET_PROFILE_ORDER", "legacy"))


def keypair():
    output = command([str(XRAY), "x25519"], step="XRAY_X25519",
                     timeout=20).decode("ascii")
    private_key = re.findall(r"^Private(?:\s+key|Key):\s*([A-Za-z0-9_-]{43})\s*$",
                             output, re.M)
    public_key = re.findall(r"^(?:Public(?:\s+key|Key)|Password \(PublicKey\)):\s*"
                            r"([A-Za-z0-9_-]{43})\s*$", output, re.M)
    need(len(private_key) == len(public_key) == 1 and
         private_key[0] != public_key[0], "PORTFOLIO_KEYPAIR")
    return private_key[0], public_key[0]


def mlkem_pair():
    output = command([str(XRAY), "vlessenc"], step="XRAY_VLESSENC",
                     timeout=25).decode("utf-8")
    pairs = re.findall(r'"decryption"\s*:\s*"([^"]+)"\s*,?\s*'
                       r'"encryption"\s*:\s*"([^"]+)"', output)
    matches = [(dec, enc) for dec, enc in pairs
               if 100 <= len(dec) <= 300 and 1000 <= len(enc) <= 3000]
    need(len(matches) == 1, "PORTFOLIO_MLKEM_PAIR")
    return matches[0]


def shared_credentials(entry, offset):
    common = {"cert": str(TLS_CERT), "key": str(TLS_KEY),
              "path": "/" + secrets.token_hex(24),
              "service_name": "vpn-" + secrets.token_hex(12),
              "short_id": secrets.token_hex(8),
              "obfs_password": secrets.token_urlsafe(24)}
    if entry["security"] == "reality":
        common["reality_private_key"], common["reality_public_key"] = keypair()
    if entry["encryption"] == "mlkem":
        common["server_decryption"], common["client_encryption"] = mlkem_pair()
    return common


def profile_credentials(entry, shared):
    credentials = dict(shared)
    credentials["uuid"] = str(uuid.uuid4())
    credentials["password"] = secrets.token_urlsafe(32)
    return credentials


def unit_bytes():
    return f"""[Unit]
Description=VPN accepted portfolio Xray
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User={ACCOUNT}
Group={ACCOUNT}
SupplementaryGroups=xui-secrets
LoadCredential=config.json:{CONF}
Environment=XRAY_LOCATION_ASSET={ASSETS}
Environment=GODEBUG=multipathtcp=0
ExecStartPre={XRAY} run -test -config %d/config.json
ExecStart={XRAY} run -config %d/config.json
Restart=on-failure
RestartSec=3s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
""".encode("utf-8")


def hook_bytes(info):
    lineage = "/etc/letsencrypt/live/" + info.get("TARGET_CERT_NAME", info["TARGET_FQDN"])
    need(re.fullmatch(r"/etc/letsencrypt/live/[A-Za-z0-9.-]{1,253}", lineage),
         "PORTFOLIO_RENEWAL_LINEAGE")
    return f"""#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
lineage={lineage}
root={ROOT}
marker={TLS_MARKER}
[[ ${{RENEWED_LINEAGE:-}} == "$lineage" ]] || exit 0
[[ -d $root && ! -L $root && $(stat -c '%u:%g:%a' "$root") == 0:0:700 ]] || exit 1
lock=/run/vpn-portfolio-tls.lock
if [[ -e $lock || -L $lock ]]; then
  [[ -f $lock && ! -L $lock && $(stat -c '%u:%g:%a:%h' "$lock") == 0:0:600:1 ]] || exit 1
fi
exec 9>"$lock"
flock -w 120 9
cmp -s "$lineage/fullchain.pem" {TLS_CERT}
cmp -s "$lineage/privkey.pem" {TLS_KEY}
expected=$(sha256sum "$lineage/fullchain.pem"); expected=${{expected%% *}}
[[ $expected =~ ^[a-f0-9]{{64}}$ ]] || exit 1
if [[ -e $marker || -L $marker ]]; then
  [[ -f $marker && ! -L $marker && $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:600:1 ]] || exit 1
  if [[ $(cat "$marker") == "$expected" ]] && systemctl is-active --quiet {UNIT_NAME}; then
    exit 0
  fi
fi
{XRAY} run -test -config {CONF}
systemctl restart {UNIT_NAME}
systemctl is-active --quiet {UNIT_NAME}
cmp -s "$lineage/fullchain.pem" {TLS_CERT}
cmp -s "$lineage/privkey.pem" {TLS_KEY}
current=$(sha256sum "$lineage/fullchain.pem"); current=${{current%% *}}
[[ $current == "$expected" ]] || exit 1
stage=$(mktemp "$root/.tls-deployed.XXXXXXXX")
trap 'rm -f -- "$stage"' EXIT
printf '%s\\n' "$expected" >"$stage"
chmod 0600 "$stage"
mv -Tf -- "$stage" "$marker"
[[ -f $marker && ! -L $marker && $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:600:1 &&
   $(cat "$marker") == "$expected" ]]
""".encode("utf-8")


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), 0, 0)
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if path.exists() and not path.is_symlink():
            path.unlink()
        raise


def write_state(value):
    raw = canonical(value)
    fd, path = tempfile.mkstemp(prefix=".state-", dir=ROOT)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), 0, 0)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(path, STATE)
        directory = os.open(ROOT, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(path):
            os.unlink(path)


def read_state():
    if not STATE.exists():
        need(not STATE.is_symlink(), "PORTFOLIO_STATE_LINK")
        return None
    safe_directory(ROOT)
    raw = private(STATE)
    state = json.loads(raw)
    need(raw == canonical(state) and state.get("version") == 1 and
         state.get("phase") in ("pending", "committed") and
         isinstance(state.get("target"), str) and
         isinstance(state.get("interface"), str) and
         isinstance(state.get("uid"), int) and
         isinstance(state.get("profile_count"), int) and
         isinstance(state.get("ports"), dict) and
         isinstance(state.get("backup"), str) and
         isinstance(state.get("tls_initial_sha256"), str) and
         re.fullmatch(r"[a-f0-9]{64}", state["tls_initial_sha256"]),
         "PORTFOLIO_STATE")
    return state


def route_hashes():
    return {name: sha(command(args, step="ROUTE_" + name.upper())) for name, args in {
        "ip4_route": ["ip", "-4", "route", "show", "table", "all"],
        "ip6_route": ["ip", "-6", "route", "show", "table", "all"],
        "ip4_rule": ["ip", "-4", "rule", "show"],
        "ip6_rule": ["ip", "-6", "rule", "show"],
    }.items()}


def ufw_added():
    return [shlex.split(line) for line in command(["ufw", "show", "added"],
                                                   step="UFW_READ")
            .decode("utf-8").splitlines() if line.startswith("ufw ")]


def ufw_rule(info, port, protocol):
    need(protocol in ("tcp", "udp") and 1024 <= port <= 65535,
         "PORTFOLIO_UFW_RULE")
    return ["allow", "in", "on", info["TARGET_INTERFACE"], "to",
            info["TARGET_IPV4"], "port", str(port), "proto", protocol,
            "comment", "vpn-portfolio"]


def rules_for(info, ports):
    return [ufw_rule(info, int(port), network)
            for port, network in sorted(ports.items(), key=lambda pair: int(pair[0]))]


def ufw_port_conflict(added, ports):
    """Recognize any existing UFW rule covering a planned public port."""
    wanted = {int(port) for port in ports}
    for row in added:
        candidates = row[2:3]
        candidates.extend(row[index + 1] for index, token in enumerate(row[:-1])
                          if token == "port")
        for value in candidates:
            match = re.fullmatch(r"([0-9]{1,5})(?::([0-9]{1,5}))?(?:/(?:tcp|udp))?",
                                 value)
            if match and any(int(match[1]) <= port <= int(match[2] or match[1])
                             for port in wanted):
                return True
    return False


def snapshot():
    BACKUPS.mkdir(mode=0o700, exist_ok=True)
    safe_directory(BACKUPS)
    backup = BACKUPS / ("install-" + secrets.token_hex(12))
    backup.mkdir(mode=0o700)
    safe_directory(backup)
    database = command(["runuser", "-u", "xui", "--", "python3", "-I", "-B",
                        "-c", SQLITE_SNAPSHOT_WORKER], step="DB_SNAPSHOT",
                       timeout=90)
    need(0 < len(database) <= 64 * 1024 * 1024, "PORTFOLIO_DB_SIZE")
    write_new(backup / "x-ui.db", database)
    with closing(sqlite3.connect("file:" + str(backup / "x-ui.db") +
                                 "?mode=ro&immutable=1", uri=True)) as saved:
        need(saved.execute("PRAGMA quick_check").fetchone()[0] == "ok",
             "PORTFOLIO_DB_BACKUP")
    paths = ["etc/x-ui", "usr/local/x-ui", "etc/krysyuk-standalone",
             "etc/ufw", "etc/systemd/system", "etc/nginx", "etc/letsencrypt"]
    command(["tar", "--acls", "--xattrs", "--numeric-owner", "-cpf",
             str(backup / "managed-before.tar"), "-C", "/", *paths],
            step="TAR_SNAPSHOT", timeout=180)
    command(["tar", "-tf", str(backup / "managed-before.tar")],
            step="TAR_READBACK", timeout=90)
    write_new(backup / "nft-before.txt", command(["nft", "-s", "list", "ruleset"],
                                                   step="NFT_SNAPSHOT"))
    write_new(backup / "ufw-before.txt", command(["ufw", "show", "added"],
                                                   step="UFW_SNAPSHOT"))
    write_new(backup / "routes-before.json", canonical(route_hashes()))
    hashes = {p.name: sha(p.read_bytes()) for p in backup.iterdir() if p.is_file()}
    write_new(backup / "snapshot-hashes.json", canonical(hashes))
    need(all(sha((backup / name).read_bytes()) == digest for name, digest in hashes.items()),
         "PORTFOLIO_SNAPSHOT_READBACK")
    write_new(backup / "SNAPSHOT_COMPLETE", b"sqlite-tar-firewall-routes-readback-pass\n")
    return backup


def check_snapshot(path):
    need(path.parent == BACKUPS and path.name.startswith("install-") and
         (path / "SNAPSHOT_COMPLETE").exists(), "PORTFOLIO_SNAPSHOT")
    safe_directory(path)
    hashes = json.loads(private(path / "snapshot-hashes.json"))
    need(all(sha(private(path / name)) == digest for name, digest in hashes.items()),
         "PORTFOLIO_SNAPSHOT_DRIFT")


def free_identity():
    used = {item.pw_uid for item in pwd.getpwall()}
    used |= {item.gr_gid for item in grp.getgrall()}
    for value in range(999, 699, -1):
        if value not in used:
            return value
    raise InvariantFailure("PORTFOLIO_NO_SYSTEM_UID")


def occupied_ports():
    output = command(["ss", "-H", "-lntup"],
                     step="LISTENERS_READ").decode("utf-8")
    ports = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 5:
            _, separator, value = fields[4].rpartition(":")
            if separator and value.isdecimal():
                ports.add(int(value))
    return ports


def verify_reality_contract(info, config, links):
    """Check saved runtime and public SNI independently of their state hashes."""
    reality_ports = set()
    for inbound in config['inbounds']:
        stream = inbound.get('streamSettings', {})
        if stream.get('security') == 'reality':
            need(reality_settings_match(stream.get('realitySettings'), info),
                 'PORTFOLIO_REALITY_TARGET')
            reality_ports.add(inbound['port'])
    for link in links:
        if link['port'] in reality_ports:
            pairs = parse_qsl(urlsplit(link['uri']).query, keep_blank_values=True,
                              strict_parsing=True)
            values = dict(pairs)
            need(len(values) == len(pairs) and values.get('security') == 'reality' and
                 values.get('sni') == info['TARGET_REALITY_SNI'],
                 'PORTFOLIO_REALITY_SHARE_SNI')


def verify(info, state, *, allow_pending=False):
    need(state["phase"] == "committed" or allow_pending,
         "PORTFOLIO_NOT_COMMITTED")
    need(same_target(info, state) and
         state["catalog_sha256"] == sha(CATALOG.read_bytes()),
         "PORTFOLIO_TARGET_DRIFT")
    check_snapshot(Path(state["backup"]))
    safe_directory(ROOT)
    unit_info, hook_info = UNIT.lstat(), HOOK.lstat()
    need(stat.S_ISREG(unit_info.st_mode) and unit_info.st_uid == 0 and
         stat.S_IMODE(unit_info.st_mode) == 0o644 and unit_info.st_nlink == 1 and
         stat.S_ISREG(hook_info.st_mode) and hook_info.st_uid == 0 and
         stat.S_IMODE(hook_info.st_mode) == 0o750 and hook_info.st_nlink == 1,
         "PORTFOLIO_UNIT_OWNERSHIP")
    need(sha(private(CONF)) == state["config_sha256"] and
         sha(private(LINKS)) == state["links_sha256"] and
         sha(UNIT.read_bytes()) == state["unit_sha256"] and
         sha(HOOK.read_bytes()) == state["hook_sha256"] and
         sha(XRAY.read_bytes()) == XRAY_SHA256,
         "PORTFOLIO_FILE_DRIFT")
    expected_tls_hash = sha(TLS_CERT.read_bytes())
    need(TLS_CERT.read_bytes() ==
         (Path("/etc/letsencrypt/live") / info.get("TARGET_CERT_NAME", info["TARGET_FQDN"]) /
          "fullchain.pem").read_bytes() and
         private(TLS_MARKER) == (expected_tls_hash + "\n").encode(),
         "PORTFOLIO_TLS_DEPLOYMENT")
    manifest = json.loads(private(LINKS))
    expected_rows = rows_for(info)
    expected_ports = {entry["id"]: PORT_BASE + entry["port_offset"]
                      for entry in expected_rows}
    need(manifest.get("version") == 1 and
         manifest.get("target") == info["TARGET_IPV4"] and
         len(manifest["entries"]) == state["profile_count"] and
         {entry["port"] for entry in manifest["entries"]} ==
         {int(port) for port in state["ports"]}, "PORTFOLIO_MANIFEST_DRIFT")
    need([entry["id"] for entry in manifest["entries"]] ==
         [entry["id"] for entry in expected_rows],
         "PORTFOLIO_MANIFEST_SELECTION")
    for link, recipe in zip(manifest["entries"], expected_rows):
        port = expected_ports[recipe["id"]]
        role = "WARP_CF" if recipe["egress"] == "warp" else "DIRECT"
        need(set(link) == {"id", "remark", "uri", "port", "egress"} and
             link["remark"] == recipe["name"] and link["port"] == port and
             link["egress"] == role, "PORTFOLIO_LINK_RECIPE")
        if link["uri"].startswith("vmess://"):
            encoded = link["uri"][8:]
            payload = json.loads(base64.b64decode(encoded, validate=True))
            need(payload.get("ps") == recipe["name"] and
                 payload.get("add") == info["TARGET_FQDN"] and
                 str(payload.get("port")) == str(port), "PORTFOLIO_VMESS_URI")
        else:
            parsed = urlsplit(link["uri"])
            need(parsed.scheme == recipe["uri_scheme"] and
                 parsed.hostname == info["TARGET_FQDN"] and
                 parsed.port == port and
                 unquote(parsed.fragment) == recipe["name"],
                 "PORTFOLIO_SHARE_URI")
    config = json.loads(private(CONF))
    verify_reality_contract(info, config, manifest['entries'])
    selected_outbounds = {"DIRECT", "BLOCK"}
    if any(row["egress"] == "warp" for row in expected_rows):
        selected_outbounds.add("WARP_CF")
    need({inbound["port"] for inbound in config["inbounds"]} ==
         {int(port) for port in state["ports"]} and
         {outbound["tag"] for outbound in config["outbounds"]} == selected_outbounds and
         [rule["outboundTag"] for rule in config["routing"]["rules"][4:-1]] ==
         [link["egress"] for link in manifest["entries"]] and
         config["routing"]["rules"][-1]["outboundTag"] == "BLOCK",
         "PORTFOLIO_CONFIG_ROUTES")
    command([str(XRAY), "run", "-test", "-config", str(CONF)],
            step="XRAY_VERIFY", timeout=120)
    command(["systemctl", "is-active", "--quiet", UNIT_NAME],
            step="SERVICE_ACTIVE")
    command(["systemctl", "is-enabled", "--quiet", UNIT_NAME],
            step="SERVICE_ENABLED")
    user, group = pwd.getpwnam(ACCOUNT), grp.getgrnam(ACCOUNT)
    need(user.pw_uid == user.pw_gid == group.gr_gid == state["uid"] and
         user.pw_dir == "/nonexistent" and user.pw_shell == "/usr/sbin/nologin",
         "PORTFOLIO_ACCOUNT_DRIFT")
    properties = {key: command(["systemctl", "show", "-P", key, UNIT_NAME],
                               step="SERVICE_SHOW_" + key.upper())
                  .decode("utf-8").strip()
                  for key in ("User", "Group", "FragmentPath", "DropInPaths", "MainPID")}
    need(properties["User"] == properties["Group"] == ACCOUNT and
         properties["FragmentPath"] == str(UNIT) and
         properties["DropInPaths"] == "" and properties["MainPID"].isdecimal() and
         int(properties["MainPID"]) > 0, "PORTFOLIO_SERVICE_DRIFT")
    pid = int(properties["MainPID"])
    uids = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$",
                     (Path("/proc") / str(pid) / "status").read_text(), re.M)
    need(uids is not None and all(int(value) == state["uid"]
                                  for value in uids.groups()) and
         (Path("/proc") / str(pid) / "exe").resolve(strict=True) == XRAY,
         "PORTFOLIO_PROCESS_DRIFT")
    listeners = command(["ss", "-H", "-lntup"],
                        step="LISTENERS_VERIFY").decode("utf-8")
    for port, network in state["ports"].items():
        need(any(line.startswith(network + " ") and
                 line.split()[4] == info["TARGET_IPV4"] + ":" + port and
                 "pid=" + str(pid) + "," in line
                 for line in listeners.splitlines()), "PORTFOLIO_LISTENER")
    current_ufw = ufw_added()
    need(all(current_ufw.count(["ufw", *rule]) == 1
             for rule in rules_for(info, state["ports"])),
         "PORTFOLIO_FIREWALL")
    need(route_hashes() == state["routes_before"], "PORTFOLIO_ROUTE_DRIFT")
    return manifest


def rollback(info, state):
    need(state["phase"] == "pending", "PORTFOLIO_ROLLBACK_PHASE")
    need(same_target(info, state), "PORTFOLIO_ROLLBACK_TARGET_DRIFT")
    check_snapshot(Path(state["backup"]))
    if UNIT.exists():
        run_command(["systemctl", "disable", "--now", UNIT_NAME],
                    step="ROLLBACK_SERVICE_DISABLE", check=False, timeout=60)
        stopped = run_command(["systemctl", "is-active", "--quiet", UNIT_NAME],
                              step="ROLLBACK_SERVICE_STATUS", check=False,
                              timeout=15)
        need(stopped.returncode != 0, "PORTFOLIO_SERVICE_STOP")
    current = ufw_added()
    before = state["ufw_before"]
    for rule in reversed(rules_for(info, state["ports"])):
        exact = ["ufw", *rule]
        if exact in current:
            need(exact not in before, "PORTFOLIO_FOREIGN_RULE")
            need(current.count(exact) == 1, "PORTFOLIO_UFW_DUPLICATE")
            command(["ufw", "--force", "delete", *rule],
                    step="ROLLBACK_UFW_DELETE", timeout=30)
            current = ufw_added()
    for path, digest in ((UNIT, state["unit_sha256"]),
                         (HOOK, state["hook_sha256"]),
                         (CONF, state["config_sha256"]),
                         (LINKS, state["links_sha256"])):
        if path.exists():
            need(not path.is_symlink() and sha(path.read_bytes()) == digest,
                 "PORTFOLIO_ROLLBACK_CAS")
            path.unlink()
    if TLS_MARKER.exists() or TLS_MARKER.is_symlink():
        marker = private(TLS_MARKER)
        need(marker == (state["tls_initial_sha256"] + "\n").encode(),
             "PORTFOLIO_ROLLBACK_TLS_MARKER")
        TLS_MARKER.unlink()
    command(["systemctl", "daemon-reload"],
            step="ROLLBACK_DAEMON_RELOAD")
    if ACCOUNT in [entry.pw_name for entry in pwd.getpwall()]:
        need(pwd.getpwnam(ACCOUNT).pw_uid == state["uid"],
             "PORTFOLIO_ACCOUNT_DRIFT")
        command(["userdel", ACCOUNT], step="ROLLBACK_USER_DELETE")
    if ACCOUNT in [entry.gr_name for entry in grp.getgrall()]:
        need(grp.getgrnam(ACCOUNT).gr_gid == state["uid"],
             "PORTFOLIO_GROUP_DRIFT")
        command(["groupdel", ACCOUNT], step="ROLLBACK_GROUP_DELETE")
    need(route_hashes() == state["routes_before"], "PORTFOLIO_ROLLBACK_ROUTE")
    need(ufw_added() == before, "PORTFOLIO_ROLLBACK_UFW")
    need(set(ROOT.iterdir()) == {STATE}, "PORTFOLIO_ROLLBACK_ROOT")
    need(private(STATE) == canonical(state), "PORTFOLIO_ROLLBACK_STATE")
    STATE.unlink()
    ROOT.rmdir()


def compensate_after_failure(info, state, original):
    try:
        if STATE.exists() and state["phase"] == "pending":
            rollback(info, state)
        elif ROOT.exists() and not ROOT.is_symlink() and not any(ROOT.iterdir()):
            ROOT.rmdir()
    except BaseException as rollback_error:
        raise RollbackFailure(original, rollback_error) from None


def apply(info):
    rows = rows_for(info)
    prior = read_state()
    if prior and prior["phase"] == "committed":
        verify(info, prior)
        return
    if prior and prior["phase"] == "pending":
        rollback(info, prior)
    need(not ROOT.exists() and not ROOT.is_symlink() and
         not UNIT.exists() and not UNIT.is_symlink() and
         not HOOK.exists() and not HOOK.is_symlink(),
         "PORTFOLIO_ALREADY_PRESENT")
    need(ACCOUNT not in {item.pw_name for item in pwd.getpwall()} and
         ACCOUNT not in {item.gr_name for item in grp.getgrall()},
         "PORTFOLIO_ACCOUNT_PRESENT")
    need(BASELINE_DONE.is_file() and not BASELINE_DONE.is_symlink(),
         "PORTFOLIO_BASELINE_NOT_COMMITTED")
    need(sha(XRAY.read_bytes()) == XRAY_SHA256 and
         TLS_CERT.is_file() and TLS_KEY.is_file(), "PORTFOLIO_PINNED_BASE")
    tls_initial_sha256 = sha(TLS_CERT.read_bytes())
    main = json.loads(MAIN.read_bytes())
    config, manifest, networks = build(info, main, rows,
                                       shared_credentials, profile_credentials)
    ports = {str(port): network for port, network in sorted(networks.items())}
    need(not set(networks).intersection(occupied_ports()),
         "PORTFOLIO_PORT_BUSY")
    before_ufw = ufw_added()
    need(not ufw_port_conflict(before_ufw, ports),
         "PORTFOLIO_UFW_EXISTING")
    before_routes = route_hashes()
    backup = snapshot()
    config_raw, links_raw = canonical(config), canonical(manifest)
    unit_raw, hook_raw = unit_bytes(), hook_bytes(info)
    need(len(config_raw) <= 2 * 1024 * 1024 and
         len(links_raw) <= 2 * 1024 * 1024, "PORTFOLIO_SIZE")
    for name, raw in (("staged-config.json", config_raw),
                      ("staged-links.json", links_raw),
                      ("staged-unit", unit_raw), ("staged-hook", hook_raw)):
        write_new(backup / name, raw)
    command([str(XRAY), "run", "-test", "-config",
             str(backup / "staged-config.json")],
            step="XRAY_STAGED_PREFLIGHT", timeout=120)
    uid = free_identity()
    state = {"version": 1, "phase": "pending", "target": info["TARGET_IPV4"],
             "interface": info["TARGET_INTERFACE"],
             "profile_set": info["TARGET_PROFILE_SET"],
             "profile_ids": info.get("TARGET_PROFILE_IDS", ""),
             "egress_mode": info["TARGET_EGRESS_MODE"],
             "catalog_sha256": sha(CATALOG.read_bytes()),
             "profile_count": len(manifest["entries"]), "ports": ports,
             "backup": str(backup), "uid": uid,
             "config_sha256": sha(config_raw), "links_sha256": sha(links_raw),
             "unit_sha256": sha(unit_raw), "hook_sha256": sha(hook_raw),
             "tls_initial_sha256": tls_initial_sha256,
             "ufw_before": before_ufw, "routes_before": before_routes}
    if info.get("TARGET_PROFILE_ORDER", "legacy") != "legacy":
        state["profile_order"] = info["TARGET_PROFILE_ORDER"]
    try:
        ROOT.mkdir(mode=0o700)
        safe_directory(ROOT)
        write_state(state)
        command(["groupadd", "--system", "--gid", str(uid), ACCOUNT],
                step="GROUP_CREATE")
        command(["useradd", "--system", "--uid", str(uid), "--gid", str(uid),
                 "--no-create-home", "--home-dir", "/nonexistent",
                  "--shell", "/usr/sbin/nologin", ACCOUNT],
                step="USER_CREATE")
        write_new(CONF, config_raw)
        write_new(LINKS, links_raw)
        write_new(UNIT, unit_raw, 0o644)
        write_new(HOOK, hook_raw, 0o750)
        command(["bash", "-n", str(HOOK)], step="HOOK_SYNTAX")
        command(["systemd-analyze", "verify", str(UNIT)],
                step="UNIT_PREFLIGHT")
        command(["systemctl", "daemon-reload"], step="DAEMON_RELOAD")
        command(["systemctl", "enable", "--now", UNIT_NAME],
                step="SERVICE_START", timeout=90)
        command(["env", "RENEWED_LINEAGE=/etc/letsencrypt/live/" +
                 info.get("TARGET_CERT_NAME", info["TARGET_FQDN"]), "/bin/bash", str(HOOK)],
                step="RENEWAL_HOOK", timeout=180)
        for rule in rules_for(info, ports):
            command(["ufw", *rule], step="UFW_ADD", timeout=30)
        verify(info, state, allow_pending=True)
        state["phase"] = "committed"
        write_state(state)
        print("PORTFOLIO_SERVICE_COMMITTED=" + str(state["profile_count"]))
    except BaseException as original:
        compensate_after_failure(info, state, original)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--apply", action="store_true")
    group.add_argument("--verify", action="store_true")
    group.add_argument("--rollback-pending", action="store_true")
    args = parser.parse_args()
    need(os.geteuid() == 0, "PORTFOLIO_ROOT_REQUIRED")
    os.umask(0o077)
    info = target()
    if args.apply:
        apply(info)
    elif args.verify:
        state = read_state()
        need(state is not None, "PORTFOLIO_SERVICE_ABSENT")
        verify(info, state)
        print("PORTFOLIO_SERVICE_VERIFY_OK=" + str(state["profile_count"]))
    else:
        state = read_state()
        need(state is not None and state["phase"] == "pending",
             "PORTFOLIO_NO_PENDING")
        rollback(info, state)
        print("PORTFOLIO_PENDING_ROLLBACK_OK=1")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        report_failure(error)
        sys.exit(1)
