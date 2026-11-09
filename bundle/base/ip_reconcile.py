"""Reconcile the public IPv4s of a completed IP-mode installer deployment."""
import base64
from contextlib import closing, contextmanager
from dataclasses import asdict
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote, urlsplit

from ip_addresses import discover, public_ipv4
from ip_certificate import LE_ROOT, issue, validate
from ip_feed import rewrite_feed
from ip_network import TABLE, fetch_feed, nginx_aliases, nft_rules, rebind_url, uri_lines
from ip_runtime import CellEdit, edit_rows, plan_runtime


STATE = Path("/var/lib/vpn-installer")
SOURCE = Path("/opt/vpn-installer")
BUNDLE = STATE / "bundle"
ROOT = Path("/etc/vpn-ip-addresses")
TARGET = Path("/etc/germanyvpn-target.env")
ACCESS = Path("/etc/krysyuk-standalone/access.env")
DB = Path("/etc/x-ui/x-ui.db")
MAIN = Path("/usr/local/x-ui/bin/config.json")
TLS = ACCESS.parent / "tls"
TLS_MARKER = ACCESS.parent / "tls-deployed.sha256"
PANEL = Path("/etc/nginx/conf.d/3x-ui-public.conf")
ALIASES = PANEL.with_name("vpn-ip-subscription.conf")
DROPIN = Path("/etc/systemd/system/certbot.service.d/30-vpn-active-ip.conf")
UFW = Path("/etc/ufw/user.rules")
PORTFOLIO = Path("/etc/germanyvpn-portfolio/state.json")
WARP_ROUTES = Path("/var/lib/krysyuk-warp-egress/main-routing.baseline")
PENDING = ROOT / "pending"
IP_TIMERS = ("certbot.timer", "vpn-cert-reconcile.timer")
BASE_UNITS = ("x-ui.service", "germanyvpn-xhttp-test.service")
WARP_UNITS = ("krysyuk-xray-warp-egress.service", "germanyvpn-xhttp-warp.service")
SOURCE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}


def run(*args, timeout=60, env=None):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env=env or SOURCE_ENV, timeout=timeout)
    if result.returncode:
        raise RuntimeError("IP_COMMAND_" + Path(args[0]).name.upper().replace("-", "_"))
    return result.stdout


def ctl(*args):
    run("systemctl", *args, timeout=150)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return base64.b64encode(value).decode("ascii")


def decode(value):
    return base64.b64decode(value, validate=True)


def sync_dir(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, value, mode=0o600, uid=0, gid=0):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".vpn-ip-", delete=False) as stream:
        staged = Path(stream.name)
        try:
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(staged, path)
            sync_dir(path.parent)
        finally:
            staged.unlink(missing_ok=True)


def state(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if path == TLS and stat.S_ISLNK(info.st_mode) and info.st_uid == 0:
        target = os.readlink(path)
        if re.fullmatch(r"tls-gen\.[A-Za-z0-9]+", target):
            return {"link": target}
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or
            info.st_uid not in (0, pwd.getpwnam("xui").pw_uid)):
        raise RuntimeError("IP_UNSAFE_MANAGED_FILE")
    return {"data": encode(path.read_bytes()), "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid, "gid": info.st_gid}


def publish(path, value):
    if value is None:
        path.unlink(missing_ok=True)
        sync_dir(path.parent)
    elif "link" in value:
        with tempfile.TemporaryDirectory(dir=path.parent) as stage:
            staged = Path(stage) / "tls"
            staged.symlink_to(value["link"])
            os.replace(staged, path)
            sync_dir(path.parent)
    else:
        atomic(path, decode(value["data"]), value["mode"], value["uid"], value["gid"])


class Journal:
    def __init__(self, directory, record):
        self.directory = directory
        self.record = record

    def save(self):
        atomic(self.directory / "journal.json", json.dumps(self.record).encode())

    def change(self, path, value, mode=0o600):
        before = state(path)
        if isinstance(value, bytes):
            after = {**(before or {"mode": mode, "uid": 0, "gid": 0}), "data": encode(value)}
        else:
            after = value
        if before == after:
            return
        self.record["files"].append([str(path), before, after])
        self.save()
        if state(path) != before:
            raise RuntimeError("IP_FILE_CONCURRENT_WRITE")
        publish(path, after)

    def rollback_files(self):
        for raw, before, after in reversed(self.record["files"]):
            path = Path(raw)
            actual = state(path)
            if actual == before:
                continue
            if actual != after:
                raise RuntimeError("IP_FILE_CONCURRENT_WRITE")
            publish(path, before)


def env_file(path):
    saved = state(path)
    if saved is None or saved["mode"] != 0o600 or saved["uid"] != 0 or saved["gid"] != 0:
        raise RuntimeError("IP_UNSAFE_ENV")
    result = {}
    for line in decode(saved["data"]).decode("utf-8").splitlines():
        key, _, value = line.partition("=")
        values = shlex.split(value)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in result or len(values) != 1:
            raise RuntimeError("IP_INVALID_ENV")
        result[key] = values[0]
    return result


def serialize(env):
    return "".join(f"{key}={shlex.quote(value)}\n" for key, value in env.items()).encode()


def replace_address(raw, old, new):
    pattern = rb"(?<![0-9.])" + re.escape(old.encode("ascii")) + rb"(?![0-9.])"
    return re.sub(pattern, new.encode("ascii"), raw)


def ports_for(target):
    ports = {(443, "tcp"), (443, "udp"), (8444, "tcp")}
    if target["TARGET_EGRESS_MODE"] != "direct":
        ports.add((8443, "tcp"))
    if target["TARGET_PROFILE_SET"] != "basic":
        portfolio = json.loads(PORTFOLIO.read_bytes())
        for key, proto in portfolio["ports"].items():
            port = int(key)
            if not 30000 <= port <= 30126 or proto not in ("tcp", "udp"):
                raise RuntimeError("IP_PORTFOLIO_PORT")
            ports.add((port, proto))
    return ports


def validate_firewall(target, status):
    spec = importlib.util.spec_from_file_location("vpn_ip_network_contract",
                                                 BUNDLE / "scripts/network-contract.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    portfolio_ports = json.loads(PORTFOLIO.read_bytes())["ports"] if PORTFOLIO.exists() else {}
    module.validate_ufw(status.decode("ascii"), target["TARGET_IPV4"], target["TARGET_INTERFACE"],
                        target["TARGET_SSH_PORT"], True, Path("/etc/default/ufw").read_text(),
                        portfolio_ports=portfolio_ports, egress_mode=target["TARGET_EGRESS_MODE"])


def portfolio_routes():
    return {"ip4_route": run("ip", "-4", "route", "show", "table", "all"),
            "ip6_route": run("ip", "-6", "route", "show", "table", "all"),
            "ip4_rule": run("ip", "-4", "rule", "show"),
            "ip6_rule": run("ip", "-6", "rule", "show")}


def without_warp_link(routes):
    # After a reboot with a changed IP, the managed WARP veth may be created
    # during recovery. All host routes outside that exact veth must match.
    return {key: [line for line in raw.splitlines()
                  if not (key.endswith("_route") and re.search(rb"\bdev kw-host(?: |$)", line))]
            for key, raw in routes.items()}


def certificate_pointer(lineage):
    folder = TLS.parent / ("tls-gen." + secrets.token_hex(8))
    folder.mkdir(mode=0o700)
    gid = grp.getgrnam("xui-secrets").gr_gid
    os.chown(folder, 0, gid)
    folder.chmod(0o750)
    for name in ("fullchain.pem", "privkey.pem"):
        atomic(folder / name, (lineage / name).read_bytes(), 0o640, 0, gid)
    return {"link": folder.name}


def snapshot_database(path):
    with closing(sqlite3.connect(":memory:")) as snapshot:
        with as_xui(), closing(sqlite3.connect(f"file:{DB}?mode=ro", uri=True)) as original:
            original.backup(snapshot)
        with closing(sqlite3.connect(path)) as saved:
            snapshot.backup(saved)
            if saved.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise RuntimeError("IP_DATABASE_BACKUP")
    if path.stat().st_size == 0:
        raise RuntimeError("IP_DATABASE_BACKUP")


@contextmanager
def as_xui():
    owner = pwd.getpwnam("xui")
    os.setegid(owner.pw_gid)
    os.seteuid(owner.pw_uid)
    try:
        yield
    finally:
        os.seteuid(0)
        os.setegid(0)


def database(edits, restore=False):
    with as_xui(), closing(sqlite3.connect(f"file:{DB}?mode=rw", uri=True)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        edit_rows(db, edits, restore=restore)
        if db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise RuntimeError("IP_DATABASE_CHECK")


def services(target):
    units = list(BASE_UNITS)
    timers = list(IP_TIMERS)
    if target["TARGET_EGRESS_MODE"] != "direct":
        units = [*WARP_UNITS, *units]
        timers.append("krysyuk-warp-health.timer")
    if target["TARGET_PROFILE_SET"] != "basic":
        units.append("germanyvpn-portfolio.service")
    return units, timers


def quiesce(timers):
    ctl("stop", *timers)
    for unit in timers:
        worker = unit.removesuffix(".timer") + ".service"
        deadline = time.monotonic() + 120
        while run("systemctl", "show", "-p", "MainPID", "--value", worker).strip() != b"0":
            if time.monotonic() >= deadline:
                raise RuntimeError("IP_TIMER_WORKER_BUSY")
            time.sleep(1)


def activate(units, timers, panel=True):
    ctl("daemon-reload")
    run("ufw", "reload")
    ctl("restart", "vpn-ip-feed.service")
    ctl("restart", "vpn-ip-aliases.service")
    ctl("start", *units)
    if panel:
        run("nginx", "-t")
        ctl("start", "nginx.service")
    ctl("start", *timers)


def verify_feeds(primary, aliases, path):
    for ua in ("Happ", "v2RayTun", "Karing"):
        body, headers = fetch_feed(primary, path, ua)
        if ua == "Happ":
            primary_links = uri_lines(body)
        for address in aliases:
            actual, alias_headers = fetch_feed(address, path, ua)
            if uri_lines(actual) != uri_lines(rewrite_feed(body, primary, address)):
                raise RuntimeError("IP_ALIAS_SUBSCRIPTION")
            for header in ("routing", "routing-enable"):
                if alias_headers.get(header) != headers.get(header):
                    raise RuntimeError("IP_ALIAS_METADATA")
    return primary_links


def verify_alias_payloads(primary, aliases, path, ports, target):
    if not aliases:
        return
    spec = importlib.util.spec_from_file_location("vpn_ip_payload",
                                                 BUNDLE / "scripts/finalize-xhttp.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    expected = {}
    classes = (("warp", "☁️ Cloudflare"), ("direct", "🖥️ IP сервера"))
    for egress, suffix in classes:
        if target["TARGET_EGRESS_MODE"] in (egress, "both"):
            for protocol in ("REALITY", "HYSTERIA2", "XHTTP"):
                expected[f"{target['TARGET_LABEL']} · {suffix} · {protocol}"] = egress == "warp"
    for address in aliases:
        # Test every translated TCP port and the actual baseline transports,
        # including a real QUIC handshake for the translated UDP/443 port.
        for port, protocol in ports:
            if protocol == "tcp":
                with socket.create_connection((address, port), timeout=3):
                    pass
        links, _headers = fetch_feed(address, path, "Happ")
        baseline = {}
        for uri in uri_lines(links):
            label = unquote(urlsplit(uri).fragment)
            if label in expected:
                baseline[label] = uri
        if set(baseline) != set(expected):
            raise RuntimeError("IP_ALIAS_BASELINE")
        for label, uri in baseline.items():
            module.payload(uri, expected[label], primary)


def verify_current():
    target = env_file(TARGET)
    primary = target["TARGET_IPV4"]
    aliases = target.get("TARGET_ADDITIONAL_IPV4", "").split()
    validate(target.get("TARGET_CERT_NAME", primary), [primary, *aliases])
    for unit in ("vpn-ip-address.timer", "vpn-ip-feed.service", "vpn-ip-aliases.service"):
        ctl("is-active", "--quiet", unit)
        ctl("is-enabled", "--quiet", unit)
    run("nft", "-s", "list", "table", "ip", TABLE)
    path = urlsplit(env_file(ACCESS)["SUBSCRIPTION_URL"]).path
    verify_feeds(primary, aliases, path)


def render_bundle(journal, target):
    # Render from immutable installer source, never by blind replacement in
    # the previous bundle (which may itself contain the new IP in a fixture).
    with tempfile.TemporaryDirectory(dir="/run", prefix="vpn-ip-render-") as tmp:
        rendered = Path(tmp)
        run("cp", "-a", str(SOURCE / "bundle") + "/.", str(rendered))
        run("python3", "-I", "-B", str(SOURCE / "tools/render.py"), str(rendered),
            env={**SOURCE_ENV, **target})
        for path in rendered.rglob("*"):
            if path.is_file():
                journal.change(BUNDLE / path.relative_to(rendered), path.read_bytes(),
                               stat.S_IMODE(path.stat().st_mode))


def complete(journal, mark=False):
    if mark:
        journal.record["committed"] = True
        journal.save()
    PENDING.unlink()
    sync_dir(ROOT)


def rollback(journal):
    units, timers = journal.record["units"], journal.record["timers"]
    if not journal.record["applying"]:
        ctl("start", *timers)
        complete(journal)
        return
    quiesce(timers)
    ctl("stop", "nginx.service", *units)
    journal.rollback_files()
    edits = [CellEdit(**item) for item in journal.record["database"]]
    if edits:
        database(edits, restore=True)
    try:
        assigned = set(discover(journal.record["old"])["addresses"])
    except ValueError:
        assigned = set()
    if journal.record["old"] in assigned:
        activate(units, timers, panel=set(journal.record["previous"]) <= assigned)
    else:
        # The provider may already have withdrawn the old address. Preserve
        # the previous configuration and allow the next run to retry the new IP.
        ctl("daemon-reload")
        run("ufw", "reload")
        ctl("restart", "vpn-ip-aliases.service")
        ctl("start", *timers)
    complete(journal)


def open_journal():
    saved = state(PENDING)
    if saved is None:
        return None
    name = decode(saved["data"]).decode("ascii").strip()
    if not re.fullmatch(r"vpn-ip-[A-Za-z0-9_]+", name):
        raise RuntimeError("IP_JOURNAL_POINTER")
    directory = Path("/var/backups") / name
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("IP_JOURNAL_DIRECTORY")
    record = state(directory / "journal.json")
    return Journal(directory, json.loads(decode(record["data"])))


def reconcile():
    journal = open_journal()
    if journal:
        if journal.record.get("committed"):
            complete(journal)
        else:
            rollback(journal)
    target = env_file(TARGET)
    if target["TARGET_ADDRESS_MODE"] != "ip" or target["TARGET_TLS_MODE"] != "letsencrypt":
        return
    old = public_ipv4(target["TARGET_IPV4"])
    current = discover()
    primary, addresses = current["primary"], current["addresses"]
    interface = target["TARGET_INTERFACE"]
    if any(dev != interface for dev in current["interfaces"].values()):
        raise RuntimeError("IP_ADDRESS_INTERFACE")
    aliases = [ip for ip in addresses if ip != primary]
    previous = [old, *target.get("TARGET_ADDITIONAL_IPV4", "").split()]
    if set(addresses) == set(previous) and primary == old:
        print("IP_ADDRESS_UNCHANGED=1")
        return

    units, timers = services(target)
    directory = Path(tempfile.mkdtemp(prefix="vpn-ip-", dir="/var/backups"))
    transaction = Journal(directory, {"previous": previous, "old": old, "units": units,
                                      "timers": timers, "database": [], "files": [], "applying": False})
    transaction.save()
    atomic(PENDING, (directory.name + "\n").encode())
    try:
        quiesce(timers)
        name = issue(addresses, target["ACME_EMAIL"])
        validate(name, addresses)
        lineage = LE_ROOT / "live" / name
        snapshot_database(directory / "x-ui.db")
        plan = plan_runtime(Path("/"), old, primary, addresses, interface, interface,
                            previous_addresses=previous, lineage=str(lineage),
                            database_path=directory / "x-ui.db")
        access = env_file(ACCESS)
        access["PANEL_URL"] = rebind_url(access["PANEL_URL"], old, primary, 2053)
        access["SUBSCRIPTION_URL"] = rebind_url(access["SUBSCRIPTION_URL"], old, primary, 2096)
        path = urlsplit(access["SUBSCRIPTION_URL"]).path
        route_command = BUNDLE / "warp-egress/scripts/capture-main-routing.sh"
        routes = run("bash", str(route_command)) if WARP_ROUTES.exists() else None
        atomic(directory / "nft-before.txt", run("nft", "-s", "list", "ruleset"))
        firewall = run("ufw", "status", "verbose")
        validate_firewall(target, firewall)
        atomic(directory / "ufw-before.txt", firewall)
        before_routes = portfolio_routes() if PORTFOLIO in plan.files else None
        if before_routes is not None:
            portfolio = json.loads(plan.files[PORTFOLIO])
            portfolio["ufw_before"] = [[primary if word == old else word for word in line]
                                      for line in portfolio["ufw_before"]]
            plan.files[PORTFOLIO] = json.dumps(portfolio, ensure_ascii=False,
                                               sort_keys=True, separators=(",", ":")).encode()
        ports = ports_for(target)
        expected = nft_rules(primary, aliases, interface, ports)
        atomic(directory / "aliases.nft", expected)
        run("nft", "-c", "-f", str(directory / "aliases.nft"))
        for number, (config, data) in enumerate(plan.xray_configs.items()):
            candidate = directory / f"xray-{number}.json"
            atomic(candidate, data)
            if config == MAIN:
                binary = MAIN.parent / "xray-linux-amd64"
                assets = binary.parent
            elif config.is_relative_to(Path("/run/krysyuk-warp-egress")):
                binary = Path("/opt/krysyuk-warp-egress/bin/xray")
                assets = binary.parent.parent / "share"
            else:
                binary = Path("/usr/local/lib/germanyvpn-xhttp-test/xray")
                assets = binary.parent
            run(str(binary), "run", "-test", "-config", str(candidate),
                env={**SOURCE_ENV, "XRAY_LOCATION_ASSET": str(assets)})
        transaction.record["database"] = [asdict(edit) for edit in plan.database]
        transaction.record["applying"] = True
        transaction.save()
        # The previous nginx alias may become the new native 3x-ui listener.
        # Close it before starting x-ui to avoid a bind collision.
        ctl("stop", "nginx.service", *units)
        if plan.database:
            database(plan.database)
        for file, content in plan.files.items():
            transaction.change(file, content)
        target.update(TARGET_IPV4=primary, TARGET_FQDN=primary, TARGET_CERT_NAME=name,
                      TARGET_ADDITIONAL_IPV4=" ".join(aliases))
        transaction.change(TARGET, serialize(target))
        transaction.change(ACCESS, serialize(access))
        transaction.change(PANEL, replace_address(PANEL.read_bytes(), old, primary))
        transaction.change(UFW, replace_address(UFW.read_bytes(), old, primary))
        transaction.change(ROOT / "proxy.json", json.dumps(current).encode(), 0o644)
        transaction.change(ROOT / "aliases.nft", expected)
        transaction.change(ALIASES, nginx_aliases(aliases, access["SUBSCRIPTION_URL"]), 0o600)
        transaction.change(DROPIN, ("[Service]\nExecStart=\nExecStart=/opt/vpn-certbot/bin/certbot "
                                    f"-q renew --cert-name {name}\n").encode(), 0o644)
        transaction.change(TLS, certificate_pointer(lineage))
        certificate_hash = (digest((lineage / "fullchain.pem").read_bytes()) + "\n").encode()
        transaction.change(TLS_MARKER, certificate_hash)
        if before_routes is not None:
            transaction.change(PORTFOLIO.with_name("tls-deployed.sha256"), certificate_hash)
        if routes is not None:
            transaction.change(WARP_ROUTES, routes)
        if old != primary:
            render_bundle(transaction, target)
        activate(units, timers)
        for attempt in range(20):
            try:
                uris = verify_feeds(primary, aliases, path)
                break
            except (OSError, ValueError):
                if attempt == 19:
                    raise
                time.sleep(1)
        for file, content in plan.final_files(MAIN.read_bytes(), uris).items():
            transaction.change(file, content)
        verify_alias_payloads(primary, aliases, path, ports, target)
        if routes is not None and run("bash", str(route_command)) != routes:
            raise RuntimeError("IP_DEFAULT_ROUTE_CHANGED")
        if before_routes is not None:
            after_routes = portfolio_routes()
            if without_warp_link(after_routes) != without_warp_link(before_routes):
                raise RuntimeError("IP_PORTFOLIO_ROUTES_CHANGED")
            portfolio["routes_before"] = {key: digest(value) for key, value in after_routes.items()}
            transaction.change(PORTFOLIO, json.dumps(portfolio, ensure_ascii=False, sort_keys=True,
                                                     separators=(",", ":")).encode())
        run("bash", str(SOURCE / "tools/verify.sh"), timeout=600)
        if discover() != current:
            raise RuntimeError("IP_ADDRESS_SET_CHANGED")
        complete(transaction, mark=True)
        print(f"IP_ADDRESS_RECONCILED=1 PRIMARY={primary} IPV4_COUNT={len(addresses)}")
    except BaseException:
        if PENDING.exists() and not transaction.record.get("committed"):
            rollback(transaction)
        raise


def cancelled(_signal, _frame):
    raise RuntimeError("IP_RECONCILE_INTERRUPTED")


def main():
    os.umask(0o077)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, cancelled)
    try:
        if sys.argv[1:] == ["--check"]:
            verify_current()
            return 0
        if sys.argv[1:]:
            return 2
        with open("/run/vpn-installer.lock", "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return 0
            reconcile()
    except Exception as error:
        # Errors from third-party libraries can contain URLs or DB values.
        reason = str(error) if re.fullmatch(r"IP_[A-Z0-9_]+", str(error)) else type(error).__name__
        print(f"VPN_ERROR_CODE=IP_RECONCILE REASON={reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
