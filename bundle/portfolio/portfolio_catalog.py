"""Select the accepted protocol portfolio and generate subscription remarks.

The catalog contains public protocol recipes only. Server credentials, ports,
certificate paths and share links are supplied by the deployment runtime.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import sys
import unicodedata


CATALOG_PATH = Path(__file__).resolve().with_name("catalog.json")
PROFILE_SETS = ("basic", "dpi", "all", "custom")
EGRESS_MODES = ("warp", "direct", "both")
EGRESS_LABELS = {"warp": "☁️ Cloudflare", "direct": "🖥️ IP сервера"}
TIER_PRIORITY = {"A": 0, "B1": 1, "B2": 2, "C": 3, "D": 4, "E": 5}
# A balanced subset of the historical mobile-tested recipes, not a measured
# ranking or a guarantee against future filtering. Persist its explicit IDs
# through the existing custom selection contract.
TOP10_STEMS = (
    "hysteria2-tls-hysteria-salamander",
    "vless-reality-xhttp-auto",
    "vless-reality-xhttp-stream-up",
    "vless-reality-xhttp-packet-up",
    "trojan-reality-xhttp-auto",
    "trojan-reality-xhttp-packet-up",
    "vless-reality-xhttp-packet-up-mlkem",
    "vless-tls-xhttp-auto",
    "vless-tls-xhttp-packet-up",
    "vless-tls-xhttp-stream-one",
)
BASELINE_SUFFIXES = {
    "vless-reality-grpc-warp": "REALITY",
    "hysteria2-tls-hysteria-warp": "HYSTERIA2",
    "vless-reality-xhttp-packet-up-warp": "XHTTP",
    "vless-reality-grpc-direct": "REALITY",
    "hysteria2-tls-hysteria-direct": "HYSTERIA2",
    "vless-reality-xhttp-packet-up-direct": "XHTTP",
}
TRANSPORT_NAMES = {
    "tcp": "TCP",
    "ws": "WebSocket",
    "grpc": "gRPC",
    "httpupgrade": "HTTP Upgrade",
    "xhttp": "XHTTP",
    "hysteria": "UDP",
}
XHTTP_MODE_NAMES = {
    "auto": "AUTO",
    "packet-up": "PACKET-UP",
    "stream-up": "STREAM-UP",
    "stream-one": "STREAM-ONE",
}
CIPHER_NAMES = {
    "aes-128-gcm": "AES-128-GCM",
    "aes-256-gcm": "AES-256-GCM",
    "chacha20-poly1305": "CHACHA20-POLY1305",
    "chacha20-ietf-poly1305": "CHACHA20-IETF-POLY1305",
    "xchacha20-ietf-poly1305": "XCHACHA20-IETF-POLY1305",
    "2022-blake3-aes-128-gcm": "SS2022-AES-128-GCM",
    "2022-blake3-aes-256-gcm": "SS2022-AES-256-GCM",
    "2022-blake3-chacha20-poly1305": "SS2022-CHACHA20-POLY1305",
}


def load_catalog(path: Path = CATALOG_PATH) -> dict:
    """Load the reviewed, secret-free recipes without target-specific state."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported portfolio catalog schema")
    entries = data.get("entries")
    if not isinstance(entries, list) or len(entries) != 146:
        raise ValueError("Portfolio catalog must contain 146 accepted profiles")
    if [item["id"] for item in entries[:6]] != list(BASELINE_SUFFIXES):
        raise ValueError("Portfolio baseline order changed")
    if len({item["id"] for item in entries}) != len(entries):
        raise ValueError("Duplicate portfolio profile ID")
    return data


def _validate_label(target_label: str) -> str:
    if not isinstance(target_label, str) or not 1 <= len(target_label) <= 80:
        raise ValueError("TARGET_LABEL must be 1 to 80 characters")
    if not target_label.strip():
        raise ValueError("TARGET_LABEL must contain a name")
    if any(unicodedata.category(char) in {"Cc", "Zl", "Zp"} for char in target_label):
        raise ValueError("TARGET_LABEL contains a forbidden control character")
    return target_label


def profile_name(entry: dict, target_label: str) -> str:
    """Keep baseline names intact and describe each additional real variant."""
    target_label = _validate_label(target_label)
    egress = entry["egress"]
    if egress not in EGRESS_LABELS:
        raise ValueError("Unsupported egress")
    if entry["baseline_reuse"]:
        suffix = BASELINE_SUFFIXES[entry["id"]]
    else:
        pieces = [entry["protocol"].upper(), TRANSPORT_NAMES[entry["transport"]]]
        pieces.append({"tls": "TLS", "reality": "REALITY", "none": "PLAIN"}[entry["security"]])
        if entry["xhttp_mode"] is not None:
            pieces.append(XHTTP_MODE_NAMES[entry["xhttp_mode"]])
        if entry["encryption"] == "mlkem":
            pieces.append("ML-KEM")
        elif entry["encryption"] != "none":
            pieces.append(entry["encryption"].upper())
        if entry["flow"]:
            pieces.append("VISION" if entry["flow"] == "xtls-rprx-vision" else entry["flow"].upper())
        cipher = entry["cipher"]
        if cipher not in {"none", "auto", "mlkem", "salamander"}:
            pieces.append(CIPHER_NAMES[cipher])
        if entry["obfs"] != "none":
            pieces.append("SALAMANDER" if entry["obfs"] == "salamander" else entry["obfs"].upper())
        suffix = " ".join(pieces)
    return f"{target_label} · {EGRESS_LABELS[egress]} · {suffix}"


def is_public_native(row: dict, egress_mode: str) -> bool:
    """Whether this recipe is exported natively rather than as a public URI.

    The single direct exit owns its native clients. A WARP/both installation
    exports WARP gRPC/Hysteria natively and direct clients as external links.
    Promoted XHTTP is always external, including its baseline recipe.
    """
    if egress_mode not in EGRESS_MODES:
        raise ValueError(f"Unknown egress mode: {egress_mode}")
    native_role = "direct" if egress_mode == "direct" else "warp"
    return bool(row["baseline_reuse"] and row["egress"] == native_role and
                ((row["protocol"] == "vless" and row["transport"] == "grpc") or
                 row["protocol"] == "hysteria2"))


def select_profiles(profile_set: str, egress_mode: str, target_label: str,
                    profile_ids: str = "") -> list[dict]:
    """Return ordered recipes with unique names for the requested menu options.

    ``basic`` is the six original links. ``dpi`` includes tiers A–D and the
    original six (98 total). ``all`` includes all 146 accepted links. Egress
    filtering preserves that order. A custom URI-only selection preserves its
    explicit CSV order; native-containing selections retain the original order.
    The source observation was on Miranda;
    these selections do not claim future DPI resistance on other networks.
    """
    if profile_set not in PROFILE_SETS:
        raise ValueError(f"Unknown profile set: {profile_set}")
    if egress_mode not in EGRESS_MODES:
        raise ValueError(f"Unknown egress mode: {egress_mode}")
    _validate_label(target_label)
    requested = set()
    if profile_set == "custom":
        ids = profile_ids.split(",")
        requested = set(ids)
        if not profile_ids or "" in requested or len(requested) != len(ids):
            raise ValueError("Choose at least one unique profile")
    elif profile_ids:
        raise ValueError("Profile IDs are only valid for a custom set")
    result = []
    entries = load_catalog()["entries"]
    ordered = entries[:6] + sorted(entries[6:], key=lambda row: TIER_PRIORITY[row["tier"]])
    for entry in ordered:
        if profile_set == "basic" and not entry["baseline_reuse"]:
            continue
        if profile_set == "dpi" and entry["tier"] == "E":
            continue
        if egress_mode != "both" and entry["egress"] != egress_mode:
            continue
        if profile_set == "custom" and entry["id"] not in requested:
            continue
        row = copy.deepcopy(entry)
        row["name"] = profile_name(row, target_label)
        result.append(row)
    if profile_set == "custom" and requested != {row["id"] for row in result}:
        raise ValueError("A selected profile is unavailable for this egress")
    if profile_set == "custom" and not any(is_public_native(row, egress_mode) for row in result):
        by_id = {row["id"]: row for row in result}
        result = [by_id[profile_id] for profile_id in ids]
    if len({row["name"] for row in result}) != len(result):
        raise ValueError("Portfolio profile names are not unique")
    return result


def select_top10(egress: str, label: str = "VPN") -> list[dict]:
    """Resolve the preset's explicit priority, grouped by WARP/direct exit."""
    if egress not in EGRESS_MODES:
        raise ValueError(f"Unknown egress mode: {egress}")
    roles = ("warp", "direct") if egress == "both" else (egress,)
    ids = ",".join(f"{stem}-{role}" for role in roles for stem in TOP10_STEMS)
    return select_profiles("custom", egress, label, ids)


def select_numbers(egress_mode: str, selection: str) -> list[dict]:
    """Resolve numbers and inclusive ranges against the displayed menu."""
    rows = select_profiles("all", egress_mode, "VPN")
    chosen = set()
    for token in re.split(r"\s*,\s*|\s+", selection.strip()):
        match = re.fullmatch(r"([1-9][0-9]{0,2})(?:-([1-9][0-9]{0,2}))?", token)
        if not match:
            raise ValueError("Use profile numbers or inclusive ranges")
        start = int(match[1])
        stop = int(match[2]) if match[2] else start
        if not start <= stop <= len(rows):
            raise ValueError("Profile number or range is outside the menu")
        indices = set(range(start, stop + 1))
        if chosen & indices:
            raise ValueError("A profile is selected more than once")
        chosen.update(indices)
    return [row for number, row in enumerate(rows, 1) if number in chosen]


def write_selection(rows: list[dict], output) -> None:
    roles = {row["egress"] for row in rows}
    mode = "both" if len(roles) == 2 else roles.pop()
    print(mode, ",".join(row["id"] for row in rows), len(rows), file=output)


def checklist(egress_mode: str) -> int:
    """Draw on the terminal and return the saved selection through fd 3."""
    try:
        import curses
        import locale

        if not sys.stdin.isatty() or not sys.stdout.isatty():
            return 69
        locale.setlocale(locale.LC_ALL, "")
        curses.setupterm(fd=sys.stdout.fileno())
        if not curses.tigetstr("cup") or not curses.tigetstr("clear"):
            return 69
    except ImportError:
        return 69
    except (curses.error, locale.Error):
        return 69

    rows = select_profiles("all", egress_mode, "VPN")

    def choose(screen):
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        cursor = first = 0
        checked = set()
        notice = ""
        while True:
            height, width = screen.getmaxyx()
            screen.erase()
            compact = height < 7 or width < 24
            visible = max(1, height - 5)
            if compact:
                if height > 0 and width > 1:
                    screen.addstr(0, 0, "Увеличьте окно или Esc."[:width - 1])
            else:
                first = min(first, max(0, len(rows) - visible))
                if cursor < first:
                    first = cursor
                elif cursor >= first + visible:
                    first = cursor - visible + 1
                end = min(first + visible, len(rows))

                def line(y, text, attr=0):
                    screen.addstr(y, 0, text[:width - 1], attr)

                line(0, "Выберите профили", curses.A_BOLD)
                line(1, "↑/↓ — курсор   Пробел — отметить   PgUp/PgDn — листать")
                line(2, "Enter — подтвердить   Esc — отменить")
                line(3, f"Отмечено: {len(checked)} из {len(rows)}   Строки {first + 1}–{end}")
                for index in range(first, end):
                    row = rows[index]
                    marker = "x" if index in checked else " "
                    egress = "WARP" if row["egress"] == "warp" else "IP"
                    name = row["name"].rsplit(" · ", 1)[-1]
                    attr = curses.A_REVERSE if index == cursor else 0
                    line(index - first + 4, f"[{marker}] {egress:4}  {name}", attr)
                line(height - 1, notice, curses.A_BOLD)
            screen.refresh()

            key = screen.getch()
            if key in (-1, 4, 27):
                return None
            if compact:
                continue
            moves = {curses.KEY_UP: -1, curses.KEY_DOWN: 1,
                     curses.KEY_PPAGE: -visible, curses.KEY_NPAGE: visible}
            if key in moves:
                cursor = max(0, min(len(rows) - 1, cursor + moves[key]))
            elif key == curses.KEY_HOME:
                cursor = 0
            elif key == curses.KEY_END:
                cursor = len(rows) - 1
            elif key == ord(" "):
                checked.symmetric_difference_update({cursor})
                notice = ""
            elif key in (10, 13, curses.KEY_ENTER):
                if checked:
                    return [rows[index] for index in sorted(checked)]
                notice = "Отметьте хотя бы один профиль."

    try:
        selected = curses.wrapper(choose)
    except KeyboardInterrupt:
        return 1
    if selected is None:
        return 1
    with os.fdopen(3, "w", encoding="utf-8") as output:
        write_selection(selected, output)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--set", dest="profile_set", choices=PROFILE_SETS)
    action.add_argument("--preset", choices=("top10",))
    action.add_argument("--menu", action="store_true")
    action.add_argument("--choose")
    action.add_argument("--checklist", action="store_true")
    parser.add_argument("--egress", choices=EGRESS_MODES, required=True)
    parser.add_argument("--label", default=os.environ.get("TARGET_LABEL"))
    parser.add_argument("--ids", default=os.environ.get("TARGET_PROFILE_IDS", ""))
    parser.add_argument("--counts", action="store_true")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        if args.menu:
            for number, row in enumerate(select_profiles("all", args.egress, "VPN"), 1):
                print(f"  {number:3}. {row['name'].removeprefix('VPN · ')}")
        elif args.choose is not None:
            write_selection(select_numbers(args.egress, args.choose), sys.stdout)
        elif args.preset == "top10":
            label = args.label if args.label is not None else "VPN"
            write_selection(select_top10(args.egress, label), sys.stdout)
        elif args.checklist:
            return checklist(args.egress)
        else:
            if args.label is None:
                parser.error("--label or TARGET_LABEL is required")
            rows = select_profiles(args.profile_set, args.egress, args.label, args.ids)
            if args.counts:
                print(len(rows), sum(not row["baseline_reuse"] for row in rows))
            else:
                json.dump(rows, sys.stdout, ensure_ascii=False, separators=(",", ":"))
                sys.stdout.write("\n")
    except (KeyError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
