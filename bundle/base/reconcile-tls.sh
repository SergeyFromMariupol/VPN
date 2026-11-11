#!/usr/bin/env bash
# Retry both TLS consumers after Certbot has renewed the managed lineage.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1
bundle=/var/lib/vpn-installer/bundle
source "$bundle/scripts/target-contract.sh"
[[ $TARGET_TLS_MODE == letsencrypt ]] || exit 1
hook60=/etc/letsencrypt/renewal-hooks/deploy/60-krysyuk-standalone-xui
hook80=/etc/letsencrypt/renewal-hooks/deploy/80-germanyvpn-portfolio
portfolio_root=/etc/germanyvpn-portfolio
portfolio_state=$portfolio_root/state.json
lineage="/etc/letsencrypt/live/${TARGET_CERT_NAME:-$TARGET_FQDN}"
case ${TARGET_REALITY_MODE:-external} in
  self-steal|decoy)
    hook55=/etc/letsencrypt/renewal-hooks/deploy/55-vpn-reality-decoy
    [[ -f $hook55 && ! -L $hook55 &&
       $(stat -c '%u:%g:%a:%h' "$hook55") == 0:0:755:1 ]] || exit 1
    RENEWED_LINEAGE="$lineage" bash "$hook55"
    ;;
esac
[[ -f $hook60 && ! -L $hook60 &&
   $(stat -c '%u:%g:%a:%h' "$hook60") == 0:0:750:1 ]] || exit 1
RENEWED_LINEAGE="$lineage" bash "$hook60"
if [[ $TARGET_PROFILE_SET == custom ]]; then
  ((TARGET_EXTRA_PROFILE_COUNT > 0)) || exit 0
else
  [[ $TARGET_PROFILE_SET != basic ]] || exit 0
fi
if [[ ! -e $portfolio_root && ! -L $portfolio_root ]]; then exit 0; fi
[[ -d $portfolio_root && ! -L $portfolio_root &&
   $(stat -c '%u:%g:%a' "$portfolio_root") == 0:0:700 ]] || exit 1
if [[ ! -e $portfolio_state && ! -L $portfolio_state ]]; then exit 0; fi
[[ -f $portfolio_state && ! -L $portfolio_state &&
   $(stat -c '%u:%g:%a:%h' "$portfolio_state") == 0:0:600:1 ]] || exit 1
phase=$(python3 -I -B - "$portfolio_state" "$TARGET_IPV4" \
  "$TARGET_PROFILE_SET" "$TARGET_EGRESS_MODE" "${TARGET_PROFILE_IDS:-}" <<'PY'
import json
import sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_bytes())
if (state.get('target') != sys.argv[2] or
        state.get('profile_set') != sys.argv[3] or
        state.get('egress_mode') != sys.argv[4] or
        state.get('profile_ids', '') != sys.argv[5] or
        state.get('phase') not in ('pending', 'committed')):
    raise SystemExit(1)
print(state['phase'])
PY
)
[[ $phase == committed ]] || exit 0
[[ -f $hook80 && ! -L $hook80 &&
   $(stat -c '%u:%g:%a:%h' "$hook80") == 0:0:750:1 ]] || exit 1
RENEWED_LINEAGE="$lineage" bash "$hook80"
