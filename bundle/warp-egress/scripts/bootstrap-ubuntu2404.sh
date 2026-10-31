#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly script_dir
bundle_root=$(cd -- "$script_dir/.." && pwd -P)
readonly bundle_root
# shellcheck source=../VERSION.env
source "$bundle_root/VERSION.env"
# shellcheck source=phase-state.sh
source "$script_dir/phase-state.sh"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $(id -u) -eq 0 ]] || die 'run as root'
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || \
  die "Ubuntu 24.04 is required; found ${ID:-unknown} ${VERSION_ID:-unknown}"
[[ $(dpkg --print-architecture) == amd64 ]] || die 'this bundle supports amd64 only'

# shellcheck source=bootstrap-transaction.sh
source "$script_dir/bootstrap-transaction.sh"
# Shared output: bootstrap_transaction_begin assigns the private staging path.
stage=''
bootstrap_transaction_begin
export DEBIAN_FRONTEND=noninteractive
apt-get update
bootstrap_apt_install \
  ca-certificates curl dnsutils gnupg iproute2 jq nftables python3-minimal \
  shellcheck systemd tcpdump ufw unzip

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 2 --connect-timeout 15 --max-time 300 \
  https://pkg.cloudflareclient.com/pubkey.gpg --output "$stage/cloudflare.gpg"
install -d -o root -g root -m 0755 \
  /usr/share/keyrings /etc/apt/sources.list.d /etc/apt/preferences.d
gpg --batch --yes --dearmor \
  --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
  "$stage/cloudflare.gpg"
chmod 0644 /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
printf '%s\n' \
  'deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ noble main' \
  >/etc/apt/sources.list.d/cloudflare-client.list
chmod 0644 /etc/apt/sources.list.d/cloudflare-client.list
install -o root -g root -m 0644 \
  "$bundle_root/config/90-krysyuk-cloudflare-warp.pref" \
  /etc/apt/preferences.d/90-krysyuk-cloudflare-warp

apt-get update
# The official package index may retire the audited version while retaining
# its immutable pool artifact. Fetch only that exact official artifact and
# verify the bundle-pinned digest before exposing it to the package manager.
[[ "$WARP_DEB_URL" == "https://pkg.cloudflareclient.com/pool/noble/main/c/cloudflare-warp/cloudflare-warp_${WARP_VERSION}_amd64.deb" ]] || \
  die 'Cloudflare WARP package URL does not match the pinned official artifact'
warp_deb="$stage/cloudflare-warp_${WARP_VERSION}_amd64.deb"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 2 --connect-timeout 15 --max-time 300 \
  "$WARP_DEB_URL" --output "$warp_deb"
warp_deb_sha=$(sha256sum "$warp_deb" | awk '{print $1}')
[[ ${warp_deb_sha,,} == "$WARP_DEB_SHA256" ]] || \
  die 'pinned Cloudflare WARP package SHA-256 mismatch'
bootstrap_apt_install "$warp_deb"
warp_version=$(dpkg-query -W -f='${Version}' cloudflare-warp)
[[ "$warp_version" == "$WARP_VERSION" ]] || \
  die "cloudflare-warp must be exactly ${WARP_VERSION} for this audited bundle"
candidate=$(apt-cache policy cloudflare-warp \
  | awk '/Candidate:/ && !found {print $2; found=1}')
[[ "$candidate" == "$WARP_VERSION" ]] || \
  die 'Cloudflare WARP apt preference did not retain the installed audited version'
apt-mark hold cloudflare-warp >/dev/null
apt-mark showhold | grep -Fxq cloudflare-warp || \
  die 'could not hold Cloudflare WARP at the audited version'
systemctl disable --now warp-svc.service >/dev/null 2>&1 || true
[[ $(systemctl is-enabled warp-svc.service 2>/dev/null || true) == masked ]] || \
  die 'host WARP service was unexpectedly unmasked during package installation'
[[ -x /usr/lib/systemd/systemd-socket-proxyd ]] || \
  die 'systemd-socket-proxyd is missing'

release_base="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 2 --connect-timeout 15 --max-time 300 \
  "${release_base}/${XRAY_RELEASE_ARCHIVE}" --output "$stage/xray.zip"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 2 --connect-timeout 15 --max-time 300 \
  "${release_base}/${XRAY_RELEASE_ARCHIVE}.dgst" --output "$stage/xray.zip.dgst"
expected_sha=$(grep -Eio '[0-9a-fA-F]{64}' "$stage/xray.zip.dgst" | head -n 1 || true)
[[ ${#expected_sha} -eq 64 ]] || die 'could not parse the official Xray SHA-256 digest'
actual_sha=$(sha256sum "$stage/xray.zip" | awk '{print $1}')
[[ ${expected_sha,,} == "$XRAY_RELEASE_SHA256" ]] || \
  die 'official digest does not match the bundle-pinned Xray SHA-256'
[[ ${actual_sha,,} == "$XRAY_RELEASE_SHA256" ]] || die 'official Xray archive SHA-256 mismatch'
unzip -q "$stage/xray.zip" -d "$stage/unpacked"
for required in xray geoip.dat geosite.dat; do
  [[ -f "$stage/unpacked/$required" ]] || die 'official Xray archive is incomplete'
done
actual_binary_sha=$(sha256sum "$stage/unpacked/xray" | awk '{print $1}')
[[ ${actual_binary_sha,,} == "$XRAY_BINARY_SHA256" ]] || \
  die 'pinned Xray Linux binary SHA-256 mismatch'

install -d -o root -g root -m 0755 \
  /opt/krysyuk-warp-egress/bin /opt/krysyuk-warp-egress/share
install -o root -g root -m 0755 "$stage/unpacked/xray" \
  /opt/krysyuk-warp-egress/bin/xray
install -o root -g root -m 0644 \
  "$stage/unpacked/geoip.dat" "$stage/unpacked/geosite.dat" \
  /opt/krysyuk-warp-egress/share/

if ! getent group xraywarp >/dev/null; then
  groupadd --system xraywarp
fi
if ! getent passwd xraywarp >/dev/null; then
  useradd --system --home-dir /nonexistent --no-create-home \
    --gid xraywarp --shell /usr/sbin/nologin xraywarp
fi
[[ $(getent passwd xraywarp | cut -d: -f6) == /nonexistent ]] || \
  die 'xraywarp has an unexpected home directory'
[[ $(getent passwd xraywarp | cut -d: -f7) == /usr/sbin/nologin ]] || \
  die 'xraywarp has an unexpected login shell'
[[ $(id -gn xraywarp) == xraywarp ]] || die 'xraywarp has an unexpected primary group'

install -d -o root -g root -m 0700 \
  /etc/krysyuk-warp-egress /var/lib/krysyuk-warp-egress/rollback
install -d -o root -g root -m 0755 \
  /etc/nftables.d /usr/local/libexec/krysyuk-warp-egress

first_line=$(/opt/krysyuk-warp-egress/bin/xray version | sed -n '1p')
grep -Eq "^Xray[[:space:]]+${XRAY_VERSION}([[:space:]]|$)" <<<"$first_line" || \
  die 'installed Xray version is not the pinned version'

printf 'BOOTSTRAP_OK xray=%s warp=%s host-warp-service-stopped=1\n' \
  "$XRAY_VERSION" "$WARP_VERSION"
printf '%s\n' 'The audited deploy will run warp-svc only inside its private network namespace.'
bootstrap_transaction_commit
