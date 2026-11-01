#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
# shellcheck source=../scripts/target-contract.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../scripts" && pwd -P)/target-contract.sh"

# Legacy first-install/dual flow must never resurrect retired TLS8443.
if [[ -e /etc/germanyvpn-xhttp-test/promotion.json || -L /etc/germanyvpn-xhttp-test/promotion.json ]]; then
  printf 'ERROR: promoted XHTTP marker exists; use the owned promoted-six workflow, not legacy provisioning\n' >&2
  exit 1
fi

readonly SERVER_IPV4="$TARGET_IPV4"
readonly PUBLIC_FQDN="$TARGET_FQDN"
readonly REALITY_TARGET="$TARGET_REALITY_SNI"
readonly PANEL_PORT='2053'
readonly SUBSCRIPTION_PORT='2096'
readonly XHTTP_PORT='8443'
readonly XUI_VERSION='3.7.0'
readonly XRAY_VERSION='26.7.28'
readonly XRAY_SHA256='64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d'

readonly xui='/usr/local/x-ui/x-ui'
readonly xray='/usr/local/x-ui/bin/xray-linux-amd64'
readonly runtime_root='/etc/krysyuk-standalone'
readonly runtime_env="$runtime_root/server.env"
readonly api_token_file="$runtime_root/admin-api.token"
readonly access_file="$runtime_root/access.env"
readonly tls_root="$runtime_root/tls"
readonly tls_fullchain="$tls_root/fullchain.pem"
readonly tls_private_key="$tls_root/privkey.pem"
readonly letsencrypt_live="/etc/letsencrypt/live/$PUBLIC_FQDN"
readonly decoy_root='/var/www/krysyuk-standalone-decoy'
readonly hardening_source="$(cd -- "$(dirname -- "$0")/../templates" && pwd -P)/20-krysyuk-nonroot-hardening.conf"
readonly hardening_target='/etc/systemd/system/x-ui.service.d/20-krysyuk-nonroot-hardening.conf'
readonly renew_hook='/etc/letsencrypt/renewal-hooks/deploy/60-krysyuk-standalone-xui'
readonly backup_root='/var/backups/krysyuk-standalone'

mode='check'

usage() {
  cat <<'EOF'
Usage:
  configure-standalone.sh --check-only
  configure-standalone.sh --apply

Creates one standalone 3x-ui subscription with exactly three links:
VLESS+REALITY gRPC/443, VLESS+XHTTP+TLS/H2 TCP/8443, and Hysteria2
TLS/QUIC UDP/443. Initial provisioning keeps the panel backend loopback-only on
TCP/2053 and publishes the native subscription over HTTPS on TCP/2096. Run the
separate reviewed expose-panel-https.sh transaction when public panel access is
required.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --check-only) mode='check' ;;
    --apply) mode='apply' ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done

[[ "$EUID" -eq 0 ]] || die 'root is required'

for command_name in basename bash certbot chmod chown cmp cp curl dig dirname find \
  grep install ip jq mktemp nft openssl pgrep ps python3 readlink rm runuser sed seq sha256sum \
  sleep sort sqlite3 ss stat systemctl systemd-analyze tar timeout tr ufw uuidgen; do
  command -v "$command_name" >/dev/null 2>&1 || die "missing command: $command_name"
done

[[ -x "$xui" && ! -L "$xui" ]] || die '3x-ui binary is missing or unsafe'
[[ -x "$xray" && ! -L "$xray" ]] || die 'Xray binary is missing or unsafe'
[[ "$($xui -v 2>&1)" == "$XUI_VERSION" ]] || die 'unexpected 3x-ui version'
printf '%s  %s\n' "$XRAY_SHA256" "$xray" | sha256sum --check --strict - >/dev/null
xray_version_output=$("$xray" version 2>&1)
grep -Eq "(^|[[:space:]])${XRAY_VERSION//./[.]}([[:space:]]|$)" <<<"$xray_version_output" ||
  die 'unexpected Xray version'
unset xray_version_output

[[ -f "$letsencrypt_live/fullchain.pem" && -f "$letsencrypt_live/privkey.pem" ]] ||
  die 'Let us Encrypt certificate is missing'
verify_target_certificate "$letsencrypt_live/fullchain.pem" ||
  die 'certificate is invalid, expires within 24 hours or does not cover the public endpoint'
cert_pub=$(openssl x509 -in "$letsencrypt_live/fullchain.pem" -pubkey -noout | openssl sha256)
key_pub=$(openssl pkey -in "$letsencrypt_live/privkey.pem" -pubout | openssl sha256)
[[ "$cert_pub" == "$key_pub" ]] || die 'certificate/private-key mismatch'
unset cert_pub key_pub

if [[ $TARGET_ADDRESS_MODE == domain ]]; then
  for resolver in 1.1.1.1 9.9.9.9; do
    mapfile -t public_a < <(dig +short A "$PUBLIC_FQDN" "@$resolver" | sort -u)
    [[ "${#public_a[@]}" -eq 1 && "${public_a[0]}" == "$SERVER_IPV4" ]] ||
      die 'public A record does not resolve exactly to the server IPv4'
    [[ -z "$(dig +short AAAA "$PUBLIC_FQDN" "@$resolver")" ]] ||
      die 'public AAAA is forbidden until separate IPv6 acceptance'
  done
fi

reality_probe=$(timeout 15 openssl s_client \
  -connect "$REALITY_TARGET:443" -servername "$REALITY_TARGET" \
  -alpn h2 -tls1_3 -verify_return_error -verify_hostname "$REALITY_TARGET" \
  </dev/null 2>&1) || die 'REALITY target TLS preflight failed'
grep -Fq 'Verification: OK' <<<"$reality_probe" || die 'REALITY target verification failed'
grep -Fq 'ALPN protocol: h2' <<<"$reality_probe" || die 'REALITY target lacks negotiated H2'
unset reality_probe

inbound_count=$(sqlite3 /etc/x-ui/x-ui.db 'select count(*) from inbounds;')
[[ "$inbound_count" =~ ^[0-9]+$ ]] || die 'could not inspect inbound count'

if [[ "$mode" == check ]]; then
  printf 'PREFLIGHT_OK=1\n'
  printf 'SERVER=%s\nFQDN=%s\n' "$SERVER_IPV4" "$PUBLIC_FQDN"
  printf 'VERSIONS=3x-ui-%s/Xray-%s\n' "$XUI_VERSION" "$XRAY_VERSION"
  printf 'INBOUND_COUNT=%s\n' "$inbound_count"
  printf '%s\n' 'No changes made.'
  exit 0
fi

[[ "$inbound_count" -eq 0 ]] || die 'clean zero-inbound database is required'
systemctl is-active --quiet x-ui && die 'x-ui must be stopped before first provisioning'
systemctl is-enabled --quiet x-ui.service || die 'x-ui must already be enabled for boot'
systemctl is-enabled --quiet certbot.timer || die 'certbot timer must already be enabled'
systemctl is-active --quiet certbot.timer || die 'certbot timer must already be active'
[[ ! -e "$runtime_root" ]] || die "runtime root already exists: $runtime_root"
[[ ! -e /etc/systemd/system/x-ui.service.d ]] ||
  die 'x-ui systemd drop-in directory already exists; reviewed merge required'
[[ ! -e "$decoy_root" ]] || die "decoy path already exists: $decoy_root"
[[ ! -e "$renew_hook" ]] || die "renewal hook already exists: $renew_hook"
[[ -f "$hardening_source" && ! -L "$hardening_source" ]] ||
  die 'staged non-root hardening unit is missing'
bundle_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
renew_hook_source="$bundle_root/templates/60-krysyuk-standalone-xui"
[[ -f "$renew_hook_source" && ! -L "$renew_hook_source" && -r "$renew_hook_source" ]] ||
  die 'certificate renewal hook source is missing or unsafe'
[[ "$(ufw status | sed -n '1p')" == 'Status: inactive' ]] ||
  die 'this first-install transaction expects inactive UFW'
ufw show added | grep -Fq '(None)' || die 'this first-install transaction expects no UFW user rules'

stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup="$backup_root/${stamp}-standalone-provision"
install -d -o root -g root -m 0700 "$backup"
sqlite3 /etc/x-ui/x-ui.db ".backup '$backup/x-ui.db'"
chmod 0600 "$backup/x-ui.db"
sqlite3 "$backup/x-ui.db" 'PRAGMA quick_check;' | grep -qx ok || die 'SQLite snapshot failed'
stat -c '%u:%g:%a' /etc/x-ui/x-ui.db >"$backup/x-ui.db.meta"
cp -a /etc/systemd/system/x-ui.service "$backup/x-ui.service"
cp -a /etc/default/ufw "$backup/ufw.default"
cp -a /etc/ufw/user.rules "$backup/ufw.user.rules"
cp -a /etc/ufw/user6.rules "$backup/ufw.user6.rules"
nft -s list ruleset >"$backup/nft-before.txt"
ip -4 route show table all >"$backup/ip4-routes-before.txt"
ip -4 rule show >"$backup/ip4-rules-before.txt"
tar --acls --xattrs --numeric-owner -cpf "$backup/certbot-before.tar" -C / etc/letsencrypt
tar -tf "$backup/certbot-before.tar" >/dev/null
tar --acls --xattrs --numeric-owner -cpf "$backup/services-before.tar" -C / etc/nginx etc/systemd/system
tar -tf "$backup/services-before.tar" >/dev/null
tar --acls --xattrs --numeric-owner -cpf "$backup/xui-trees.tar" -C / \
  etc/x-ui usr/local/x-ui var/lib/x-ui var/log/x-ui
tar -tf "$backup/xui-trees.tar" >/dev/null
"$xui" setting -show true >"$backup/x-ui-settings.txt" 2>&1
chmod 0600 "$backup"/*
(
  cd "$backup"
  sha256sum ufw.default ufw.user.rules ufw.user6.rules x-ui.db x-ui.db.meta \
    x-ui-settings.txt x-ui.service xui-trees.tar certbot-before.tar services-before.tar nft-before.txt \
    ip4-routes-before.txt ip4-rules-before.txt >SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)
printf 'SNAPSHOT=%s\n' "$backup"

stage=''
failure_line='unknown'
transaction_exit() {
  local status=$? rollback_ok=1 xui_quiesced=1 db_uid='' db_gid='' db_mode='' unit_state=''
  trap - EXIT ERR INT TERM HUP
  set +e
  if [[ -n "$stage" && -d "$stage" ]]; then
    rm -rf -- "$stage" >/dev/null 2>&1 || rollback_ok=0
  fi
  if ((status != 0)); then
    printf 'Provisioning failure line: %s\n' "$failure_line" >&2
    printf 'Provisioning failed; restoring clean x-ui/UFW state from %s\n' "$backup" >&2
    if ! systemctl stop x-ui.service >/dev/null 2>&1; then
      xui_quiesced=0
    fi
    if unit_state=$(systemctl show x-ui.service -p LoadState -p ActiveState -p MainPID 2>/dev/null); then
      unit_state=$'\n'"$unit_state"$'\n'
      [[ $unit_state == *$'\nLoadState=loaded\n'* &&
         $unit_state == *$'\nActiveState=inactive\n'* &&
         $unit_state == *$'\nMainPID=0\n'* ]] || xui_quiesced=0
    else xui_quiesced=0; fi
    ((xui_quiesced)) || rollback_ok=0
    if ((xui_quiesced)); then
      rm -rf -- /etc/systemd/system/x-ui.service.d "$runtime_root" "$decoy_root" || rollback_ok=0
      rm -f -- "$renew_hook" || rollback_ok=0
      rm -rf -- /etc/x-ui /usr/local/x-ui /var/lib/x-ui /var/log/x-ui || rollback_ok=0
      tar --acls --xattrs --numeric-owner -xpf "$backup/xui-trees.tar" -C / || rollback_ok=0
      install -o root -g root -m 0644 "$backup/x-ui.service" /etc/systemd/system/x-ui.service || rollback_ok=0
      if IFS=: read -r db_uid db_gid db_mode <"$backup/x-ui.db.meta" &&
         [[ $db_uid =~ ^[0-9]+$ && $db_gid =~ ^[0-9]+$ && $db_mode =~ ^[0-7]{3,4}$ ]]; then
        install -o "$db_uid" -g "$db_gid" -m "$db_mode" "$backup/x-ui.db" /etc/x-ui/x-ui.db || rollback_ok=0
      else rollback_ok=0; fi
      install -o root -g root -m 0644 "$backup/ufw.default" /etc/default/ufw || rollback_ok=0
      install -o root -g root -m 0640 "$backup/ufw.user.rules" /etc/ufw/user.rules || rollback_ok=0
      install -o root -g root -m 0640 "$backup/ufw.user6.rules" /etc/ufw/user6.rules || rollback_ok=0
      ufw --force disable >/dev/null 2>&1 || rollback_ok=0
      systemctl daemon-reload >/dev/null 2>&1 || rollback_ok=0
      systemctl reset-failed x-ui.service >/dev/null 2>&1 || rollback_ok=0
      [[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'PRAGMA quick_check;' 2>/dev/null) == ok ]] || rollback_ok=0
      [[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'SELECT count(*) FROM inbounds;' 2>/dev/null) == 0 ]] || rollback_ok=0
      cmp -s "$backup/x-ui.service" /etc/systemd/system/x-ui.service || rollback_ok=0
      cmp -s "$backup/ufw.default" /etc/default/ufw || rollback_ok=0
      cmp -s "$backup/ufw.user.rules" /etc/ufw/user.rules || rollback_ok=0
      cmp -s "$backup/ufw.user6.rules" /etc/ufw/user6.rules || rollback_ok=0
      [[ $(ufw status 2>/dev/null | sed -n '1p') == 'Status: inactive' ]] || rollback_ok=0
    else
      # Replacing SQLite/config files under a still-running x-ui is unsafe.
      # Keep its data and current firewall until the protected snapshot can
      # be restored after the service has really stopped.
      printf 'STANDALONE_ROLLBACK_RUNTIME_RETAINED=1\n' >&2
    fi
    printf 'STANDALONE_ROLLBACK_OK=%s SNAPSHOT=%s\n' "$rollback_ok" "$backup" >&2
  fi
  ((rollback_ok)) || status=1
  exit "$status"
}
trap 'failure_line=$LINENO' ERR
trap transaction_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

random_hex() {
  openssl rand -hex "$1"
}

random_b64url() {
  openssl rand -base64 "$1" | tr -d '\n=' | tr '+/' '-_'
}

panel_username="admin_$(random_hex 8)"
panel_password=$(random_b64url 32)
panel_base_path=$(random_hex 32)
subscription_path=$(random_hex 20)
subscription_id=$(random_hex 32)
xhttp_private_path=$(random_hex 24)
vless_uuid=$(uuidgen | tr 'A-Z' 'a-z')
hysteria2_auth=$(random_b64url 32)
reality_short_id=$(random_hex 8)
key_output=$("$xray" x25519)
reality_private_key=$(sed -nE 's#^Private([[:space:]]+key|Key):[[:space:]]*##p' <<<"$key_output" | sed -n '1p')
reality_public_key=$(sed -nE 's#^(Public([[:space:]]+key|Key)|Password( \(PublicKey\))?):[[:space:]]*##p' \
  <<<"$key_output" | sed -n '1p')
unset key_output

[[ "$panel_username" =~ ^[A-Za-z0-9._-]{4,64}$ ]] || die 'generated panel username is invalid'
[[ "$panel_password" =~ ^[A-Za-z0-9._-]{32,128}$ ]] || die 'generated panel password is invalid'
[[ "$panel_base_path" =~ ^[a-f0-9]{64}$ ]] || die 'generated panel path is invalid'
[[ "$subscription_path" =~ ^[a-f0-9]{40}$ ]] || die 'generated subscription path is invalid'
[[ "$subscription_id" =~ ^[a-f0-9]{64}$ ]] || die 'generated subscription ID is invalid'
[[ "$xhttp_private_path" =~ ^[a-f0-9]{48}$ ]] || die 'generated XHTTP path is invalid'
[[ "$vless_uuid" =~ ^[0-9a-f-]{36}$ ]] || die 'generated VLESS UUID is invalid'
[[ "$hysteria2_auth" =~ ^[A-Za-z0-9_-]{40,128}$ ]] || die 'generated Hysteria2 auth is invalid'
[[ "$reality_short_id" =~ ^[a-f0-9]{16}$ ]] || die 'generated REALITY short ID is invalid'
[[ "$reality_private_key" =~ ^[A-Za-z0-9_-]{43}$ ]] || die 'REALITY private key parse failed'
[[ "$reality_public_key" =~ ^[A-Za-z0-9_-]{43}$ ]] || die 'REALITY public key parse failed'

install -d -o root -g xui-secrets -m 0750 "$runtime_root"
tmp_env=$(mktemp "$runtime_root/server.env.XXXXXXXX")
printf '%s\n' \
  "PANEL_USERNAME=$panel_username" \
  "PANEL_PASSWORD=$panel_password" \
  "PANEL_BASE_PATH=$panel_base_path" \
  "SUBSCRIPTION_PATH=$subscription_path" \
  "SUBSCRIPTION_ID=$subscription_id" \
  "XHTTP_PRIVATE_PATH=$xhttp_private_path" \
  "VLESS_UUID=$vless_uuid" \
  "HYSTERIA2_AUTH=$hysteria2_auth" \
  "REALITY_SHORT_ID=$reality_short_id" \
  "REALITY_PRIVATE_KEY=$reality_private_key" \
  "REALITY_PUBLIC_KEY=$reality_public_key" >"$tmp_env"
install -o root -g root -m 0600 "$tmp_env" "$runtime_env"
rm -f -- "$tmp_env"
unset panel_password hysteria2_auth reality_private_key

tls_generation=$(mktemp -d "$runtime_root/tls-gen.XXXXXXXX")
chown root:xui-secrets "$tls_generation"
chmod 0750 "$tls_generation"
install -o root -g xui-secrets -m 0640 "$letsencrypt_live/fullchain.pem" "$tls_generation/fullchain.pem"
install -o root -g xui-secrets -m 0640 "$letsencrypt_live/privkey.pem" "$tls_generation/privkey.pem"
ln -s -- "$(basename "$tls_generation")" "$tls_root"
install -d -o root -g xui -m 0750 "$decoy_root"
printf '%s\n' '<!doctype html><html><head><title>Welcome</title></head><body><h1>Welcome</h1></body></html>' \
  >"$decoy_root/index.html"
chown root:xui "$decoy_root/index.html"
chmod 0640 "$decoy_root/index.html"

# shellcheck disable=SC1090
source "$runtime_env"
TLS_FULLCHAIN="$tls_fullchain"
TLS_PRIVATE_KEY="$tls_private_key"
export SERVER_IPV4 PUBLIC_FQDN REALITY_TARGET PANEL_USERNAME PANEL_PASSWORD PANEL_BASE_PATH
export SUBSCRIPTION_PATH SUBSCRIPTION_ID XHTTP_PRIVATE_PATH VLESS_UUID HYSTERIA2_AUTH
export REALITY_SHORT_ID REALITY_PRIVATE_KEY REALITY_PUBLIC_KEY TLS_FULLCHAIN TLS_PRIVATE_KEY

stage=$(mktemp -d -p /run krysyuk-standalone.XXXXXXXX)
cleanup_stage() {
  rm -rf -- "$stage"
  stage=''
}

jq -n '
  {
    api: {services:["HandlerService","LoggerService","StatsService","RoutingService"],tag:"api"},
    dns: {
      servers:[
        {address:"https://1.1.1.1/dns-query",tag:"dns_cf",queryStrategy:"UseIPv4",skipFallback:true,finalQuery:true},
        {address:"https://9.9.9.9/dns-query",tag:"dns_q9",queryStrategy:"UseIPv4",skipFallback:true,finalQuery:true}
      ],
      queryStrategy:"UseIPv4",disableCache:false,disableFallback:false,disableFallbackIfMatch:false
    },
    inbounds:[{listen:"127.0.0.1",port:62789,protocol:"tunnel",settings:{rewriteAddress:"127.0.0.1"},tag:"api"}],
    log:{access:"none",dnsLog:false,error:"",loglevel:"warning",maskAddress:""},
    metrics:{listen:"127.0.0.1:11111",tag:"metrics_out"},
    outbounds:[
      {
        tag:"DIRECT",protocol:"freedom",
        settings:{domainStrategy:"UseIP",finalRules:[{action:"block",ip:["geoip:private","::/0"]},{action:"allow"}]},
        streamSettings:{sockopt:{tcpKeepAliveIdle:60,tcpKeepAliveInterval:30}}
      },
      {tag:"BLOCK",protocol:"blackhole",settings:{}}
    ],
    policy:{levels:{"0":{statsUserDownlink:true,statsUserUplink:true}},system:{statsInboundDownlink:true,statsInboundUplink:true,statsOutboundDownlink:true,statsOutboundUplink:true}},
    routing:{domainStrategy:"AsIs",domainMatcher:"hybrid",rules:[
      {type:"field",inboundTag:["api"],outboundTag:"api"},
      {type:"field",protocol:["bittorrent"],outboundTag:"BLOCK"},
      {type:"field",ip:["geoip:private","::/0"],outboundTag:"BLOCK"}
    ]},
    stats:{}
  }
' >"$stage/xray-global.json"

jq -n \
  --arg ip "$SERVER_IPV4" --arg fqdn "$PUBLIC_FQDN" --arg target "$REALITY_TARGET" \
  --arg uuid "$VLESS_UUID" --arg sub "$SUBSCRIPTION_ID" \
  --arg private_key "$REALITY_PRIVATE_KEY" --arg public_key "$REALITY_PUBLIC_KEY" \
  --arg short_id "$REALITY_SHORT_ID" '
  {
    enable:false,remark:"VPN VLESS REALITY TCP 443",listen:$ip,port:443,protocol:"vless",expiryTime:0,total:0,
    settings:{clients:[{id:$uuid,email:"germany-reality",flow:"",limitIp:(env.TARGET_DEVICE_LIMIT|tonumber),totalGB:0,expiryTime:0,enable:true,tgId:0,subId:$sub,comment:(env.TARGET_LABEL+" \u00b7 REALITY"),reset:0}],decryption:"none",encryption:"none",fallbacks:[]},
    streamSettings:{network:"grpc",grpcSettings:{serviceName:"reality-grpc",multiMode:false},security:"reality",realitySettings:{show:false,xver:0,target:($target+":443"),serverNames:[$target],privateKey:$private_key,minClientVer:"26.3.27",maxClientVer:"",maxTimediff:0,shortIds:[$short_id],mldsa65Seed:"",settings:{publicKey:$public_key,fingerprint:"chrome",serverName:"",spiderX:"/",mldsa65Verify:""}}},
    sniffing:{enabled:true,destOverride:["http","tls","quic","fakedns"],metadataOnly:false,routeOnly:false,ipsExcluded:[],domainsExcluded:[]},
    shareAddrStrategy:"custom",shareAddr:$fqdn,subSortIndex:1
  }
' >"$stage/reality.json"

jq -n \
  --arg ip "$SERVER_IPV4" --arg fqdn "$PUBLIC_FQDN" --arg uuid "$VLESS_UUID" \
  --arg sub "$SUBSCRIPTION_ID" --arg path "/$XHTTP_PRIVATE_PATH" \
  --arg cert "$TLS_FULLCHAIN" --arg key "$TLS_PRIVATE_KEY" '
  {
    enable:false,remark:"VPN VLESS XHTTP TLS 8443",listen:$ip,port:8443,protocol:"vless",expiryTime:0,total:0,
    settings:{clients:[{id:$uuid,email:"germany-xhttp",flow:"",limitIp:(env.TARGET_DEVICE_LIMIT|tonumber),totalGB:0,expiryTime:0,enable:true,tgId:0,subId:$sub,comment:(env.TARGET_LABEL+" \u00b7 XHTTP"),reset:0}],decryption:"none",encryption:"none",fallbacks:[]},
    streamSettings:{network:"xhttp",security:"tls",xhttpSettings:{path:$path,host:$fqdn,mode:"packet-up"},tlsSettings:{serverName:$fqdn,minVersion:"1.2",maxVersion:"1.3",cipherSuites:"",rejectUnknownSni:(env.TARGET_ADDRESS_MODE!="ip"),disableSystemRoot:false,enableSessionResumption:true,certificates:[{certificateFile:$cert,keyFile:$key,ocspStapling:0,oneTimeLoading:false,usage:"encipherment",buildChain:false}],alpn:["h2"],echServerKeys:"",settings:{fingerprint:"chrome",echConfigList:""}}},
    sniffing:{enabled:true,destOverride:["http","tls","quic","fakedns"],metadataOnly:false,routeOnly:false,ipsExcluded:[],domainsExcluded:[]},
    shareAddrStrategy:"custom",shareAddr:$fqdn,subSortIndex:3
  }
' >"$stage/xhttp.json"

jq -n \
  --arg ip "$SERVER_IPV4" --arg fqdn "$PUBLIC_FQDN" --arg auth "$HYSTERIA2_AUTH" \
  --arg sub "$SUBSCRIPTION_ID" --arg cert "$TLS_FULLCHAIN" --arg key "$TLS_PRIVATE_KEY" \
  --arg decoy "$decoy_root" '
  {
    enable:false,remark:"VPN Hysteria2 UDP 443",listen:$ip,port:443,protocol:"hysteria",expiryTime:0,total:0,
    settings:{version:2,clients:[{auth:$auth,email:"germany-hysteria2",limitIp:(env.TARGET_DEVICE_LIMIT|tonumber),totalGB:0,expiryTime:0,enable:true,tgId:0,subId:$sub,comment:(env.TARGET_LABEL+" \u00b7 HYSTERIA2"),reset:0}]},
    streamSettings:{network:"hysteria",hysteriaSettings:{version:2,udpIdleTimeout:60,masquerade:{type:"file",dir:$decoy,url:"",rewriteHost:false,insecure:false,content:"",headers:{},statusCode:0}},security:"tls",tlsSettings:{serverName:$fqdn,minVersion:"1.2",maxVersion:"1.3",cipherSuites:"",rejectUnknownSni:(env.TARGET_ADDRESS_MODE!="ip"),disableSystemRoot:false,enableSessionResumption:true,certificates:[{certificateFile:$cert,keyFile:$key,ocspStapling:0,oneTimeLoading:false,usage:"encipherment",buildChain:false}],alpn:["h3"],echServerKeys:"",settings:{fingerprint:"chrome",echConfigList:""}}},
    sniffing:{enabled:true,destOverride:["http","tls","quic","fakedns"],metadataOnly:false,routeOnly:false,ipsExcluded:[],domainsExcluded:[]},
    shareAddrStrategy:"custom",shareAddr:$fqdn,subSortIndex:2
  }
' >"$stage/hysteria2.json"

for json_file in "$stage/xray-global.json" "$stage/reality.json" "$stage/xhttp.json" "$stage/hysteria2.json"; do
  jq --exit-status . "$json_file" >/dev/null || die "invalid generated JSON: $json_file"
done

jq --slurpfile reality "$stage/reality.json" \
  --slurpfile xhttp "$stage/xhttp.json" --slurpfile hysteria "$stage/hysteria2.json" '
  def core($p; $tag):
    ($p.settings
      | if $p.protocol == "vless" then (del(.encryption) | .clients |= map({id,email,flow}))
        elif $p.protocol == "hysteria" then .clients |= map({auth,email}) else . end) as $settings
    | ({port:$p.port,protocol:$p.protocol,settings:$settings,streamSettings:$p.streamSettings,sniffing:$p.sniffing,tag:$tag}
       + (if $p.listen == "" then {} else {listen:$p.listen} end));
  .inbounds += [core($reality[0];"standalone-reality"),core($xhttp[0];"standalone-xhttp"),core($hysteria[0];"standalone-hysteria2")]
' "$stage/xray-global.json" >"$stage/xray-preflight.json"
XRAY_LOCATION_ASSET=/usr/local/x-ui/bin "$xray" run -test -config "$stage/xray-preflight.json" >/dev/null
printf 'XRAY_PREFLIGHT_OK=1\n'

ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw default deny routed >/dev/null
ufw allow "$TARGET_SSH_PORT/tcp" comment 'SSH key-only' >/dev/null
ufw allow 80/tcp comment 'ACME HTTP-01' >/dev/null
ufw --force enable >/dev/null

# The supported CLI places password/base path in argv. On this verified clean,
# stopped database use the same bcrypt cost and schema as upstream v3.7.0
# internal/web/service/panel/user.go. This does not bypass fresh preconditions.
python3 - <<'PY'
import bcrypt
import os
import sqlite3

db = sqlite3.connect('/etc/x-ui/x-ui.db')
try:
    with db:
        if db.execute('select count(*) from inbounds').fetchone()[0] != 0:
            raise SystemExit('initial credentials require a clean zero-inbound DB')
        users = db.execute('select id from users').fetchall()
        if len(users) != 1:
            raise SystemExit('initial credentials require exactly one bootstrap user')
        password = bcrypt.hashpw(os.environ['PANEL_PASSWORD'].encode(),
                                 bcrypt.gensalt(rounds=10, prefix=b'2a')).decode()
        db.execute('update users set username=?,password=?,login_epoch=coalesce(login_epoch,0)+1 where id=?',
                   (os.environ['PANEL_USERNAME'], password, users[0][0]))
        for key, value in {
            'webListen': '127.0.0.1', 'webPort': '2053',
            'webBasePath': '/' + os.environ['PANEL_BASE_PATH'] + '/',
            'webDomain': '', 'webCertFile': '', 'webKeyFile': ''
        }.items():
            row = db.execute('select id from settings where key=?', (key,)).fetchone()
            if row:
                db.execute('update settings set value=? where key=?', (value,key))
            else:
                db.execute('insert into settings(key,value) values(?,?)', (key,value))
    if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
        raise SystemExit('initial credentials DB quick_check failed')
finally:
    db.close()
PY
systemctl start x-ui.service
for _ in $(seq 1 30); do
  if systemctl is-active --quiet x-ui.service &&
     ss -H -lnt | grep -Eq "127[.]0[.]0[.]1:${PANEL_PORT}[[:space:]]"; then
    break
  fi
  sleep 1
done
systemctl is-active --quiet x-ui.service || die 'x-ui did not start for local API configuration'
ss -H -lnt | grep -Eq "127[.]0[.]0[.]1:${PANEL_PORT}[[:space:]]" || die 'panel is not loopback-only'
if ss -H -lnt | grep -Eq "(0[.]0[.]0[.]0|[*]|\[::\]):${PANEL_PORT}[[:space:]]"; then
  die 'panel unexpectedly listens publicly'
fi

refresh_api_token() {
  local token_output token
  token_output=$("$xui" setting -getApiToken true 2>&1)
  token=$(sed -nE 's/^apiToken:[[:space:]]*//p' <<<"$token_output" | sed -n '1p')
  [[ "$token" =~ ^[A-Za-z0-9._-]{32,256}$ ]] || die 'could not obtain a safe local API bearer'
  printf '%s\n' "$token" >"$api_token_file"
  chmod 0600 "$api_token_file"
  printf 'Authorization: Bearer %s\n' "$token" >"$stage/api.header"
  chmod 0600 "$stage/api.header"
  unset token token_output
}

api_url="http://127.0.0.1:${PANEL_PORT}/${PANEL_BASE_PATH}/panel/api"
api_get() {
  curl --proto '=http' --fail-with-body --silent --show-error --max-time 30 \
    --header "@$stage/api.header" --header 'Host: localhost' \
    --header 'X-Requested-With: XMLHttpRequest' "$@"
}
api_post() {
  curl --proto '=http' --fail-with-body --silent --show-error --max-time 60 \
    --header "@$stage/api.header" --header 'Host: localhost' \
    --header 'X-Requested-With: XMLHttpRequest' --request POST "$@"
}

refresh_api_token
invalid_code=$(curl --proto '=http' --silent --show-error --max-time 10 \
  --output /dev/null --write-out '%{http_code}' \
  --header 'Authorization: Bearer 000000000000000000000000000000000000000000000000' \
  --header 'X-Requested-With: XMLHttpRequest' "$api_url/inbounds/list")
[[ "$invalid_code" =~ ^(401|403)$ ]] || die 'invalid API bearer was not rejected'

api_post --output "$stage/settings-before.json" "$api_url/setting/all"
jq --exit-status '.success == true and (.obj|type=="object")' "$stage/settings-before.json" >/dev/null
jq --arg ip "$SERVER_IPV4" --arg fqdn "$PUBLIC_FQDN" \
  --arg panel_path "/$PANEL_BASE_PATH/" --arg sub_path "/$SUBSCRIPTION_PATH/" \
  --arg sub_uri "https://$PUBLIC_FQDN:$SUBSCRIPTION_PORT" \
  --arg cert "$TLS_FULLCHAIN" --arg key "$TLS_PRIVATE_KEY" '
  .obj
  | .webListen="127.0.0.1" | .webPort=2053 | .webDomain="" | .webBasePath=$panel_path
  | .webCertFile="" | .webKeyFile="" | .trustedProxyCIDRs="127.0.0.1/32,::1/128"
  | .subEnable=true | .subJsonEnable=false | .subJsonAutoDetect=false
  | .subListen=$ip | .subPort=2096 | .subDomain=$fqdn | .subPath=$sub_path | .subURI=$sub_uri
  | .subCertFile=$cert | .subKeyFile=$key | .remarkTemplate="{{COMMENT}}"
' "$stage/settings-before.json" >"$stage/settings-intended.json"
api_post --header 'Content-Type: application/json' --data-binary "@$stage/settings-intended.json" \
  --output "$stage/settings-update.json" "$api_url/setting/update"
jq --exit-status '.success == true' "$stage/settings-update.json" >/dev/null
systemctl restart x-ui.service
for _ in $(seq 1 30); do
  if systemctl is-active --quiet x-ui.service &&
     ss -H -lnt | grep -Eq "127[.]0[.]0[.]1:${PANEL_PORT}[[:space:]]" &&
     ss -H -lnt | grep -Eq "${SERVER_IPV4}:${SUBSCRIPTION_PORT}[[:space:]]"; then
    break
  fi
  sleep 1
done
systemctl is-active --quiet x-ui.service || die 'x-ui failed after settings update'
refresh_api_token

api_post --data-urlencode "xraySetting@$stage/xray-global.json" \
  --data-urlencode 'outboundTestUrl=https://www.cloudflare.com/cdn-cgi/trace' \
  --output "$stage/xray-update.json" "$api_url/xray/update"
jq --exit-status '.success == true' "$stage/xray-update.json" >/dev/null

api_get --output "$stage/inbounds-before.json" "$api_url/inbounds/list"
jq --exit-status '.success == true and (.obj|length==0)' "$stage/inbounds-before.json" >/dev/null ||
  die 'inbound database changed during transaction'

for payload in "$stage/reality.json" "$stage/xhttp.json" "$stage/hysteria2.json"; do
  response="$stage/add-$(basename "$payload")"
  api_post --header 'Content-Type: application/json' --data-binary "@$payload" \
    --output "$response" "$api_url/inbounds/add"
  jq --exit-status '.success == true' "$response" >/dev/null
done

api_get --output "$stage/inbounds-added.json" "$api_url/inbounds/list"
reality_id=$(jq -r '.obj[]|select(.remark=="VPN VLESS REALITY TCP 443")|.id' "$stage/inbounds-added.json")
xhttp_id=$(jq -r '.obj[]|select(.remark=="VPN VLESS XHTTP TLS 8443")|.id' "$stage/inbounds-added.json")
hysteria_id=$(jq -r '.obj[]|select(.remark=="VPN Hysteria2 UDP 443")|.id' "$stage/inbounds-added.json")
for inbound_id in "$reality_id" "$xhttp_id" "$hysteria_id"; do
  [[ "$inbound_id" =~ ^[1-9][0-9]*$ ]] || die 'could not resolve created inbound IDs'
done

add_host_group() {
  local inbound_id="$1" port="$2" security="$3" sni="$4" path="$5" alpn="$6" host_header="$7"
  local host_payload="$stage/host-${inbound_id}.json"
  local host_response="$stage/host-${inbound_id}-response.json"
  jq -n --argjson inbound_id "$inbound_id" --arg fqdn "$PUBLIC_FQDN" \
    --argjson port "$port" --arg security "$security" --arg sni "$sni" \
    --arg path "$path" --arg alpn "$alpn" --arg host_header "$host_header" '
    {
      groupId:"",inboundIds:[$inbound_id],remark:"VPN standalone",hosts:[$fqdn],sortOrder:0,
      serverDescription:"",port:$port,security:$security,sni:$sni,hostHeader:$host_header,path:$path,
      alpn:(if $alpn=="" then [] else [$alpn] end),fingerprint:"chrome",allowInsecure:false,
      isDisabled:false,isHidden:false,keepSniBlank:false,overrideSniFromAddress:false,
      pinnedPeerCertSha256:[],verifyPeerCertByName:"",echConfigList:"",muxParams:"",sockoptParams:"",
      finalMask:"",vlessRoute:"",excludeFromSubTypes:[],nodeGuids:[],mihomoIpVersion:"ipv4",
      mihomoX25519:false,shuffleHost:false,tags:["PRIVATE"]
    }
  ' >"$host_payload"
  api_post --header 'Content-Type: application/json' --data-binary "@$host_payload" \
    --output "$host_response" "$api_url/hosts/add"
  jq --exit-status '.success == true' "$host_response" >/dev/null
}

add_host_group "$reality_id" 443 reality "$REALITY_TARGET" '' '' ''
add_host_group "$xhttp_id" "$XHTTP_PORT" tls "$PUBLIC_FQDN" "/$XHTTP_PRIVATE_PATH" h2 "$PUBLIC_FQDN"
add_host_group "$hysteria_id" 443 tls "$PUBLIC_FQDN" '' h3 ''

for inbound_id in "$reality_id" "$xhttp_id" "$hysteria_id"; do
  api_post --header 'Content-Type: application/json' --data '{"enable":true}' \
    --output "$stage/enable-${inbound_id}.json" "$api_url/inbounds/setEnable/${inbound_id}"
  jq --exit-status '.success == true' "$stage/enable-${inbound_id}.json" >/dev/null
done

for _ in $(seq 1 30); do
  if ss -H -lnt | grep -Eq "${SERVER_IPV4}:443[[:space:]]" &&
     ss -H -lnt | grep -Eq "${SERVER_IPV4}:${XHTTP_PORT}[[:space:]]" &&
     ss -H -lnu | grep -Eq "${SERVER_IPV4}:443[[:space:]]"; then
    break
  fi
  sleep 1
done
ss -H -lnt | grep -Eq "${SERVER_IPV4}:443[[:space:]]" || die 'REALITY listener is absent'
ss -H -lnt | grep -Eq "${SERVER_IPV4}:${XHTTP_PORT}[[:space:]]" || die 'XHTTP listener is absent'
ss -H -lnu | grep -Eq "${SERVER_IPV4}:443[[:space:]]" || die 'Hysteria2 listener is absent'
XRAY_LOCATION_ASSET=/usr/local/x-ui/bin "$xray" run -test -config /usr/local/x-ui/bin/config.json >/dev/null
sqlite3 /etc/x-ui/x-ui.db 'PRAGMA quick_check;' | grep -qx ok

systemctl stop x-ui.service
install -d -o root -g root -m 0755 /etc/systemd/system/x-ui.service.d
install -o root -g root -m 0644 "$hardening_source" "$hardening_target"
chown -R root:root /usr/local/x-ui
chmod -R go-w /usr/local/x-ui
chown root:xui /usr/local/x-ui/bin
chmod 1770 /usr/local/x-ui/bin
chown root:root "$xui" "$xray"
chmod 0755 "$xui" "$xray"
if [[ -f /usr/local/x-ui/bin/config.json ]]; then
  chown xui:xui /usr/local/x-ui/bin/config.json
  chmod 0600 /usr/local/x-ui/bin/config.json
fi
chown root:xui /etc/x-ui
chmod 1770 /etc/x-ui
find /etc/x-ui -maxdepth 1 -type f -name 'x-ui.db*' \
  -exec chown xui:xui {} + -exec chmod 0600 {} +
if [[ -f /etc/x-ui/system_metrics.gob ]]; then
  chown xui:xui /etc/x-ui/system_metrics.gob
  chmod 0600 /etc/x-ui/system_metrics.gob
fi
if [[ -f /etc/x-ui/install-result.env ]]; then
  install -o root -g root -m 0600 /etc/x-ui/install-result.env "$runtime_root/install-result.env"
  rm -f -- /etc/x-ui/install-result.env
fi
chown root:root /etc/systemd/system/x-ui.service "$hardening_target"
chmod 0644 /etc/systemd/system/x-ui.service "$hardening_target"

runuser -u xui -- test -r "$tls_fullchain"
runuser -u xui -- test -r "$tls_private_key"
runuser -u xui -- test -r "$decoy_root/index.html"
runuser -u xui -- test -w /etc/x-ui
runuser -u xui -- test -w /etc/x-ui/x-ui.db
runuser -u xui -- test -w /usr/local/x-ui/bin
systemctl daemon-reload
systemd-analyze verify x-ui.service >/dev/null
systemctl start x-ui.service

for _ in $(seq 1 30); do
  if systemctl is-active --quiet x-ui.service &&
     ss -H -lnt | grep -Eq "127[.]0[.]0[.]1:${PANEL_PORT}[[:space:]]" &&
     ss -H -lnt | grep -Eq "${SERVER_IPV4}:${SUBSCRIPTION_PORT}[[:space:]]" &&
     ss -H -lnt | grep -Eq "${SERVER_IPV4}:443[[:space:]]" &&
     ss -H -lnt | grep -Eq "${SERVER_IPV4}:${XHTTP_PORT}[[:space:]]" &&
     ss -H -lnu | grep -Eq "${SERVER_IPV4}:443[[:space:]]"; then
    break
  fi
  sleep 1
done
systemctl is-active --quiet x-ui.service || die 'non-root x-ui failed to start'
main_pid=$(systemctl show -p MainPID --value x-ui.service)
[[ "$(ps -o user= -p "$main_pid" | tr -d '[:space:]')" == xui ]] || die 'x-ui is not running as xui'
xray_pid=''
xray_count=0
mapfile -t xray_children < <(pgrep -P "$main_pid" || true)
for candidate_pid in "${xray_children[@]}"; do
  [[ "$(readlink -f -- "/proc/$candidate_pid/exe" 2>/dev/null || true)" == "$xray" ]] || continue
  xray_pid="$candidate_pid"
  ((xray_count += 1))
done
[[ "$xray_count" -eq 1 && "$(ps -o user= -p "$xray_pid" | tr -d '[:space:]')" == xui ]] ||
  die 'Xray child is not running as xui'

ufw allow "$SUBSCRIPTION_PORT/tcp" comment '3x-ui HTTPS subscription' >/dev/null
ufw allow 443/tcp comment 'VLESS REALITY' >/dev/null
ufw allow 443/udp comment 'Hysteria2' >/dev/null
ufw allow "$XHTTP_PORT/tcp" comment 'VLESS XHTTP TLS H2' >/dev/null
ufw reload >/dev/null

install -o root -g root -m 0750 "$renew_hook_source" "$renew_hook"
systemctl enable --now certbot.timer >/dev/null

subscription_url="https://${PUBLIC_FQDN}:${SUBSCRIPTION_PORT}/${SUBSCRIPTION_PATH}/${SUBSCRIPTION_ID}"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 30 \
  --user-agent 'v2rayN/7' --resolve "${PUBLIC_FQDN}:${SUBSCRIPTION_PORT}:${SERVER_IPV4}" \
  --output "$stage/subscription.body" "$subscription_url"
[[ -s "$stage/subscription.body" ]] || die 'subscription body is empty'

SUB_BODY="$stage/subscription.body" CHECK_PUBLIC_FQDN="$PUBLIC_FQDN" \
  CHECK_REALITY_TARGET="$REALITY_TARGET" CHECK_XHTTP_PORT="$XHTTP_PORT" python3 - <<'PY'
import base64
import os
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

raw = Path(os.environ["SUB_BODY"]).read_bytes().strip()
text = raw.decode("utf-8", "strict")
if "://" not in text:
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    text = base64.urlsafe_b64decode(padded.encode()).decode("utf-8", "strict")
links = [line.strip() for line in text.splitlines() if line.strip()]
if len(links) != 3:
    raise SystemExit(f"subscription expected 3 links, got {len(links)}")
parsed = [urlparse(link) for link in links]
if sorted(item.scheme for item in parsed) != ["hysteria2", "vless", "vless"]:
    raise SystemExit("subscription schemes are not exactly two VLESS plus one Hysteria2")
comments = sorted(unquote(item.fragment) for item in parsed)
expected_comments = sorted([
    os.environ["TARGET_LABEL"] + " \u00b7 REALITY",
    os.environ["TARGET_LABEL"] + " \u00b7 XHTTP",
    os.environ["TARGET_LABEL"] + " \u00b7 HYSTERIA2",
])
if comments != expected_comments:
    raise SystemExit("subscription display comments are not exact")
fqdn = os.environ["CHECK_PUBLIC_FQDN"]
for item in parsed:
    if item.hostname != fqdn:
        raise SystemExit("subscription address is not the managed FQDN")
vless = [item for item in parsed if item.scheme == "vless"]
reality = [item for item in vless if parse_qs(item.query).get("security") == ["reality"]]
xhttp = [item for item in vless if parse_qs(item.query).get("type") == ["xhttp"]]
if len(reality) != 1 or reality[0].port != 443:
    raise SystemExit("REALITY link shape mismatch")
reality_query = parse_qs(reality[0].query)
if reality_query.get("sni") != [os.environ["CHECK_REALITY_TARGET"]]:
    raise SystemExit("REALITY SNI mismatch")
if reality_query.get("type") != ["grpc"] or reality_query.get("serviceName") != ["reality-grpc"]:
    raise SystemExit("REALITY gRPC transport mismatch")
if any(reality_query.get("flow", [""])):
    raise SystemExit("REALITY gRPC must not advertise Vision flow")
if len(xhttp) != 1 or xhttp[0].port != int(os.environ["CHECK_XHTTP_PORT"]):
    raise SystemExit("XHTTP link shape mismatch")
xhttp_query = parse_qs(xhttp[0].query)
if xhttp_query.get("security") != ["tls"] or xhttp_query.get("alpn") != ["h2"] or xhttp_query.get("mode") != ["packet-up"]:
    raise SystemExit("XHTTP TLS/H2 shape mismatch")
hysteria = [item for item in parsed if item.scheme == "hysteria2"]
if len(hysteria) != 1 or hysteria[0].port != 443:
    raise SystemExit("Hysteria2 link shape mismatch")
print("SUBSCRIPTION_SHAPE_OK=3")
PY

api_get --output "$stage/inbounds-final.json" "$api_url/inbounds/list"
jq --exit-status --arg fqdn "$PUBLIC_FQDN" --arg uuid "$VLESS_UUID" \
  --arg auth "$HYSTERIA2_AUTH" --arg sub "$SUBSCRIPTION_ID" '
  .success == true and (.obj|length==3) and ([.obj[].enable]|all)
  and ([.obj[].shareAddr]|unique==[$fqdn])
  and ([.obj[]|select(.protocol=="vless")|.settings.clients[0].id]|unique==[$uuid])
  and ([.obj[]|select(.protocol=="hysteria")|.settings.clients[0].auth]==[$auth])
  and ([.obj[].settings.clients[0].subId]|unique==[$sub])
' "$stage/inbounds-final.json" >/dev/null

api_get --output "$stage/hosts-final.json" "$api_url/hosts/list"
jq --exit-status --arg host443 "$PUBLIC_FQDN:443" \
  --arg host8443 "$PUBLIC_FQDN:$XHTTP_PORT" --arg fqdn "$PUBLIC_FQDN" \
  --arg target "$REALITY_TARGET" --arg xhttp_path "/$XHTTP_PRIVATE_PATH" '
  ([.obj[]|select(.security=="reality")]) as $rs
  | ([.obj[]|select(.security=="tls" and .port==8443)]) as $xs
  | ([.obj[]|select(.security=="tls" and .port==443)]) as $hs
  | .success == true and (.obj|length==3)
  and ($rs|length==1) and ($xs|length==1) and ($hs|length==1)
  and ($rs[0].hosts==[$host443] and $rs[0].sni==$target and $rs[0].alpn==[])
  and ($xs[0].hosts==[$host8443] and $xs[0].sni==$fqdn
       and $xs[0].path==$xhttp_path and $xs[0].hostHeader==$fqdn and $xs[0].alpn==["h2"])
  and ($hs[0].hosts==[$host443] and $hs[0].sni==$fqdn and $hs[0].alpn==["h3"])
  and ([.obj[].isDisabled]|all(.==false))
' "$stage/hosts-final.json" >/dev/null

if ss -H -lnt | grep -Eq "(0[.]0[.]0[.]0|[*]|\[::\]):${PANEL_PORT}[[:space:]]"; then
  die 'panel became publicly reachable'
fi
ufw status | grep -Fq 'Status: active' || die 'UFW is not active'
ufw status | grep -Eq "(^|[[:space:]])${PANEL_PORT}(/tcp)?([[:space:]]|$).*ALLOW" &&
  die 'panel port is allowed by UFW'
sqlite3 /etc/x-ui/x-ui.db 'PRAGMA quick_check;' | grep -qx ok
XRAY_LOCATION_ASSET=/usr/local/x-ui/bin "$xray" run -test -config /usr/local/x-ui/bin/config.json >/dev/null
systemctl enable x-ui.service >/dev/null
systemctl is-enabled --quiet x-ui.service || die 'x-ui is not enabled for reboot'

printf '%s\n' \
  "PANEL_URL=http://127.0.0.1:${PANEL_PORT}/${PANEL_BASE_PATH}/" \
  "PANEL_USERNAME=$PANEL_USERNAME" \
  "PANEL_PASSWORD=$PANEL_PASSWORD" \
  "SUBSCRIPTION_URL=$subscription_url" >"$access_file"
chmod 0600 "$access_file"

touch "$backup/PROVISION_COMMITTED"
chmod 0600 "$backup/PROVISION_COMMITTED"
cleanup_stage
trap - ERR EXIT INT TERM HUP
printf 'STANDALONE_PROVISION_OK=1\n'
printf 'BACKUP=%s\n' "$backup"
printf 'ACCESS_FILE=%s\n' "$access_file"
printf '%s\n' 'Secrets and subscription URI were written root-only and were not printed.'
