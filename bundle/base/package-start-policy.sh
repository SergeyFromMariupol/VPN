#!/usr/bin/env bash
# Temporary package-service start suppression, owned by inode before publish.
policy_identity=''
mask_identity=''
policy_staged=''
mask_staging=''
mask_staging_identity=''

prepare_start_policy() {
  policy_staged=$(mktemp -p "$(dirname -- "$policy_path")" .vpn-policy-rc.d.XXXXXXXX)
  policy_identity=$(stat -c '%d:%i' "$policy_staged")
  printf '#!/bin/sh\nexit 101\n' >"$policy_staged"
  chmod 0755 "$policy_staged"
  mv -T --no-clobber -- "$policy_staged" "$policy_path"
  [[ -f $policy_path && ! -L $policy_path && $(stat -c '%d:%i' "$policy_path") == "$policy_identity" ]] ||
    die 'package start policy appeared concurrently'

  mask_staging=$(mktemp -d -p "$(dirname -- "$nginx_mask")" .vpn-nginx-mask.XXXXXXXX)
  mask_staging_identity=$(stat -c '%d:%i' "$mask_staging")
  ln -s /dev/null "$mask_staging/mask"
  mask_identity=$(stat -c '%d:%i' "$mask_staging/mask")
  mv -T --no-clobber -- "$mask_staging/mask" "$nginx_mask"
  [[ -L $nginx_mask && $(stat -c '%d:%i' "$nginx_mask") == "$mask_identity" &&
     $(readlink "$nginx_mask") == /dev/null ]] || die 'nginx package mask appeared concurrently'
  rmdir -- "$mask_staging"
}

restore_start_policy() {
  local status=0 reload_mask=0
  if [[ -n $policy_identity ]]; then
    if [[ ! -e $policy_path && ! -L $policy_path ]]; then :
    elif [[ -f $policy_path && ! -L $policy_path &&
            $(stat -c '%d:%i' "$policy_path") == "$policy_identity" ]]; then
      rm -- "$policy_path" || status=1
    else status=1; fi
  fi
  if [[ -n $mask_identity ]]; then
    if [[ ! -e $nginx_mask && ! -L $nginx_mask ]]; then reload_mask=1
    elif [[ -L $nginx_mask && $(stat -c '%d:%i' "$nginx_mask") == "$mask_identity" &&
            $(readlink "$nginx_mask") == /dev/null ]]; then
      if rm -- "$nginx_mask"; then reload_mask=1; else status=1; fi
    else status=1; fi
  fi
  if [[ -n $policy_staged && (-e $policy_staged || -L $policy_staged) ]]; then
    if [[ -f $policy_staged && ! -L $policy_staged &&
          $(stat -c '%d:%i' "$policy_staged") == "$policy_identity" ]]; then
      rm -- "$policy_staged" || status=1
    else status=1; fi
  fi
  if [[ -n $mask_staging && (-e $mask_staging || -L $mask_staging) ]]; then
    if [[ -d $mask_staging && ! -L $mask_staging &&
          $(stat -c '%d:%i' "$mask_staging") == "$mask_staging_identity" ]]; then
      # This link is still inside our private 0700 staging directory if a
      # signal arrived before it was published to the fixed systemd path.
      if [[ -L $mask_staging/mask && $(readlink "$mask_staging/mask") == /dev/null ]]; then
        rm -- "$mask_staging/mask" || status=1
      fi
      rmdir -- "$mask_staging" || status=1
    else status=1; fi
  fi
  if ((reload_mask)); then systemctl daemon-reload >/dev/null 2>&1 || status=1; fi
  if ((status == 0)); then
    policy_identity=''; mask_identity=''; policy_staged=''
    mask_staging=''; mask_staging_identity=''
  fi
  return "$status"
}
