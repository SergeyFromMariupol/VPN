#!/usr/bin/env bash
# Prepare a complete resumable state before the first installation transaction.
# The caller owns an EXIT trap and invokes cleanup_installation_bootstrap.
bootstrap_committed=0
bootstrap_source=''
bootstrap_source_identity=''
bootstrap_state=''
bootstrap_state_identity=''
bootstrap_target_dir=''
bootstrap_target_dir_identity=''
bootstrap_target_identity=''

bootstrap_identity() { stat -c '%d:%i' -- "$1"; }

bootstrap_remove_owned() {
  local path=$1 identity=$2
  [[ -n $identity ]] || return 0
  [[ -e $path || -L $path ]] || return 0
  if [[ -L $path || $(bootstrap_identity "$path") != "$identity" ]]; then
    printf 'BOOTSTRAP_CLEANUP_REFUSED=%s\n' "$path" >&2
    return 1
  fi
  rm -rf -- "$path"
}

cleanup_installation_bootstrap() {
  local failed=0
  if (( !bootstrap_committed )); then
    bootstrap_remove_owned "$destination" "$bootstrap_source_identity" || failed=1
    bootstrap_remove_owned "$state" "$bootstrap_state_identity" || failed=1
    bootstrap_remove_owned "$target_file" "$bootstrap_target_identity" || failed=1
  fi
  bootstrap_remove_owned "$bootstrap_source" "$bootstrap_source_identity" || failed=1
  bootstrap_remove_owned "$bootstrap_state" "$bootstrap_state_identity" || failed=1
  bootstrap_remove_owned "$bootstrap_target_dir" "$bootstrap_target_dir_identity" || failed=1
  (( !failed ))
}

bootstrap_publish() {
  local staged=$1 final=$2 identity=$3
  # Staging is on the same filesystem. -n never replaces a path created by
  # another operation; inode readback also detects mv's successful no-op case.
  mv -nT -- "$staged" "$final"
  [[ ! -L $final && $(bootstrap_identity "$final") == "$identity" ]] || {
    printf 'BOOTSTRAP_PUBLISH_CONFLICT=%s\n' "$final" >&2
    return 1
  }
}

prepare_installation_bootstrap() {
  bootstrap_source=$(mktemp -d "${destination}.bootstrap.XXXXXXXX")
  bootstrap_source_identity=$(bootstrap_identity "$bootstrap_source")
  bootstrap_state=$(mktemp -d "${state}.bootstrap.XXXXXXXX")
  bootstrap_state_identity=$(bootstrap_identity "$bootstrap_state")
  bootstrap_target_dir=$(mktemp -d "${target_file}.bootstrap.XXXXXXXX")
  bootstrap_target_dir_identity=$(bootstrap_identity "$bootstrap_target_dir")

  cp -a -- "$source_dir/." "$bootstrap_source/"
  # GitHub archives may contain group-writable files. Normalize only our copy.
  chown -hR root:root "$bootstrap_source"
  find "$bootstrap_source" -type d -exec chmod go-w {} +
  find "$bootstrap_source" -type f -exec chmod go-w {} +
  chmod 0700 "$bootstrap_source" "$bootstrap_state" "$bootstrap_target_dir"
  (cd -- "$bootstrap_source"; sha256sum --check --strict SHA256SUMS >/dev/null)
  python3 "$bootstrap_source/tools/write-target.py" "$bootstrap_target_dir/target.env"
  bootstrap_target_identity=$(bootstrap_identity "$bootstrap_target_dir/target.env")
  cp -- "$task_stage/inventory.txt" "$bootstrap_state/inventory-before.txt"
  cat /proc/sys/kernel/random/boot_id >"$bootstrap_state/install-boot-id"
  cp -a -- "$bootstrap_source/bundle" "$bootstrap_state/bundle"
  python3 "$bootstrap_source/tools/render.py" "$bootstrap_state/bundle"
  chmod 0700 "$bootstrap_state/bundle"
  (cd -- "$bootstrap_state/bundle"; sha256sum --check --strict SOURCE_SHA256SUMS >/dev/null)

  bootstrap_publish "$bootstrap_source" "$destination" "$bootstrap_source_identity"
  bootstrap_publish "$bootstrap_state" "$state" "$bootstrap_state_identity"
  bootstrap_publish "$bootstrap_target_dir/target.env" "$target_file" "$bootstrap_target_identity"
  [[ $(stat -c '%U:%G:%a' "$destination") == root:root:700 &&
     $(stat -c '%U:%G:%a' "$state") == root:root:700 &&
     $(stat -c '%U:%G:%a' "$target_file") == root:root:600 ]]
  # Every managed path is now complete and can be resumed. From this point on,
  # transaction-specific rollback owns mutations; the bootstrap retains state.
  bootstrap_committed=1
}
