#!/usr/bin/env bash
# Shared options for this installer only; do not change the host's APT policy.
vpn_apt_get() {
  # A fresh cloud image can still be running its own unattended upgrade. Wait
  # for the dpkg lock instead of failing immediately; never delete a lock file.
  # Preserve locally modified conffiles, including the working SSH config.
  DEBIAN_FRONTEND=noninteractive apt-get \
    -o DPkg::Lock::Timeout=180 \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold "$@"
}
