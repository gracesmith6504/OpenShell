#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

role="${1:-login}"

mkdir -p /run/munge /var/lib/munge /var/log/munge /var/log/slurm /work
chown -R munge:munge /run/munge /var/lib/munge /var/log/munge
chown -R slurm:slurm /var/log/slurm /var/spool/slurmctld /var/spool/slurmd

if ! pgrep -x munged >/dev/null 2>&1; then
  munged --force
fi

case "${role}" in
  controller)
    exec slurmctld -Dvvv
    ;;
  compute)
    until getent hosts controller >/dev/null 2>&1; do
      sleep 1
    done
    mkdir -p /run/netns
    mountpoint -q /run/netns || mount --bind /run/netns /run/netns
    exec slurmd -Dvvv
    ;;
  login)
    exec sleep infinity
    ;;
  *)
    exec "$@"
    ;;
esac
