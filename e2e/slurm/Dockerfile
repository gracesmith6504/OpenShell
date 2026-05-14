# syntax=docker/dockerfile:1.4

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      munge \
      procps \
      python3 \
      singularity-container \
      slurm-client \
      slurmctld \
      slurmd \
    && rm -rf /var/lib/apt/lists/*

COPY slurm.conf /etc/slurm/slurm.conf
COPY cgroup.conf /etc/slurm/cgroup.conf
COPY entrypoint.sh /usr/local/bin/openshell-slurm-entrypoint

RUN chmod 0755 /usr/local/bin/openshell-slurm-entrypoint \
    && mkdir -p /etc/munge /run/munge /var/lib/munge /var/log/munge \
      /var/log/slurm /var/spool/slurmctld /var/spool/slurmd /work \
    && python3 - <<'PY' >/etc/munge/munge.key
import sys
sys.stdout.buffer.write((b"openshell-e2e-munge-key-" * 64)[:1024])
PY
RUN chown munge:munge /etc/munge/munge.key /run/munge /var/lib/munge /var/log/munge \
    && chmod 0400 /etc/munge/munge.key \
    && chown -R slurm:slurm /var/log/slurm /var/spool/slurmctld /var/spool/slurmd

ENTRYPOINT ["/usr/local/bin/openshell-slurm-entrypoint"]
CMD ["login"]
