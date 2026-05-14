#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run an e2e command against an OpenShell gateway running on a Docker Compose
# Slurm login node. The gateway creates Apptainer-backed sandbox jobs through
# sbatch/srun on the compose compute node.

set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "Usage: e2e/with-slurm-gateway.sh <command> [args...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"

normalize_arch() {
  case "$1" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "$1" ;;
  esac
}

compose_cmd() {
  docker compose -p "${COMPOSE_PROJECT}" -f "${ROOT}/e2e/slurm/docker-compose.yml" "$@"
}

WORKDIR_PARENT="${TMPDIR:-/tmp}"
WORKDIR_PARENT="${WORKDIR_PARENT%/}"
WORKDIR="$(mktemp -d "${WORKDIR_PARENT}/openshell-e2e-slurm.XXXXXX")"
COMPOSE_PROJECT="openshell-slurm-$$"
BIN_DIR="${WORKDIR}/bin"
GATEWAY_LOG="/work/gateway.log"
GATEWAY_PID_FILE="/work/gateway.pid"
HOST_PORT=""
CLI_BIN=""
E2E_XDG_DATA_HOME="${WORKDIR}/data"

export XDG_CONFIG_HOME="${WORKDIR}/config"

cleanup() {
  local exit_code=$?

  if command -v docker >/dev/null 2>&1; then
    compose_cmd exec -T login sh -lc \
      'if [ -f /work/gateway.pid ]; then kill "$(cat /work/gateway.pid)" >/dev/null 2>&1 || true; fi' \
      >/dev/null 2>&1 || true
    if [ "${exit_code}" -ne 0 ]; then
      echo "=== slurm gateway log (preserved for debugging) ==="
      compose_cmd exec -T login sh -lc 'cat /work/gateway.log 2>/dev/null || true' || true
      echo "=== compose logs (preserved for debugging) ==="
      compose_cmd logs --no-color || true
      echo "=== end slurm logs ==="
    fi
    compose_cmd down -v --remove-orphans >/dev/null 2>&1 || true
  fi

  rm -rf "${WORKDIR}" 2>/dev/null || true
}
trap cleanup EXIT

if [ -n "${OPENSHELL_GATEWAY_ENDPOINT:-}" ]; then
  case "${OPENSHELL_GATEWAY_ENDPOINT}" in
    http://*) ;;
    https://*)
      echo "ERROR: OPENSHELL_GATEWAY_ENDPOINT endpoint mode is HTTP-only for Slurm e2e." >&2
      exit 2
      ;;
    *)
      echo "ERROR: OPENSHELL_GATEWAY_ENDPOINT must start with http:// for Slurm e2e endpoint mode." >&2
      exit 2
      ;;
  esac

  export XDG_DATA_HOME="${E2E_XDG_DATA_HOME}"
  GATEWAY_NAME="${OPENSHELL_GATEWAY:-openshell-e2e-slurm-endpoint}"
  e2e_register_plaintext_gateway \
    "${XDG_CONFIG_HOME}" \
    "${GATEWAY_NAME}" \
    "${OPENSHELL_GATEWAY_ENDPOINT}" \
    "$(e2e_endpoint_port "${OPENSHELL_GATEWAY_ENDPOINT}")"
  export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
  export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-360}"
  export OPENSHELL_E2E_DRIVER="${OPENSHELL_E2E_DRIVER:-slurm}"

  echo "Using existing Slurm e2e gateway endpoint: ${OPENSHELL_GATEWAY_ENDPOINT}"
  "$@"
  exit $?
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker CLI is required to run Slurm e2e tests" >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: docker daemon is not reachable (docker info failed)" >&2
  exit 2
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose is required to run Slurm e2e tests" >&2
  exit 2
fi

target_dir="$(e2e_cargo_target_dir "${ROOT}")"
CLI_BIN="${target_dir}/debug/openshell"
echo "Building openshell CLI..."
cargo build -p openshell-cli --bin openshell --features openshell-core/dev-settings

DAEMON_ARCH="$(normalize_arch "$(docker info --format '{{.Architecture}}' 2>/dev/null || true)")"
echo "Staging Linux gateway and supervisor binaries for linux/${DAEMON_ARCH}..."
PREBUILT_ARCH="${DAEMON_ARCH}" "${ROOT}/tasks/scripts/stage-prebuilt-binaries.sh" all
mkdir -p "${BIN_DIR}"
cp "${ROOT}/deploy/docker/.build/prebuilt-binaries/${DAEMON_ARCH}/openshell-gateway" "${BIN_DIR}/openshell-gateway"
cp "${ROOT}/deploy/docker/.build/prebuilt-binaries/${DAEMON_ARCH}/openshell-sandbox" "${BIN_DIR}/openshell-sandbox"
chmod 0755 "${BIN_DIR}/openshell-gateway" "${BIN_DIR}/openshell-sandbox"

export XDG_DATA_HOME="${E2E_XDG_DATA_HOME}"
HOST_PORT="$(e2e_pick_port)"
export OPENSHELL_SLURM_GATEWAY_PORT="${HOST_PORT}"
export OPENSHELL_SLURM_BIN_DIR="${BIN_DIR}"

echo "Starting local Slurm cluster (${COMPOSE_PROJECT})..."
compose_cmd up -d --build

echo "Waiting for Slurm to become ready..."
elapsed=0
timeout=120
while [ "${elapsed}" -lt "${timeout}" ]; do
  if compose_cmd exec -T login sinfo -h >/dev/null 2>&1; then
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
if [ "${elapsed}" -ge "${timeout}" ]; then
  echo "ERROR: Slurm did not become ready within ${timeout}s" >&2
  exit 1
fi

DEFAULT_SANDBOX_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
SANDBOX_IMAGE="${OPENSHELL_E2E_SLURM_SANDBOX_IMAGE:-${OPENSHELL_SANDBOX_IMAGE:-${DEFAULT_SANDBOX_IMAGE}}}"
HANDSHAKE_SECRET="e2e-slurm-$(python3 -c 'import secrets; print(secrets.token_hex(16))')"

echo "Starting openshell-gateway on Slurm login node (host port ${HOST_PORT})..."
compose_cmd exec -T login sh -lc "
  rm -f ${GATEWAY_PID_FILE}
  OPENSHELL_SSH_HANDSHAKE_SECRET='${HANDSHAKE_SECRET}' \
    /opt/openshell/bin/openshell-gateway \
      --bind-address 0.0.0.0 \
      --port 8080 \
      --drivers slurm \
      --disable-tls \
      --db-url 'sqlite:/work/gateway.db?mode=rwc' \
      --grpc-endpoint 'http://login:8080' \
      --sandbox-image '${SANDBOX_IMAGE}' \
      --sandbox-image-pull-policy missing \
      --slurm-work-dir /work/openshell \
      --slurm-apptainer-bin singularity \
      --slurm-extra-apptainer-arg=--writable-tmpfs \
      --slurm-extra-apptainer-arg=--bind \
      --slurm-extra-apptainer-arg=/run/netns:/run/netns \
      --slurm-supervisor-bin /opt/openshell/bin/openshell-sandbox \
      --log-level info \
      >${GATEWAY_LOG} 2>&1 &
  echo \$! > ${GATEWAY_PID_FILE}
"

GATEWAY_NAME="openshell-e2e-slurm-${HOST_PORT}"
CLI_GATEWAY_ENDPOINT="http://127.0.0.1:${HOST_PORT}"
e2e_register_plaintext_gateway \
  "${XDG_CONFIG_HOME}" \
  "${GATEWAY_NAME}" \
  "${CLI_GATEWAY_ENDPOINT}" \
  "${HOST_PORT}"

export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-360}"
export OPENSHELL_E2E_DRIVER="slurm"

echo "Waiting for gateway to become healthy..."
elapsed=0
timeout=120
last_status_output=""
while [ "${elapsed}" -lt "${timeout}" ]; do
  if last_status_output="$("${CLI_BIN}" status 2>&1)"; then
    echo "Gateway healthy after ${elapsed}s."
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
if [ "${elapsed}" -ge "${timeout}" ]; then
  echo "ERROR: gateway did not become healthy within ${timeout}s" >&2
  printf '%s\n' "${last_status_output}"
  exit 1
fi

echo "Running e2e command against ${CLI_GATEWAY_ENDPOINT}: $*"
"$@"
