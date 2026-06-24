#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

STATE_DIR="${OPENSHELL_DIND_STATE_DIR:-/var/lib/openshell-dind}"
DOCKER_DATA_ROOT="${OPENSHELL_DIND_DOCKER_DATA_ROOT:-${STATE_DIR}/docker}"
LOG_DIR="${OPENSHELL_DIND_LOG_DIR:-/var/log/openshell-dind}"
PORT="${OPENSHELL_SERVER_PORT:-18080}"
GATEWAY_NAME="${OPENSHELL_DOCKER_GATEWAY_NAME:-dind-dev}"
SANDBOX_NAMESPACE="${OPENSHELL_SANDBOX_NAMESPACE:-dind-dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
SANDBOX_IMAGE_PULL_POLICY="${OPENSHELL_SANDBOX_IMAGE_PULL_POLICY:-IfNotPresent}"
SUPERVISOR_BIN="${OPENSHELL_SUPERVISOR_BIN:-/usr/local/libexec/openshell/openshell-sandbox}"
STORAGE_DRIVER="${OPENSHELL_DIND_STORAGE_DRIVER:-vfs}"

export DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-${STATE_DIR}/config}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-${STATE_DIR}/data}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-${STATE_DIR}/state}"

mkdir -p \
  /var/run \
  "${DOCKER_DATA_ROOT}" \
  "${LOG_DIR}" \
  "${XDG_CONFIG_HOME}" \
  "${XDG_DATA_HOME}" \
  "${XDG_STATE_HOME}"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: DinD requires root. Start this terminal with Dagger insecure root capabilities." >&2
  exit 1
fi

has_cap() {
  local bit=$1
  local cap_eff
  cap_eff="$(awk '/^CapEff:/ { print $2 }' /proc/self/status 2>/dev/null || echo 0)"
  [ $((16#${cap_eff} & (1 << bit))) -ne 0 ]
}

if ! has_cap 12 || ! has_cap 21; then
  cat >&2 <<'EOF'
ERROR: DinD requires NET_ADMIN and SYS_ADMIN capabilities.

Start the terminal with:
  dagger call installed-deb-dind-container --arch <amd64|arm64> terminal --insecure-root-capabilities
EOF
  exit 1
fi

if [ ! -x "${SUPERVISOR_BIN}" ]; then
  echo "ERROR: openshell-sandbox supervisor binary is missing: ${SUPERVISOR_BIN}" >&2
  exit 1
fi

wait_for_docker() {
  for _ in $(seq 1 60); do
    if docker info >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

start_dockerd() {
  if docker info >/dev/null 2>&1; then
    return 0
  fi

  if [ -S /var/run/docker.sock ] && ! pgrep -x dockerd >/dev/null 2>&1; then
    rm -f /var/run/docker.sock
  fi

  if ! pgrep -x dockerd >/dev/null 2>&1; then
    echo "Starting nested dockerd..."
    # shellcheck disable=SC2086
    dockerd \
      --host=unix:///var/run/docker.sock \
      --storage-driver="${STORAGE_DRIVER}" \
      --data-root="${DOCKER_DATA_ROOT}" \
      ${OPENSHELL_DIND_DOCKERD_FLAGS:-} \
      >"${LOG_DIR}/dockerd.log" 2>&1 &
    echo "$!" >"${STATE_DIR}/dockerd.pid"
  fi

  if ! wait_for_docker; then
    echo "ERROR: nested dockerd did not become ready." >&2
    tail -200 "${LOG_DIR}/dockerd.log" >&2 || true
    exit 1
  fi
}

write_gateway_config() {
  local tls_dir="${STATE_DIR}/tls"
  local config_path="${STATE_DIR}/gateway.toml"

  openshell-gateway generate-certs \
    --output-dir "${tls_dir}" \
    --server-san "127.0.0.1" \
    --server-san "localhost" \
    --server-san "host.openshell.internal" \
    >/dev/null

  cat >"${config_path}" <<EOF
[openshell]
version = 1

[openshell.gateway]
compute_drivers = ["docker"]
disable_tls = true

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${tls_dir}/jwt/signing.pem"
public_key_path = "${tls_dir}/jwt/public.pem"
kid_path = "${tls_dir}/jwt/kid"
gateway_id = "${GATEWAY_NAME}"
ttl_secs = 3600

[openshell.drivers.docker]
default_image = "${SANDBOX_IMAGE}"
image_pull_policy = "${SANDBOX_IMAGE_PULL_POLICY}"
sandbox_namespace = "${SANDBOX_NAMESPACE}"
supervisor_bin = "${SUPERVISOR_BIN}"
EOF

  printf '%s' "${config_path}"
}

register_gateway_metadata() {
  local endpoint="http://127.0.0.1:${PORT}"
  local gateway_dir="${XDG_CONFIG_HOME}/openshell/gateways/${GATEWAY_NAME}"

  mkdir -p "${gateway_dir}"
  cat >"${gateway_dir}/metadata.json" <<EOF
{
  "name": "${GATEWAY_NAME}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${PORT},
  "auth_mode": "plaintext"
}
EOF
  printf '%s' "${GATEWAY_NAME}" >"${XDG_CONFIG_HOME}/openshell/active_gateway"
}

wait_for_gateway() {
  for _ in $(seq 1 60); do
    if openshell status >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

start_gateway() {
  local config_path
  config_path="$(write_gateway_config)"
  register_gateway_metadata

  if [ -f "${STATE_DIR}/gateway.pid" ] && kill -0 "$(cat "${STATE_DIR}/gateway.pid")" 2>/dev/null; then
    return 0
  fi

  echo "Starting OpenShell gateway..."
  OPENSHELL_DB_URL="sqlite:${STATE_DIR}/gateway.db?mode=rwc" \
    openshell-gateway \
      --config "${config_path}" \
      --port "${PORT}" \
      --log-level "${OPENSHELL_LOG_LEVEL:-info}" \
      --drivers docker \
      --disable-tls \
      --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc" \
      >"${LOG_DIR}/openshell-gateway.log" 2>&1 &
  echo "$!" >"${STATE_DIR}/gateway.pid"

  if ! wait_for_gateway; then
    echo "ERROR: OpenShell gateway did not become ready." >&2
    tail -200 "${LOG_DIR}/openshell-gateway.log" >&2 || true
    exit 1
  fi
}

start_dockerd
start_gateway

cat <<EOF
OpenShell DinD environment ready.
  gateway: ${GATEWAY_NAME} (http://127.0.0.1:${PORT})
  sandbox namespace: ${SANDBOX_NAMESPACE}
  dockerd log: ${LOG_DIR}/dockerd.log
  gateway log: ${LOG_DIR}/openshell-gateway.log

Try:
  openshell status
  openshell sandbox create
EOF

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

exec /bin/bash
