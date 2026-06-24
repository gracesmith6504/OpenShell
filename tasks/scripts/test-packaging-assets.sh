#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

assert_contains() {
  local file=$1
  local expected=$2

  if ! grep -Fq "$expected" "$file"; then
    echo "FAIL: ${file} is missing expected text:" >&2
    echo "  ${expected}" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file=$1
  local unexpected=$2

  if grep -Fq "$unexpected" "$file"; then
    echo "FAIL: ${file} contains stale text:" >&2
    echo "  ${unexpected}" >&2
    exit 1
  fi
}

assert_occurrences() {
  local file=$1
  local expected=$2
  local count=$3
  local actual

  actual=$(grep -F "$expected" "$file" | wc -l | tr -d '[:space:]')
  if [[ "$actual" != "$count" ]]; then
    echo "FAIL: ${file} expected ${count} occurrences of:" >&2
    echo "  ${expected}" >&2
    echo "found ${actual}" >&2
    exit 1
  fi
}

assert_file_exists() {
  local file=$1

  if [[ ! -f "$file" ]]; then
    echo "ERROR: ${file} not found" >&2
    exit 1
  fi
}

service="${ROOT}/deploy/deb/openshell-gateway.service"
spec="${ROOT}/openshell.spec"
snapcraft="${ROOT}/snapcraft.yaml"

assert_file_exists "$service"
assert_file_exists "$spec"
assert_file_exists "$snapcraft"

assert_contains \
  "$service" \
  'Environment=OPENSHELL_LOCAL_TLS_DIR=%h/.local/state/openshell/tls'
assert_contains \
  "$service" \
  'ExecStartPre=/usr/bin/openshell-gateway generate-certs --output-dir ${OPENSHELL_LOCAL_TLS_DIR} --server-san host.openshell.internal'
assert_not_contains "$service" '%S/openshell/tls'

assert_contains \
  "$spec" \
  'Environment=OPENSHELL_LOCAL_TLS_DIR=%%h/.local/state/openshell/tls'
assert_contains \
  "$spec" \
  'ExecStartPre=/usr/bin/openshell-gateway generate-certs --output-dir ${OPENSHELL_LOCAL_TLS_DIR} --server-san host.openshell.internal'
assert_not_contains "$spec" '%%S/openshell/tls'

assert_contains "$snapcraft" 'confinement: strict'
assert_occurrences "$snapcraft" 'XDG_CONFIG_HOME: "$SNAP_USER_COMMON/xdg-config"' 2
assert_occurrences "$snapcraft" 'XDG_DATA_HOME: "$SNAP_USER_COMMON/xdg-data"' 2
assert_occurrences "$snapcraft" 'XDG_STATE_HOME: "$SNAP_USER_COMMON/xdg-state"' 2

echo "packaging asset tests passed"
