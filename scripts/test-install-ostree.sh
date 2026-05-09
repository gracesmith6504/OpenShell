#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ORIG_PATH="${PATH}"

OPENSHELL_INSTALL_SOURCE_ONLY=1
export OPENSHELL_INSTALL_SOURCE_ONLY
. "${ROOT}/install.sh"

PASS=0
FAIL=0

pass() {
  PASS=$((PASS + 1))
  printf '  PASS: %s\n' "$1"
}

fail() {
  FAIL=$((FAIL + 1))
  printf '  FAIL: %s\n' "$1" >&2
  if [ -n "${2:-}" ]; then
    printf '        %s\n' "$2" >&2
  fi
}

assert_eq() {
  _actual="$1"
  _expected="$2"
  _label="$3"

  if [ "$_actual" = "$_expected" ]; then
    pass "$_label"
  else
    fail "$_label" "expected '${_expected}', got '${_actual}'"
  fi
}

assert_contains() {
  _file="$1"
  _pattern="$2"
  _label="$3"

  if grep -qF "$_pattern" "$_file"; then
    pass "$_label"
  else
    fail "$_label" "expected '${_pattern}' in ${_file}"
  fi
}

make_fake_cmd() {
  _dir="$1"
  _name="$2"

  cat >"${_dir}/${_name}" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod 0755 "${_dir}/${_name}"
}

test_ostree_detection_prefers_rpm_ostree() {
  printf 'TEST: ostree detection routes to rpm-ostree install path\n'

  _tmpdir="$(mktemp -d)"
  make_fake_cmd "$_tmpdir" rpm
  make_fake_cmd "$_tmpdir" dpkg

  OPENSHELL_TEST_OSTREE_BOOTED=1
  PATH="${_tmpdir}:${ORIG_PATH}"
  export OPENSHELL_TEST_OSTREE_BOOTED PATH

  _method="$(linux_package_method)"
  assert_eq "$_method" "rpm-ostree" "ostree host uses rpm-ostree method"

  unset OPENSHELL_TEST_OSTREE_BOOTED
  PATH="$ORIG_PATH"
  export PATH
  rm -rf "$_tmpdir"
}

test_ostree_unit_uses_user_local_paths() {
  printf 'TEST: generated ostree unit uses user-local paths and local gateway port\n'

  _tmpdir="$(mktemp -d)"
  _unit="${_tmpdir}/openshell-gateway.service"
  TARGET_HOME="${_tmpdir}/home"
  RELEASE_TAG=dev
  export TARGET_HOME RELEASE_TAG

  write_ostree_gateway_unit \
    "$_unit" \
    "${TARGET_HOME}/.local/bin/openshell-gateway" \
    "${TARGET_HOME}/.local/libexec/openshell/init-pki.sh" \
    "${TARGET_HOME}/.local/libexec/openshell/init-gateway-env.sh"

  assert_contains "$_unit" "ExecStart=${TARGET_HOME}/.local/bin/openshell-gateway" "ExecStart points to user-local gateway"
  assert_contains "$_unit" "ExecStartPre=${TARGET_HOME}/.local/libexec/openshell/init-pki.sh %S/openshell/tls" "PKI helper points to user-local libexec"
  assert_contains "$_unit" "ExecStartPre=${TARGET_HOME}/.local/libexec/openshell/init-gateway-env.sh %E/openshell/gateway.env" "env helper points to user-local libexec"
  assert_contains "$_unit" "Environment=OPENSHELL_SERVER_PORT=17670" "unit uses installer gateway port"
  assert_contains "$_unit" "Environment=OPENSHELL_SUPERVISOR_IMAGE=ghcr.io/nvidia/openshell/supervisor:dev" "dev release uses dev supervisor image"

  rm -rf "$_tmpdir"
}

test_stable_release_uses_latest_supervisor() {
  printf 'TEST: stable release unit uses latest supervisor image\n'

  _tmpdir="$(mktemp -d)"
  _unit="${_tmpdir}/openshell-gateway.service"
  RELEASE_TAG=v0.0.37
  export RELEASE_TAG

  write_ostree_gateway_unit \
    "$_unit" \
    "${_tmpdir}/openshell-gateway" \
    "${_tmpdir}/init-pki.sh" \
    "${_tmpdir}/init-gateway-env.sh"

  assert_contains "$_unit" "Environment=OPENSHELL_SUPERVISOR_IMAGE=ghcr.io/nvidia/openshell/supervisor:latest" "stable release uses latest supervisor image"

  rm -rf "$_tmpdir"
}

printf '=== install.sh ostree tests ===\n\n'

test_ostree_detection_prefers_rpm_ostree
echo ""
test_ostree_unit_uses_user_local_paths
echo ""
test_stable_release_uses_latest_supervisor

printf '\n=== Results: %d passed, %d failed ===\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
