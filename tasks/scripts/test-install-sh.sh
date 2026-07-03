#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
out="${tmpdir}/out"
err="${tmpdir}/err"

export OPENSHELL_INSTALL_SH_TEST=1
# shellcheck source=../../install.sh
. "${ROOT}/install.sh"

assert_glibc_preflight_passes() {
  local name=$1
  local ldd_output=$2

  if ! (export OPENSHELL_TEST_GETCONF_UNAVAILABLE=1 OPENSHELL_TEST_LDD_OUTPUT="$ldd_output"; require_linux_package_glibc) >"$out" 2>"$err"; then
    echo "FAIL: ${name}" >&2
    cat "$err" >&2 || true
    exit 1
  fi
}

assert_glibc_preflight_fails() {
  local name=$1
  local expected=$2
  local setup=$3

  if ("$setup"; require_linux_package_glibc) >"$out" 2>"$err"; then
    echo "FAIL: ${name}: expected failure" >&2
    exit 1
  fi

  if ! grep -Fq -- "$expected" "$err"; then
    echo "FAIL: ${name}: missing expected message" >&2
    echo "Expected: ${expected}" >&2
    echo "Actual:" >&2
    cat "$err" >&2 || true
    exit 1
  fi
}

assert_gateway_failure() {
  local name=$1
  local platform=$2
  local action=$3

  if (
    export PLATFORM="$platform"
    TARGET_USER="test-user"
    TARGET_HOME="${tmpdir}/home"

    as_target_user() {
      if [ "$*" = "$action" ]; then
        return 1
      fi
      return 0
    }
    dump_local_gateway_diagnostics() {
      echo "TEST gateway diagnostics" >&2
    }
    register_local_gateway() { return 0; }
    wait_for_local_gateway_listener() { return 0; }
    wait_for_local_gateway_status() { return 0; }

    case "$platform" in
      linux) start_user_gateway ;;
      darwin) restart_homebrew_gateway "${HOMEBREW_TAP}/${HOMEBREW_FORMULA_NAME}" ;;
    esac
  ) >"$out" 2>"$err"; then
    echo "FAIL: ${name}: expected failure" >&2
    exit 1
  fi

  for expected in \
    "TEST gateway diagnostics" \
    "OpenShell remains installed" \
    "install and start Docker or Podman" \
    "install openshell-driver-vm and explicitly configure compute_drivers = [\"vm\"]"; do
    if ! grep -Fq -- "$expected" "$err"; then
      echo "FAIL: ${name}: missing expected message: ${expected}" >&2
      cat "$err" >&2 || true
      exit 1
    fi
  done
}

assert_driver_parse() {
  local name=$1
  local env_driver=$2
  local expected=$3
  shift 3

  if ! (
    INSTALL_COMPUTE_DRIVER="$env_driver"
    parse_install_args "$@"
    [ "$INSTALL_COMPUTE_DRIVER" = "$expected" ]
  ) >"$out" 2>"$err"; then
    echo "FAIL: ${name}" >&2
    cat "$err" >&2 || true
    exit 1
  fi
}

assert_driver_parse_fails() {
  local name=$1
  local expected=$2
  shift 2

  if (INSTALL_COMPUTE_DRIVER=""; parse_install_args "$@") >"$out" 2>"$err"; then
    echo "FAIL: ${name}: expected failure" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected" "$err"; then
    echo "FAIL: ${name}: missing expected message: ${expected}" >&2
    cat "$err" >&2 || true
    exit 1
  fi
}

assert_driver_configuration() {
  local name=$1
  local driver=$2
  local expected=$3

  if ! (
    INSTALL_COMPUTE_DRIVER="$driver"
    OPENSHELL_GATEWAY_BIN="/test/bin/openshell-gateway"
    as_target_user() {
      printf '%s\n' "$*" >"$out"
    }
    configure_gateway_compute_driver
  ) 2>"$err"; then
    echo "FAIL: ${name}" >&2
    cat "$err" >&2 || true
    exit 1
  fi
  if ! grep -Fxq "$expected" "$out"; then
    echo "FAIL: ${name}: unexpected config command" >&2
    echo "Expected: ${expected}" >&2
    echo "Actual:" >&2
    cat "$out" >&2 || true
    exit 1
  fi
}

assert_driver_prerequisite_notice() {
  local name=$1
  local driver=$2
  local expected_warning=$3
  local expected_url=$4

  if ! (
    INSTALL_COMPUTE_DRIVER="$driver"
    print_compute_driver_prerequisite_notice
  ) >"$out" 2>"$err"; then
    echo "FAIL: ${name}" >&2
    cat "$err" >&2 || true
    exit 1
  fi
  for expected in "$expected_warning" "$expected_url"; do
    if ! grep -Fq -- "$expected" "$err"; then
      echo "FAIL: ${name}: missing expected message: ${expected}" >&2
      cat "$err" >&2 || true
      exit 1
    fi
  done
}

setup_glibc_227() {
  export OPENSHELL_TEST_GETCONF_UNAVAILABLE=1
  export OPENSHELL_TEST_LDD_OUTPUT="ldd (GNU libc) 2.27"
}

setup_missing_glibc() {
  export OPENSHELL_TEST_GETCONF_UNAVAILABLE=1
  export OPENSHELL_TEST_LDD_UNAVAILABLE=1
}

setup_getconf_musl() {
  export OPENSHELL_TEST_LDD_UNAVAILABLE=1
  export OPENSHELL_TEST_GETCONF_OUTPUT="musl libc"
}

setup_ldd_musl() {
  export OPENSHELL_TEST_GETCONF_UNAVAILABLE=1
  export OPENSHELL_TEST_LDD_OUTPUT="musl libc (x86_64)"
}

assert_glibc_preflight_passes "glibc 2.28 passes" "glibc 2.28"
assert_glibc_preflight_passes "glibc 2.31 passes" "glibc 2.31"
assert_glibc_preflight_passes "glibc 2.35 passes" "ldd (GNU libc) 2.35"

if ! (export OPENSHELL_TEST_LDD_UNAVAILABLE=1 OPENSHELL_TEST_GETCONF_OUTPUT="glibc 2.35"; require_linux_package_glibc) >"$out" 2>"$err"; then
  echo "FAIL: getconf glibc fallback passes" >&2
  cat "$err" >&2 || true
  exit 1
fi

if ! (export OPENSHELL_TEST_LDD_OUTPUT="not ldd" OPENSHELL_TEST_GETCONF_OUTPUT="glibc 2.35"; require_linux_package_glibc) >"$out" 2>"$err"; then
  echo "FAIL: unparseable ldd output falls back to getconf" >&2
  cat "$err" >&2 || true
  exit 1
fi

assert_glibc_preflight_fails \
  "glibc 2.27 fails" \
  "OpenShell Linux packages require glibc >= 2.28; detected glibc 2.27." \
  setup_glibc_227

assert_glibc_preflight_fails \
  "missing glibc detection fails" \
  "OpenShell Linux packages require glibc >= 2.28; could not detect glibc." \
  setup_missing_glibc

assert_glibc_preflight_fails \
  "musl detection fails" \
  "OpenShell Linux packages require glibc >= 2.28; detected musl or unsupported libc." \
  setup_getconf_musl

assert_glibc_preflight_fails \
  "ldd musl fallback fails" \
  "OpenShell Linux packages require glibc >= 2.28; detected musl or unsupported libc." \
  setup_ldd_musl

assert_driver_parse \
  "compute-driver flag selects podman" \
  "" \
  podman \
  --compute-driver podman

assert_driver_parse \
  "compute-driver flag overrides environment" \
  podman \
  docker \
  --compute-driver=docker

assert_driver_parse \
  "compute-driver environment is preserved without flag" \
  vm \
  vm

assert_driver_parse_fails \
  "compute-driver rejects unsupported values" \
  "unsupported compute driver 'containerd'" \
  --compute-driver containerd

if (INSTALL_COMPUTE_DRIVER="containerd"; parse_install_args) >"$out" 2>"$err"; then
  echo "FAIL: compute-driver rejects unsupported environment value: expected failure" >&2
  exit 1
fi
if ! grep -Fq -- "unsupported compute driver 'containerd'" "$err"; then
  echo "FAIL: compute-driver rejects unsupported environment value: missing expected message" >&2
  cat "$err" >&2 || true
  exit 1
fi

assert_driver_parse_fails \
  "compute-driver rejects kubernetes for local installs" \
  "use the OpenShell Helm chart" \
  --compute-driver kubernetes

assert_driver_parse_fails \
  "compute-driver requires a value" \
  "--compute-driver requires a value" \
  --compute-driver

assert_driver_configuration \
  "podman selection configures bridge-reachable binding" \
  podman \
  "/test/bin/openshell-gateway config set --compute-driver podman --bind-address 0.0.0.0:17670"

assert_driver_configuration \
  "docker selection configures loopback binding" \
  docker \
  "/test/bin/openshell-gateway config set --compute-driver docker --bind-address 127.0.0.1:17670"

assert_driver_configuration \
  "vm selection configures loopback binding" \
  vm \
  "/test/bin/openshell-gateway config set --compute-driver vm --bind-address 127.0.0.1:17670"

assert_driver_parse_fails \
  "compute-driver leaves automatic selection to the default installation" \
  "unsupported compute driver 'auto'" \
  --compute-driver auto

assert_driver_prerequisite_notice \
  "docker selection prints prerequisite guidance" \
  docker \
  "Docker is not installed or managed by the OpenShell installer" \
  "https://docs.docker.com/engine/install/"

assert_driver_prerequisite_notice \
  "podman selection prints prerequisite guidance" \
  podman \
  "Podman is not installed or managed by the OpenShell installer" \
  "https://podman.io/docs/installation"

assert_gateway_failure \
  "systemd enable failure is actionable" \
  linux \
  "systemctl --user enable openshell-gateway"

assert_gateway_failure \
  "systemd restart failure is actionable" \
  linux \
  "systemctl --user restart openshell-gateway"

assert_gateway_failure \
  "inactive systemd service is actionable" \
  linux \
  "systemctl --user is-active --quiet openshell-gateway"

assert_gateway_failure \
  "Homebrew restart failure is actionable" \
  darwin \
  "brew services restart ${HOMEBREW_TAP}/${HOMEBREW_FORMULA_NAME}"

echo "install.sh tests passed"
