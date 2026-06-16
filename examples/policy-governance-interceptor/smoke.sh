#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

GATEWAY_PORT="${GATEWAY_PORT:-18096}"
HEALTH_PORT="${HEALTH_PORT:-18097}"
INTERCEPTOR_HOST="${INTERCEPTOR_HOST:-127.0.0.1}"
INTERCEPTOR_PORT="${INTERCEPTOR_PORT:-18098}"
INTERCEPTOR_ADDR="${INTERCEPTOR_HOST}:${INTERCEPTOR_PORT}"
GATEWAY_ENDPOINT="${GATEWAY_ENDPOINT:-http://127.0.0.1:${GATEWAY_PORT}}"
SANDBOX_NAME="${SANDBOX_NAME:-policy-governance-smoke-$$}"
CUSTOM_SANDBOX_NAME="${CUSTOM_SANDBOX_NAME:-${SANDBOX_NAME}-custom}"
KEEP_SMOKE_ARTIFACTS="${KEEP_SMOKE_ARTIFACTS:-0}"
CARGO_FEATURES="${CARGO_FEATURES:-openshell-server/gh-release-z3,openshell-cli/gh-release-z3}"
SMOKE_CC="${SMOKE_CC:-clang}"
SMOKE_CXX="${SMOKE_CXX:-clang++}"
SMOKE_RUSTC_WRAPPER="${SMOKE_RUSTC_WRAPPER-}"

SMOKE_TMP_PARENT="${SMOKE_TMP_PARENT:-/tmp}"
TMP_DIR="$(mktemp -d "${SMOKE_TMP_PARENT%/}/ospgi.XXXXXX")"
GATEWAY_CONFIG="${TMP_DIR}/gateway.toml"
GATEWAY_DB="${TMP_DIR}/gateway.db"
PKI_DIR="${TMP_DIR}/pki"
CUSTOM_POLICY="${TMP_DIR}/custom-policy.yaml"
INTERCEPTOR_LOG="${TMP_DIR}/interceptor.log"
GATEWAY_LOG="${TMP_DIR}/gateway.log"

OPENSHELL_BIN="${REPO_ROOT}/target/debug/openshell"
GATEWAY_BIN="${REPO_ROOT}/target/debug/openshell-gateway"
INTERCEPTOR_BIN="${REPO_ROOT}/target/debug/policy-governance-interceptor"

INTERCEPTOR_PID=""
GATEWAY_PID=""
FAILED=0
LAST_OUTPUT=""

OS=("${OPENSHELL_BIN}" --gateway-endpoint "${GATEWAY_ENDPOINT}")

cleanup() {
    local status=$?

    if [[ -x "${OPENSHELL_BIN}" ]]; then
        "${OS[@]}" sandbox delete "${SANDBOX_NAME}" >/dev/null 2>&1 || true
        "${OS[@]}" sandbox delete "${CUSTOM_SANDBOX_NAME}" >/dev/null 2>&1 || true
    fi

    if [[ -n "${GATEWAY_PID}" ]] && kill -0 "${GATEWAY_PID}" >/dev/null 2>&1; then
        kill "${GATEWAY_PID}" >/dev/null 2>&1 || true
        wait "${GATEWAY_PID}" 2>/dev/null || true
    fi
    if [[ -n "${INTERCEPTOR_PID}" ]] && kill -0 "${INTERCEPTOR_PID}" >/dev/null 2>&1; then
        kill "${INTERCEPTOR_PID}" >/dev/null 2>&1 || true
        wait "${INTERCEPTOR_PID}" 2>/dev/null || true
    fi

    if [[ "${KEEP_SMOKE_ARTIFACTS}" == "1" || ${status} -ne 0 ]]; then
        printf "smoke artifacts: %s\n" "${TMP_DIR}" >&2
    else
        rm -rf "${TMP_DIR}"
    fi
}
trap cleanup EXIT

run_capture() {
    local output
    if output="$("$@" 2>&1)"; then
        LAST_OUTPUT="${output}"
        return 0
    fi
    local status=$?
    LAST_OUTPUT="${output}"
    return "${status}"
}

captured_error_output() {
    [[ "${LAST_OUTPUT}" == *"Error:"* || "${LAST_OUTPUT}" == *"× code:"* ]]
}

expect_success() {
    run_capture "$@" || return 1
    ! captured_error_output
}

expect_failure() {
    if run_capture "$@"; then
        if captured_error_output; then
            return 0
        fi
        LAST_OUTPUT="command unexpectedly succeeded: $*"$'\n'"${LAST_OUTPUT}"
        return 1
    fi
    return 0
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    if [[ "${haystack}" != *"${needle}"* ]]; then
        LAST_OUTPUT="expected output to contain '${needle}'"$'\n'"${haystack}"
        return 1
    fi
}

run_case() {
    local name="$1"
    shift

    LAST_OUTPUT=""
    if "$@"; then
        printf "PASS %s\n" "${name}"
    else
        printf "FAIL %s\n" "${name}"
        if [[ -n "${LAST_OUTPUT}" ]]; then
            printf "%s\n" "${LAST_OUTPUT}" | sed 's/^/  /'
        fi
        FAILED=1
    fi
}

wait_for_interceptor() {
    for _ in $(seq 1 100); do
        if (exec 3<>"/dev/tcp/${INTERCEPTOR_HOST}/${INTERCEPTOR_PORT}") >/dev/null 2>&1; then
            return 0
        fi
        if ! kill -0 "${INTERCEPTOR_PID}" >/dev/null 2>&1; then
            printf "interceptor exited early\n" >&2
            sed 's/^/  /' "${INTERCEPTOR_LOG}" >&2 || true
            exit 1
        fi
        sleep 0.1
    done

    printf "interceptor did not become ready at %s\n" "${INTERCEPTOR_ADDR}" >&2
    sed 's/^/  /' "${INTERCEPTOR_LOG}" >&2 || true
    exit 1
}

wait_for_gateway() {
    for _ in $(seq 1 120); do
        if "${OS[@]}" status >/dev/null 2>&1; then
            return 0
        fi
        if ! kill -0 "${GATEWAY_PID}" >/dev/null 2>&1; then
            printf "gateway exited early\n" >&2
            sed 's/^/  /' "${GATEWAY_LOG}" >&2 || true
            exit 1
        fi
        sleep 0.5
    done

    printf "gateway did not become ready at %s\n" "${GATEWAY_ENDPOINT}" >&2
    sed 's/^/  /' "${GATEWAY_LOG}" >&2 || true
    exit 1
}

write_gateway_config() {
    cat > "${GATEWAY_CONFIG}" <<EOF
[openshell]
version = 1

[openshell.gateway]
bind_address = "127.0.0.1:${GATEWAY_PORT}"
health_bind_address = "127.0.0.1:${HEALTH_PORT}"
log_level = "info"
compute_drivers = ["docker"]
disable_tls = true

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${PKI_DIR}/jwt/signing.pem"
public_key_path = "${PKI_DIR}/jwt/public.pem"
kid_path = "${PKI_DIR}/jwt/kid"
gateway_id = "policy-governance-smoke"
ttl_secs = 0

[[openshell.gateway.interceptors]]
name = "policy-governance"
endpoint = "grpc://${INTERCEPTOR_ADDR}"
order = 100
timeout = "2s"
failure_policy = "fail_closed"
EOF
}

write_custom_policy() {
    cat > "${CUSTOM_POLICY}" <<'EOF'
version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  custom_example:
    name: custom-example
    endpoints:
      - host: example.com
        port: 443
        protocol: rest
        access: read-only
        enforcement: enforce
    binaries:
      - { path: /usr/bin/curl }
EOF
}

build_binaries() {
    local build_cmd=(
        cargo build
        -p openshell-server
        -p openshell-cli
        -p policy-governance-interceptor
    )
    if [[ -n "${CARGO_FEATURES}" ]]; then
        build_cmd+=(--features "${CARGO_FEATURES}")
    fi

    printf "Building smoke binaries...\n"
    (
        cd "${REPO_ROOT}"
        CC="${SMOKE_CC}" \
            CXX="${SMOKE_CXX}" \
            RUSTC_WRAPPER="${SMOKE_RUSTC_WRAPPER}" \
            "${build_cmd[@]}"
    )
}

generate_jwt_bundle() {
    XDG_CONFIG_HOME="${TMP_DIR}/xdg-config" \
        "${GATEWAY_BIN}" generate-certs \
        --output-dir "${PKI_DIR}" \
        --server-san 127.0.0.1 >/dev/null
}

start_interceptor() {
    "${INTERCEPTOR_BIN}" "${INTERCEPTOR_ADDR}" >"${INTERCEPTOR_LOG}" 2>&1 &
    INTERCEPTOR_PID=$!
    wait_for_interceptor
}

start_gateway() {
    (
        unset OPENSHELL_GATEWAY_CONFIG
        unset OPENSHELL_BIND_ADDRESS
        unset OPENSHELL_SERVER_PORT
        unset OPENSHELL_HEALTH_PORT
        unset OPENSHELL_METRICS_PORT
        unset OPENSHELL_DISABLE_TLS
        unset OPENSHELL_DRIVERS
        unset OPENSHELL_TLS_CERT
        unset OPENSHELL_TLS_KEY
        unset OPENSHELL_TLS_CLIENT_CA
        unset OPENSHELL_ENABLE_MTLS_AUTH
        unset OPENSHELL_OIDC_ISSUER
        export OPENSHELL_DB_URL="sqlite:${GATEWAY_DB}?mode=rwc"
        exec "${GATEWAY_BIN}" --config "${GATEWAY_CONFIG}"
    ) >"${GATEWAY_LOG}" 2>&1 &
    GATEWAY_PID=$!
    wait_for_gateway
}

create_governed_providers() {
    "${OS[@]}" provider create \
        --name github \
        --type github \
        --credential GITHUB_TOKEN=openshell-smoke-github >/dev/null
    "${OS[@]}" provider create \
        --name gitlab \
        --type gitlab \
        --credential GITLAB_TOKEN=openshell-smoke-gitlab >/dev/null
}

test_interceptor_vended_policy() {
    expect_success "${OS[@]}" sandbox create \
        --name "${SANDBOX_NAME}" \
        --keep \
        --no-auto-providers \
        --no-tty \
        -- echo "sandbox ready" || return 1

    expect_success "${OS[@]}" sandbox get "${SANDBOX_NAME}" --policy-only || return 1
    local policy="${LAST_OUTPUT}"
    assert_contains "${policy}" "github-source-control-readonly" || return 1
    assert_contains "${policy}" "gitlab-source-control-readonly" || return 1
    assert_contains "${policy}" "api.github.com" || return 1
    assert_contains "${policy}" "gitlab.com" || return 1

    expect_success "${OS[@]}" sandbox get "${SANDBOX_NAME}" || return 1
    local sandbox="${LAST_OUTPUT}"
    assert_contains "${sandbox}" "governance.nvidia.com/signature: eyJ" || return 1
}

test_existing_policy_cannot_change() {
    expect_failure "${OS[@]}" policy update "${SANDBOX_NAME}" \
        --add-endpoint example.com:443:read-only:rest:enforce \
        --wait \
        --timeout 20 || return 1
    expect_failure "${OS[@]}" policy set "${SANDBOX_NAME}" \
        --policy "${CUSTOM_POLICY}" \
        --wait \
        --timeout 20
}

test_custom_policy_create_denied() {
    expect_failure "${OS[@]}" sandbox create \
        --name "${CUSTOM_SANDBOX_NAME}" \
        --policy "${CUSTOM_POLICY}" \
        --no-auto-providers \
        --no-tty \
        -- echo "should not run"
}

test_provider_attach_detach_locked() {
    expect_failure "${OS[@]}" sandbox provider attach "${SANDBOX_NAME}" github || return 1
    expect_failure "${OS[@]}" sandbox provider detach "${SANDBOX_NAME}" github || return 1
}

test_new_provider_create_denied() {
    expect_failure "${OS[@]}" provider create \
        --name slack \
        --type generic \
        --credential API_KEY=openshell-smoke-slack
}

test_provider_modify_denied() {
    expect_failure "${OS[@]}" provider update github \
        --credential GITHUB_TOKEN=openshell-smoke-updated
}

build_binaries
generate_jwt_bundle
write_gateway_config
write_custom_policy
start_interceptor
start_gateway
create_governed_providers

printf "Smoke endpoint: %s\n" "${GATEWAY_ENDPOINT}"

run_case "sandboxes receive the interceptor-vended policy" test_interceptor_vended_policy
run_case "existing sandbox policies cannot be changed" test_existing_policy_cannot_change
run_case "sandboxes cannot be created with custom policies" test_custom_policy_create_denied
run_case "only the governed provider set can remain attached" test_provider_attach_detach_locked
run_case "new providers cannot be created" test_new_provider_create_denied
run_case "providers cannot be modified" test_provider_modify_denied

if [[ ${FAILED} -ne 0 ]]; then
    exit 1
fi

printf "policy governance interceptor smoke passed\n"
