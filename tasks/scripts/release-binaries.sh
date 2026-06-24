#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

case "$(uname -m)" in
    x86_64 | amd64)
        arch_name="amd64"
        cli_target="x86_64-unknown-linux-musl"
        cli_zig_target="x86_64-linux-musl"
        gnu_target="x86_64-unknown-linux-gnu"
        gnu_zig_target="x86_64-unknown-linux-gnu.2.28"
        vm_platform="linux-x86_64"
        guest_arch="x86_64"
        ;;
    aarch64 | arm64)
        arch_name="arm64"
        cli_target="aarch64-unknown-linux-musl"
        cli_zig_target="aarch64-linux-musl"
        gnu_target="aarch64-unknown-linux-gnu"
        gnu_zig_target="aarch64-unknown-linux-gnu.2.28"
        vm_platform="linux-aarch64"
        guest_arch="aarch64"
        ;;
    *)
        echo "unsupported build architecture: $(uname -m)" >&2
        exit 2
        ;;
esac

create_zig_musl_wrappers() {
    export ZIG_BIN
    ZIG_BIN="$(mise which zig)"
    export ZIG_TARGET="${cli_zig_target}"

    mkdir -p /tmp/zig-musl
    for tool in cc c++; do
        cat >"/tmp/zig-musl/${tool}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

args=()
for arg in "$@"; do
    case "$arg" in
        --target=*) ;;
        *) args+=("$arg") ;;
    esac
done

exec "$ZIG_BIN" "$(basename "$0")" --target="$ZIG_TARGET" "${args[@]}"
EOF
        chmod +x "/tmp/zig-musl/${tool}"
    done

    target_env="${cli_target//-/_}"
    target_env_upper="${target_env^^}"

    export "CC_${target_env}=/tmp/zig-musl/cc"
    export "CXX_${target_env}=/tmp/zig-musl/c++"
    export "CARGO_TARGET_${target_env_upper}_LINKER=/tmp/zig-musl/cc"
    export "CARGO_TARGET_${target_env_upper}_RUSTFLAGS=-Clink-self-contained=no"
    export CXXSTDLIB="c++"
}

stage_vm_runtime() {
    vm_runtime_dir="${PWD}/target/vm-runtime-compressed"
    vm_runtime_tarball="${PWD}/artifacts/vm-runtime-${vm_platform}.tar.zst"
    export OPENSHELL_VM_RUNTIME_COMPRESSED_DIR="${vm_runtime_dir}"

    tasks/scripts/vm/build-libkrun.sh
    tasks/scripts/vm/package-vm-runtime.sh \
        --platform "${vm_platform}" \
        --build-dir target/libkrun-build \
        --output "${vm_runtime_tarball}"
    VM_RUNTIME_TARBALL="${vm_runtime_tarball}" \
        VM_RUNTIME_PLATFORM="${vm_platform}" \
        tasks/scripts/vm/compress-vm-runtime.sh
    tasks/scripts/vm/build-supervisor-bundle.sh --arch "${guest_arch}"

    for file in \
        libkrun.so.zst \
        libkrunfw.so.5.zst \
        gvproxy.zst \
        umoci.zst \
        openshell-sandbox.zst; do
        test -s "${vm_runtime_dir}/${file}"
    done
}

git config --global --add safe.directory "${PWD}"

mise trust "${PWD}/mise.toml"
mise install --locked
mise x -- rustup target add "${cli_target}" "${gnu_target}"

create_zig_musl_wrappers

mise x -- cargo build \
    --release \
    --target "${cli_target}" \
    -p openshell-cli \
    --features bundled-z3

eval "$(
    tasks/scripts/setup-zig-cc-wrapper.sh \
        "${gnu_zig_target}" \
        "${gnu_zig_target}" \
        "${PWD}/target/zig-gnu-wrapper/${arch_name}"
)"

mise x -- cargo zigbuild \
    --release \
    --target "${gnu_zig_target}" \
    -p openshell-server \
    --bin openshell-gateway \
    --features bundled-z3

stage_vm_runtime

mise x -- cargo zigbuild \
    --release \
    --target "${gnu_zig_target}" \
    -p openshell-driver-vm \
    --bin openshell-driver-vm

tasks/scripts/verify-glibc-symbols.sh \
    2.28 \
    "target/${gnu_target}/release/openshell-gateway" \
    "target/${gnu_target}/release/openshell-driver-vm"

mkdir -p /out/bin
install -m 0755 "target/${cli_target}/release/openshell" /out/bin/openshell
install -m 0755 "target/${gnu_target}/release/openshell-gateway" /out/bin/openshell-gateway
install -m 0755 "target/${gnu_target}/release/openshell-driver-vm" /out/bin/openshell-driver-vm

/out/bin/openshell --version
/out/bin/openshell-gateway --version
/out/bin/openshell-driver-vm --version
