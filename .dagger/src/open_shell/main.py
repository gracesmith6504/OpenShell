# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import re
from dataclasses import dataclass

import dagger
from dagger import dag, function, object_type

DEFAULT_TOOLCHAIN_IMAGE = "ghcr.io/nvidia/openshell/ci:latest"
WORKDIR = "/src"
# Workflow parity: rust-native-build.yml includes the Zig-wrapper hash in its
# Rust cache key. Bump this whenever the Dagger copy of that wrapper changes.
RUST_TARGET_CACHE_GENERATION = "zig-musl-wrapper-v1"

RUST_BUILD_SOURCE_INCLUDE = [
    ".cargo/",
    "Cargo.lock",
    "Cargo.toml",
    "crates/",
    "mise.lock",
    "mise.toml",
    "providers/",
    "proto/",
    "rust-toolchain.toml",
]

_CARGO_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_FEATURES_RE = re.compile(r"^[0-9A-Za-z_, -]*$")


@dataclass(frozen=True)
class RustBuildSpec:
    component: str
    arch: str
    platform: dagger.Platform
    crate: str
    binary: str
    rust_target: str
    zig_target: str


def _rust_build_spec(component: str, arch: str) -> RustBuildSpec:
    # Workflow parity: "Resolve build target" in rust-native-build.yml.
    if component != "cli":
        raise ValueError(
            "component must be 'cli'; sandbox and gateway will be added incrementally"
        )

    match arch:
        case "amd64":
            platform = dagger.Platform("linux/amd64")
            rust_target = "x86_64-unknown-linux-musl"
            zig_target = "x86_64-linux-musl"
        case "arm64":
            platform = dagger.Platform("linux/arm64")
            rust_target = "aarch64-unknown-linux-musl"
            zig_target = "aarch64-linux-musl"
        case _:
            raise ValueError("arch must be one of: amd64, arm64")

    return RustBuildSpec(
        component=component,
        arch=arch,
        platform=platform,
        crate="openshell-cli",
        binary="openshell",
        rust_target=rust_target,
        zig_target=zig_target,
    )


def _validate_inputs(cargo_version: str, features: str) -> None:
    if cargo_version and not _CARGO_VERSION_RE.fullmatch(cargo_version):
        raise ValueError("cargo-version must be a valid Cargo package version")
    if not _FEATURES_RE.fullmatch(features):
        raise ValueError("features contains unsupported characters")


@object_type
class OpenShell:
    """Build reproducible OpenShell artifacts."""

    @function
    def rust_native_build(
        self,
        source_path: str = ".",
        component: str = "cli",
        arch: str = "amd64",
        cargo_version: str = "",
        image_tag: str = "dagger",
        features: str = "bundled-z3",
        toolchain_image: str = DEFAULT_TOOLCHAIN_IMAGE,
        github_username: str = "",
        github_token: dagger.Secret | None = None,
    ) -> dagger.Directory:
        """Build one native Linux Rust artifact; currently supports the CLI."""
        spec = _rust_build_spec(component, arch)
        _validate_inputs(cargo_version, features)

        project_source = dag.current_workspace().directory(
            source_path,
            include=RUST_BUILD_SOURCE_INCLUDE,
            gitignore=True,
        )
        base = dag.container(platform=spec.platform)
        if github_token is not None:
            if not github_username:
                raise ValueError(
                    "github-username is required when github-token is provided"
                )
            base = base.with_registry_auth("ghcr.io", github_username, github_token)

        container = (
            base.from_(toolchain_image)
            .with_directory(WORKDIR, project_source)
            .with_workdir(WORKDIR)
            # Workflow parity: "Cache Rust target and registry".
            .with_mounted_cache(
                "/root/.cargo/registry",
                dag.cache_volume(f"openshell-cargo-registry-{spec.arch}"),
            )
            .with_mounted_cache(
                "/root/.cargo/git",
                dag.cache_volume(f"openshell-cargo-git-{spec.arch}"),
            )
            .with_mounted_cache(
                f"{WORKDIR}/target",
                dag.cache_volume(
                    "openshell-cargo-target-"
                    f"{spec.component}-{spec.arch}-{RUST_TARGET_CACHE_GENERATION}"
                ),
            )
            .with_mounted_cache(
                f"{WORKDIR}/.cache/sccache",
                dag.cache_volume(f"openshell-sccache-{spec.component}-{spec.arch}"),
            )
            .with_env_variable("CARGO_INCREMENTAL", "0")
            .with_env_variable("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1")
            .with_env_variable("OPENSHELL_IMAGE_TAG", image_tag)
            .with_env_variable("RUST_BUILD_ARCH", spec.arch)
            .with_env_variable("RUST_BUILD_BINARY", spec.binary)
            .with_env_variable("RUST_BUILD_CRATE", spec.crate)
            .with_env_variable("RUST_BUILD_FEATURES", features)
            .with_env_variable("RUST_BUILD_TARGET", spec.rust_target)
            .with_env_variable("RUST_BUILD_ZIG_TARGET", spec.zig_target)
        )

        if github_token is not None:
            container = container.with_secret_variable(
                "MISE_GITHUB_TOKEN", github_token
            )

        # Workflow parity: "Install tools". Trust is Dagger-specific because
        # the repository is mounted at /src instead of Actions' checkout path.
        container = container.with_exec(
            ["mise", "trust", f"{WORKDIR}/mise.toml"]
        ).with_exec(["mise", "install", "--locked"])

        if cargo_version:
            # Workflow parity: "Patch workspace version".
            container = (
                container.with_env_variable("OPENSHELL_CARGO_VERSION", cargo_version)
                .with_env_variable("GIT_DIR", "/nonexistent")
                .with_exec(
                    [
                        "bash",
                        "-ec",
                        "sed -i -E "
                        "'/^\\[workspace\\.package\\]/,/^\\[/{"
                        's/^version[[:space:]]*=[[:space:]]*".*"/'
                        'version = "\'"$OPENSHELL_CARGO_VERSION"\'"/}\' '
                        "Cargo.toml",
                    ]
                )
            )

        build_script = r"""
set -euo pipefail

# Workflow parity: target installation from "Build <binary> (<target>)".
mise x -- rustup target add "$RUST_BUILD_TARGET"

# Workflow parity: "Set up zig musl wrappers".
ZIG="$(mise which zig)"
mkdir -p /tmp/zig-musl

# cc-rs injects a Rust target triple that Zig does not parse, so use the
# workflow's Zig target.
for tool in cc c++; do
  printf '#!/bin/bash\nargs=()\nfor arg in "$@"; do\n  case "$arg" in\n    --target=*) ;;\n    *) args+=("$arg") ;;\n  esac\ndone\nexec "%s" %s --target=%s "${args[@]}"\n' \
    "$ZIG" "$tool" "$RUST_BUILD_ZIG_TARGET" > "/tmp/zig-musl/${tool}"
  chmod +x "/tmp/zig-musl/${tool}"
done

target_env=${RUST_BUILD_TARGET//[-.]/_}
target_env_upper=${target_env^^}
export "CC_${target_env}=/tmp/zig-musl/cc"
export "CXX_${target_env}=/tmp/zig-musl/c++"
export "CARGO_TARGET_${target_env_upper}_LINKER=/tmp/zig-musl/cc"
export "CARGO_TARGET_${target_env_upper}_RUSTFLAGS=-Clink-self-contained=no"
# Workflow parity: CLI-specific C++ runtime selection in "Build <binary>".
export CXXSTDLIB=c++

# Workflow parity: Cargo invocation from "Build <binary> (<target>)".
args=(
  build
  --release
  --target "$RUST_BUILD_TARGET"
  -p "$RUST_BUILD_CRATE"
  --bin "$RUST_BUILD_BINARY"
)
if [[ -n "$RUST_BUILD_FEATURES" ]]; then
  args+=(--features "$RUST_BUILD_FEATURES")
fi

mise x -- cargo "${args[@]}"
"""

        verify_script = r"""
set -euo pipefail
# Workflow parity: "Verify packaged binary".
binary="target/${RUST_BUILD_TARGET}/release/${RUST_BUILD_BINARY}"
output="$("$binary" --version)"
echo "$output"
grep -q "^${RUST_BUILD_BINARY} " <<<"$output"
ldd --version
ldd "$binary" || true
"""

        stage_script = r"""
set -euo pipefail
# Workflow parity: "Stage binary for prebuilt layout".
binary="target/${RUST_BUILD_TARGET}/release/${RUST_BUILD_BINARY}"
mkdir -p /out
install -m 0755 "$binary" "/out/${RUST_BUILD_BINARY}"
"""

        return (
            container.with_exec(["bash", "-ec", build_script])
            .with_exec(["bash", "-ec", verify_script])
            .with_exec(["bash", "-ec", stage_script])
            .directory("/out")
        )
