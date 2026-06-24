# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import dagger
from dagger import dag, function, object_type

PACKAGE_IMAGE = "ubuntu:24.04"
WORKDIR = "/src"

CI_IMAGE_SOURCE_INCLUDE = [
    "deploy/docker/Dockerfile.ci",
    "mise.lock",
    "mise.toml",
    "tasks/",
]

BUILD_SOURCE_INCLUDE = [
    ".cargo/",
    "Cargo.lock",
    "Cargo.toml",
    "crates/",
    "mise.lock",
    "mise.toml",
    "providers/",
    "proto/",
    "rust-toolchain.toml",
    "tasks/",
]

PACKAGE_SOURCE_INCLUDE = [
    "LICENSE",
    "deploy/deb/",
    "tasks/scripts/package-deb.sh",
    "tasks/scripts/release.py",
]

GIT_SOURCE_INCLUDE = [".git/"]


def _platform_for_arch(arch: str) -> dagger.Platform | None:
    match arch:
        case "amd64":
            return dagger.Platform("linux/amd64")
        case "arm64":
            return dagger.Platform("linux/arm64")
        case _:
            raise ValueError("arch must be one of: amd64, arm64")


@object_type
class OpenShell:
    """Build and smoke-test OpenShell release packages."""

    def _workspace_dir(
        self,
        source_path: str,
        include: list[str],
        *,
        gitignore: bool = True,
    ) -> dagger.Directory:
        return dag.current_workspace().directory(
            source_path,
            include=include,
            gitignore=gitignore,
        )

    def _build_source(self, source_path: str) -> dagger.Directory:
        return self._workspace_dir(source_path, BUILD_SOURCE_INCLUDE)

    def _ci_image_source(self, source_path: str) -> dagger.Directory:
        return self._workspace_dir(source_path, CI_IMAGE_SOURCE_INCLUDE)

    def _ci_image(self, source_path: str, arch: str) -> dagger.Container:
        return self._ci_image_source(source_path).docker_build(
            dockerfile="deploy/docker/Dockerfile.ci",
            platform=_platform_for_arch(arch),
        )

    def _package_source(self, source_path: str) -> dagger.Directory:
        return self._workspace_dir(source_path, PACKAGE_SOURCE_INCLUDE)

    def _git_dir(self, source_path: str) -> dagger.Directory:
        return self._workspace_dir(
            source_path,
            GIT_SOURCE_INCLUDE,
            gitignore=False,
        ).directory(".git")

    def _source_container(
        self,
        arch: str,
        image: str,
        project_source: dagger.Directory,
    ) -> dagger.Container:
        platform = _platform_for_arch(arch)
        return (
            dag.container(platform=platform)
            .from_(image)
            .with_directory(WORKDIR, project_source)
            .with_workdir(WORKDIR)
        )

    def _release_build_container(
        self,
        arch: str,
        source_path: str,
        project_source: dagger.Directory,
        git_dir: dagger.Directory,
    ) -> dagger.Container:
        return (
            self._ci_image(source_path, arch)
            .with_directory(WORKDIR, project_source)
            .with_workdir(WORKDIR)
            .with_mounted_directory(f"{WORKDIR}/.git", git_dir, read_only=True)
            .with_mounted_cache(
                f"{WORKDIR}/target",
                dag.cache_volume(f"openshell-ci-target-{arch}"),
            )
            .with_mounted_cache(
                "/root/.cargo/registry",
                dag.cache_volume(f"openshell-cargo-registry-{arch}"),
            )
            .with_mounted_cache(
                "/root/.cargo/git",
                dag.cache_volume(f"openshell-cargo-git-{arch}"),
            )
            .with_mounted_cache(
                f"{WORKDIR}/.cache/sccache",
                dag.cache_volume(f"openshell-sccache-{arch}"),
            )
            .with_env_variable("OPENSHELL_IMAGE_TAG", "dagger")
            .with_exec(["bash", "tasks/scripts/release-binaries.sh"])
        )

    @function
    def release_binaries(
        self,
        arch: str,
        source_path: str = ".",
    ) -> dagger.Directory:
        """Build the binaries consumed by tasks/scripts/package-deb.sh."""
        build_source = self._build_source(source_path)
        return self._release_build_container(
            arch,
            source_path,
            build_source,
            self._git_dir(source_path),
        ).directory("/out/bin")

    @function
    def deb_package(
        self,
        arch: str,
        source_path: str = ".",
        version: str | None = None,
    ) -> dagger.Directory:
        """Build an OpenShell Debian package and return the artifact directory."""
        build_source = self._build_source(source_path)
        package_source = self._package_source(source_path)
        git_dir = self._git_dir(source_path)
        package_input = self._release_build_container(
            arch,
            source_path,
            build_source,
            git_dir,
        ).directory(
            "/out/bin"
        )
        arch_export = f'export OPENSHELL_DEB_ARCH="{arch}"'
        version_export = (
            f'export OPENSHELL_DEB_VERSION="{version}"'
            if version
            else 'export OPENSHELL_DEB_VERSION="$(python3 tasks/scripts/release.py get-version --deb)"'
        )
        package_script = "\n".join(
            [
                "set -euo pipefail",
                arch_export,
                'export OPENSHELL_CLI_BINARY="/out/bin/openshell"',
                'export OPENSHELL_GATEWAY_BINARY="/out/bin/openshell-gateway"',
                'export OPENSHELL_DRIVER_VM_BINARY="/out/bin/openshell-driver-vm"',
                'git config --global --add safe.directory "$PWD"',
                version_export,
                'export OPENSHELL_OUTPUT_DIR="/out/deb"',
                "tasks/scripts/package-deb.sh",
                "ls -lh /out/deb",
            ]
        )
        return (
            self._source_container(arch, PACKAGE_IMAGE, package_source)
            .with_mounted_directory(
                f"{WORKDIR}/.git",
                git_dir,
                read_only=True,
            )
            .with_mounted_directory("/out/bin", package_input, read_only=True)
            .with_env_variable("DEBIAN_FRONTEND", "noninteractive")
            .with_exec(
                [
                    "bash",
                    "-lc",
                    "apt-get update && apt-get install -y --no-install-recommends "
                    "dpkg-dev gzip git python3 systemd && rm -rf /var/lib/apt/lists/*",
                ]
            )
            .with_exec(["bash", "-lc", package_script])
            .directory("/out/deb")
        )

    @function
    def installed_deb_container(
        self,
        arch: str,
        source_path: str = ".",
        version: str | None = None,
        base_image: str = "ubuntu:24.04",
    ) -> dagger.Container:
        """Install the built Debian package into a separate end-user container."""
        platform = _platform_for_arch(arch)
        package_dir = self.deb_package(
            arch=arch,
            source_path=source_path,
            version=version,
        )
        return (
            dag.container(platform=platform)
            .from_(base_image)
            .with_mounted_directory("/packages", package_dir, read_only=True)
            .with_env_variable("DEBIAN_FRONTEND", "noninteractive")
            .with_exec(
                [
                    "bash",
                    "-lc",
                    "\n".join(
                        [
                            "set -euo pipefail",
                            "apt-get update",
                            "apt-get install -y --no-install-recommends "
                            "ca-certificates init-system-helpers",
                            "dpkg -i /packages/openshell_*.deb",
                            "rm -rf /var/lib/apt/lists/*",
                        ]
                    ),
                ]
            )
        )

    @function
    async def deb_install_smoke(
        self,
        arch: str,
        source_path: str = ".",
        version: str | None = None,
        base_image: str = "ubuntu:24.04",
    ) -> str:
        """Build the .deb, install it in a fresh container, and verify binaries."""
        return await (
            self.installed_deb_container(
                arch=arch,
                source_path=source_path,
                version=version,
                base_image=base_image,
            )
            .with_exec(
                [
                    "bash",
                    "-lc",
                    "\n".join(
                        [
                            "set -euo pipefail",
                            "openshell --version",
                            "openshell-gateway --version",
                            "/usr/libexec/openshell/openshell-driver-vm --version",
                            "test -f /usr/lib/systemd/user/openshell-gateway.service",
                            "dpkg -L openshell | sort",
                        ]
                    ),
                ]
            )
            .stdout()
        )
