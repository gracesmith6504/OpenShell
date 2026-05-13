# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
{
  libkrunfw,
  variant ? null,
}:

(libkrunfw.override { inherit variant; }).overrideAttrs (old: {
  pname = "openshell-${old.pname}";

  postPatch = ''
    ${old.postPatch or ""}

    for config in config-libkrunfw*_aarch64 config-libkrunfw*_x86_64; do
      [ -f "$config" ] || continue
      printf '\n# OpenShell VM kernel config fragment\n' >> "$config"
      cat ${../crates/openshell-driver-vm/runtime/kernel/openshell.kconfig} >> "$config"
    done
  '';
})
