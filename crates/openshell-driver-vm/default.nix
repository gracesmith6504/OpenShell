# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
{
  craneLib,
  craneCommon,
  openshellVmDriverBundle,
}:

craneLib.buildPackage (
  craneCommon
  // {
    pname = "openshell-driver-vm";
    cargoExtraArgs = "--locked -p openshell-driver-vm --bin openshell-driver-vm";

    # The driver's build.rs copies these compressed artifacts into OUT_DIR
    # so they can be embedded via `include_bytes!`. Without this, the build
    # script emits empty stub files and the binary is non-functional.
    OPENSHELL_VM_RUNTIME_COMPRESSED_DIR = "${openshellVmDriverBundle}";
  }
)
