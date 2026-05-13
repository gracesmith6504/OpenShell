# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
{
  craneLib,
  craneCommon,
}:

craneLib.buildPackage (
  craneCommon
  // {
    pname = "openshell-sandbox";
    cargoExtraArgs = "--locked -p openshell-sandbox --bin openshell-sandbox";
  }
)
