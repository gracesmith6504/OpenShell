# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
{ libkrun, libkrunfw }:

(libkrun.override {
  withBlk = true;
  withNet = true;
  inherit libkrunfw;
}).overrideAttrs
  (old: {
    pname = "openshell-libkrun";
  })
