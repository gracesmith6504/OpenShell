# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
{
  stdenvNoCC,
  zstd,
  openshellLibkrun,
  openshellLibkrunfw,
  openshellSandbox,
  gvproxy,
}:

stdenvNoCC.mkDerivation {
  pname = "openshell-vm-driver-bundle";
  inherit (openshellSandbox) version;

  dontUnpack = true;

  nativeBuildInputs = [ zstd ];

  installPhase = ''
    runHook preInstall

    mkdir -p "$out"
    zstd -19 -T0 -f ${openshellLibkrun}/lib64/libkrun.so -o "$out/libkrun.so.zst"
    zstd -19 -T0 -f ${openshellLibkrunfw}/lib64/libkrunfw.so.5 -o "$out/libkrunfw.so.5.zst"
    zstd -19 -T0 -f ${gvproxy}/bin/gvproxy -o "$out/gvproxy.zst"
    zstd -19 -T0 -f ${openshellSandbox}/bin/openshell-sandbox -o "$out/openshell-sandbox.zst"

    runHook postInstall
  '';
}
