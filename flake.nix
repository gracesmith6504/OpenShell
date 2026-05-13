# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
{
  description = "OpenShell development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      treefmt-nix,
    }:
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ]
      (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };

          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };

          openshellLibkrunfw = pkgs.callPackage ./nix/libkrunfw.nix { };
          openshellLibkrun = pkgs.callPackage ./nix/libkrun.nix {
            libkrunfw = openshellLibkrunfw;
          };
          openshellVmDriverBundle = pkgs.callPackage ./nix/openshell-vm-driver-bundle.nix {
            inherit openshellLibkrun openshellLibkrunfw;
          };

          treefmt = treefmt-nix.lib.evalModule pkgs {
            projectRootFile = "flake.nix";
            programs.nixfmt.enable = true;
          };
        in
        {
          packages = pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
            openshell-libkrunfw = openshellLibkrunfw;
            openshell-libkrun = openshellLibkrun;
            openshell-vm-driver-bundle = openshellVmDriverBundle;
          };

          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              rustToolchain
              pkg-config
              llvmPackages.libclang
              z3
            ];

            env = {
              LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            }
            // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
              OPENSHELL_VM_RUNTIME_COMPRESSED_DIR = "${openshellVmDriverBundle}";
            };
          };

          formatter = treefmt.config.build.wrapper;
        }
      );
}
