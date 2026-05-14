#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_TEST="${OPENSHELL_E2E_SLURM_TEST:-smoke}"
E2E_FEATURES="${OPENSHELL_E2E_SLURM_FEATURES:-e2e,e2e-slurm}"

cargo build -p openshell-cli --features openshell-core/dev-settings

exec "${ROOT}/e2e/with-slurm-gateway.sh" \
  cargo test --manifest-path "${ROOT}/e2e/rust/Cargo.toml" \
    --features "${E2E_FEATURES}" \
    --test "${E2E_TEST}" \
    -- --nocapture
