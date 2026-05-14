// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::config::DEFAULT_SSH_HANDSHAKE_SKEW_SECS;
use std::path::PathBuf;

const DEFAULT_SLURM_WORK_DIR: &str = "/tmp/openshell-slurm";
const DEFAULT_APPTAINER_BIN: &str = "apptainer";
const DEFAULT_GPU_RESOURCE: &str = "gpu";

/// Gateway-local configuration for the Slurm compute driver.
#[derive(Clone)]
pub struct SlurmComputeConfig {
    /// Shared filesystem directory visible on the login and compute nodes.
    pub work_dir: PathBuf,
    /// Default sandbox image used when the sandbox template does not set one.
    pub default_image: String,
    /// Gateway endpoint reachable from Slurm compute nodes.
    pub grpc_endpoint: String,
    /// Optional Slurm partition.
    pub partition: Option<String>,
    /// Optional Slurm account.
    pub account: Option<String>,
    /// Optional Slurm `QoS`.
    pub qos: Option<String>,
    /// Optional Slurm time limit, passed through to `sbatch --time`.
    pub time_limit: Option<String>,
    /// Apptainer binary on the compute nodes.
    pub apptainer_bin: String,
    /// Host/shared-filesystem path to the `openshell-sandbox` supervisor binary.
    pub supervisor_bin: PathBuf,
    /// Unix socket path the in-sandbox supervisor uses for SSH relay.
    pub sandbox_ssh_socket_path: String,
    /// Shared secret for the NSSH1 SSH handshake.
    pub ssh_handshake_secret: String,
    /// Maximum clock skew in seconds for SSH handshake timestamps.
    pub ssh_handshake_skew_secs: u64,
    /// Default supervisor log level.
    pub log_level: String,
    /// Additional operator-supplied `sbatch` arguments.
    pub extra_sbatch_args: Vec<String>,
    /// Additional operator-supplied `srun` arguments.
    pub extra_srun_args: Vec<String>,
    /// Additional operator-supplied `apptainer exec` arguments.
    pub extra_apptainer_args: Vec<String>,
    /// Slurm GRES name used for `--gres=<name>:1`.
    pub gpu_resource: String,
    /// Shared-filesystem path to the CA certificate for sandbox mTLS.
    pub guest_tls_ca: Option<PathBuf>,
    /// Shared-filesystem path to the client certificate for sandbox mTLS.
    pub guest_tls_cert: Option<PathBuf>,
    /// Shared-filesystem path to the client private key for sandbox mTLS.
    pub guest_tls_key: Option<PathBuf>,
}

impl SlurmComputeConfig {
    #[must_use]
    pub fn default_work_dir() -> PathBuf {
        PathBuf::from(DEFAULT_SLURM_WORK_DIR)
    }

    #[must_use]
    pub fn default_apptainer_bin() -> String {
        DEFAULT_APPTAINER_BIN.to_string()
    }

    #[must_use]
    pub fn default_gpu_resource() -> String {
        DEFAULT_GPU_RESOURCE.to_string()
    }

    #[must_use]
    pub fn tls_enabled(&self) -> bool {
        self.guest_tls_ca.is_some() && self.guest_tls_cert.is_some() && self.guest_tls_key.is_some()
    }

    pub fn validate_tls_config(&self) -> Result<(), String> {
        let has_ca = self.guest_tls_ca.is_some();
        let has_cert = self.guest_tls_cert.is_some();
        let has_key = self.guest_tls_key.is_some();

        if (has_ca && has_cert && has_key) || (!has_ca && !has_cert && !has_key) {
            return Ok(());
        }

        let mut missing = Vec::new();
        if !has_ca {
            missing.push("--slurm-tls-ca / OPENSHELL_SLURM_TLS_CA");
        }
        if !has_cert {
            missing.push("--slurm-tls-cert / OPENSHELL_SLURM_TLS_CERT");
        }
        if !has_key {
            missing.push("--slurm-tls-key / OPENSHELL_SLURM_TLS_KEY");
        }

        Err(format!(
            "Partial Slurm TLS configuration: all three TLS paths must be provided together. Missing: {}",
            missing.join(", ")
        ))
    }
}

impl Default for SlurmComputeConfig {
    fn default() -> Self {
        Self {
            work_dir: Self::default_work_dir(),
            default_image: String::new(),
            grpc_endpoint: String::new(),
            partition: None,
            account: None,
            qos: None,
            time_limit: None,
            apptainer_bin: Self::default_apptainer_bin(),
            supervisor_bin: PathBuf::from("/usr/local/bin/openshell-sandbox"),
            sandbox_ssh_socket_path: "/run/openshell/ssh.sock".to_string(),
            ssh_handshake_secret: String::new(),
            ssh_handshake_skew_secs: DEFAULT_SSH_HANDSHAKE_SKEW_SECS,
            log_level: "info".to_string(),
            extra_sbatch_args: Vec::new(),
            extra_srun_args: Vec::new(),
            extra_apptainer_args: Vec::new(),
            gpu_resource: Self::default_gpu_resource(),
            guest_tls_ca: None,
            guest_tls_cert: None,
            guest_tls_key: None,
        }
    }
}

impl std::fmt::Debug for SlurmComputeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlurmComputeConfig")
            .field("work_dir", &self.work_dir)
            .field("default_image", &self.default_image)
            .field("grpc_endpoint", &self.grpc_endpoint)
            .field("partition", &self.partition)
            .field("account", &self.account)
            .field("qos", &self.qos)
            .field("time_limit", &self.time_limit)
            .field("apptainer_bin", &self.apptainer_bin)
            .field("supervisor_bin", &self.supervisor_bin)
            .field("sandbox_ssh_socket_path", &self.sandbox_ssh_socket_path)
            .field("ssh_handshake_secret", &"[REDACTED]")
            .field("ssh_handshake_skew_secs", &self.ssh_handshake_skew_secs)
            .field("log_level", &self.log_level)
            .field("extra_sbatch_args", &self.extra_sbatch_args)
            .field("extra_srun_args", &self.extra_srun_args)
            .field("extra_apptainer_args", &self.extra_apptainer_args)
            .field("gpu_resource", &self.gpu_resource)
            .field("guest_tls_ca", &self.guest_tls_ca)
            .field("guest_tls_cert", &self.guest_tls_cert)
            .field("guest_tls_key", &self.guest_tls_key)
            .finish()
    }
}
