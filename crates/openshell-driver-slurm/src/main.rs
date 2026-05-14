// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
use openshell_driver_slurm::{ComputeDriverService, SlurmComputeConfig, SlurmComputeDriver};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "openshell-driver-slurm")]
#[command(version = openshell_core::VERSION)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:50057")]
    bind_address: SocketAddr,
    #[arg(long, env = "OPENSHELL_SLURM_WORK_DIR", default_value_os_t = SlurmComputeConfig::default_work_dir())]
    work_dir: PathBuf,
    #[arg(long, env = "OPENSHELL_SANDBOX_IMAGE")]
    sandbox_image: Option<String>,
    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: String,
    #[arg(long, env = "OPENSHELL_SLURM_PARTITION")]
    partition: Option<String>,
    #[arg(long, env = "OPENSHELL_SLURM_ACCOUNT")]
    account: Option<String>,
    #[arg(long, env = "OPENSHELL_SLURM_QOS")]
    qos: Option<String>,
    #[arg(long, env = "OPENSHELL_SLURM_TIME_LIMIT")]
    time_limit: Option<String>,
    #[arg(long, env = "OPENSHELL_SLURM_APPTAINER_BIN", default_value_t = SlurmComputeConfig::default_apptainer_bin())]
    apptainer_bin: String,
    #[arg(long, env = "OPENSHELL_SLURM_SUPERVISOR_BIN")]
    supervisor_bin: PathBuf,
    #[arg(long, env = "OPENSHELL_SSH_HANDSHAKE_SECRET")]
    ssh_handshake_secret: String,
    #[arg(long, env = "OPENSHELL_SLURM_EXTRA_SBATCH_ARG")]
    extra_sbatch_arg: Vec<String>,
    #[arg(long, env = "OPENSHELL_SLURM_EXTRA_SRUN_ARG")]
    extra_srun_arg: Vec<String>,
    #[arg(long, env = "OPENSHELL_SLURM_EXTRA_APPTAINER_ARG")]
    extra_apptainer_arg: Vec<String>,
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let driver = SlurmComputeDriver::new(SlurmComputeConfig {
        work_dir: args.work_dir,
        default_image: args.sandbox_image.unwrap_or_default(),
        grpc_endpoint: args.grpc_endpoint,
        partition: args.partition,
        account: args.account,
        qos: args.qos,
        time_limit: args.time_limit,
        apptainer_bin: args.apptainer_bin,
        supervisor_bin: args.supervisor_bin,
        ssh_handshake_secret: args.ssh_handshake_secret,
        extra_sbatch_args: args.extra_sbatch_arg,
        extra_srun_args: args.extra_srun_arg,
        extra_apptainer_args: args.extra_apptainer_arg,
        ..SlurmComputeConfig::default()
    })
    .await
    .map_err(|err| miette::miette!("{err}"))?;

    info!(address = %args.bind_address, "Starting Slurm compute driver");
    tonic::transport::Server::builder()
        .add_service(ComputeDriverServer::new(ComputeDriverService::new(driver)))
        .serve(args.bind_address)
        .await
        .map_err(|err| miette::miette!("{err}"))
}
