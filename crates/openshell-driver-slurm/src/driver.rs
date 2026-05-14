// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Slurm compute driver.

use crate::config::SlurmComputeConfig;
use futures::Stream;
use openshell_core::ComputeDriverError;
use openshell_core::proto::compute::v1::{
    DriverCondition, DriverPlatformEvent, DriverResourceRequirements, DriverSandbox,
    DriverSandboxStatus, GetCapabilitiesResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesPlatformEvent, WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

const WATCH_BUFFER: usize = 128;
const WATCH_INTERVAL: Duration = Duration::from_secs(2);
const SLURM_JOB_PREFIX: &str = "openshell";
const SUPERVISOR_MOUNT_PATH: &str = "/opt/openshell/bin/openshell-sandbox";
const TLS_CA_MOUNT_PATH: &str = "/etc/openshell/tls/client/ca.crt";
const TLS_CERT_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.crt";
const TLS_KEY_MOUNT_PATH: &str = "/etc/openshell/tls/client/tls.key";
const SUPERVISOR_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const SANDBOX_COMMAND: &str = "sleep infinity";

pub type WatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, SlurmDriverError>> + Send>>;

#[derive(Debug, thiserror::Error)]
pub enum SlurmDriverError {
    #[error("sandbox already exists")]
    AlreadyExists,
    #[error("{0}")]
    Precondition(String),
    #[error("{0}")]
    Message(String),
}

impl From<SlurmDriverError> for ComputeDriverError {
    fn from(value: SlurmDriverError) -> Self {
        match value {
            SlurmDriverError::AlreadyExists => Self::AlreadyExists,
            SlurmDriverError::Precondition(message) => Self::Precondition(message),
            SlurmDriverError::Message(message) => Self::Message(message),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SlurmCommandOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[tonic::async_trait]
pub trait SlurmCommandRunner: Send + Sync + 'static {
    async fn run(
        &self,
        program: &str,
        args: &[String],
    ) -> Result<SlurmCommandOutput, SlurmDriverError>;
}

#[derive(Debug, Default)]
struct SystemCommandRunner;

#[tonic::async_trait]
impl SlurmCommandRunner for SystemCommandRunner {
    async fn run(
        &self,
        program: &str,
        args: &[String],
    ) -> Result<SlurmCommandOutput, SlurmDriverError> {
        let output = Command::new(program)
            .args(args)
            .output()
            .await
            .map_err(|err| SlurmDriverError::Message(format!("run {program}: {err}")))?;

        Ok(SlurmCommandOutput {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SlurmSandboxState {
    sandbox_id: String,
    sandbox_name: String,
    job_id: String,
    job_name: String,
    created_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalMarkerState {
    Starting,
    Running,
    Exited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalStatusMarker {
    state: LocalMarkerState,
    exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SlurmJobSnapshot {
    state: String,
    reason: String,
}

#[derive(Clone)]
pub struct SlurmComputeDriver {
    config: SlurmComputeConfig,
    runner: Arc<dyn SlurmCommandRunner>,
    events: broadcast::Sender<WatchSandboxesEvent>,
}

impl std::fmt::Debug for SlurmComputeDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlurmComputeDriver")
            .field("work_dir", &self.config.work_dir)
            .field("default_image", &self.config.default_image)
            .field("grpc_endpoint", &self.config.grpc_endpoint)
            .finish()
    }
}

impl SlurmComputeDriver {
    pub async fn new(config: SlurmComputeConfig) -> Result<Self, SlurmDriverError> {
        Self::with_runner(config, Arc::new(SystemCommandRunner)).await
    }

    pub async fn with_runner(
        config: SlurmComputeConfig,
        runner: Arc<dyn SlurmCommandRunner>,
    ) -> Result<Self, SlurmDriverError> {
        let (events, _) = broadcast::channel(WATCH_BUFFER);
        let driver = Self {
            config,
            runner,
            events,
        };
        driver.preflight().await?;
        Ok(driver)
    }

    async fn preflight(&self) -> Result<(), SlurmDriverError> {
        if self.config.grpc_endpoint.trim().is_empty() {
            return Err(SlurmDriverError::Precondition(
                "grpc_endpoint is required when using the slurm compute driver".to_string(),
            ));
        }
        self.config
            .validate_tls_config()
            .map_err(SlurmDriverError::Precondition)?;
        ensure_executable_file(&self.config.supervisor_bin, "slurm supervisor binary")?;
        if self.config.tls_enabled() {
            ensure_readable_file(
                self.config
                    .guest_tls_ca
                    .as_ref()
                    .expect("checked by tls_enabled"),
                "slurm TLS CA",
            )?;
            ensure_readable_file(
                self.config
                    .guest_tls_cert
                    .as_ref()
                    .expect("checked by tls_enabled"),
                "slurm TLS certificate",
            )?;
            ensure_readable_file(
                self.config
                    .guest_tls_key
                    .as_ref()
                    .expect("checked by tls_enabled"),
                "slurm TLS private key",
            )?;
        }
        tokio::fs::create_dir_all(&self.config.work_dir)
            .await
            .map_err(|err| {
                SlurmDriverError::Precondition(format!(
                    "create slurm work dir '{}': {err}",
                    self.config.work_dir.display()
                ))
            })?;
        set_private_dir_permissions(&self.config.work_dir).await?;

        for program in [
            "sbatch",
            "srun",
            "squeue",
            "scancel",
            &self.config.apptainer_bin,
        ] {
            self.require_command(program).await?;
        }

        info!(
            work_dir = %self.config.work_dir.display(),
            grpc_endpoint = %self.config.grpc_endpoint,
            "Slurm compute driver ready"
        );
        Ok(())
    }

    async fn require_command(&self, program: &str) -> Result<(), SlurmDriverError> {
        let args = vec!["--version".to_string()];
        let output = self.runner.run(program, &args).await?;
        if output.status == Some(0) {
            return Ok(());
        }
        Err(SlurmDriverError::Precondition(format!(
            "required Slurm driver command '{program}' failed: {}",
            trim_command_error(&output)
        )))
    }

    #[must_use]
    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            driver_name: "slurm".to_string(),
            driver_version: openshell_core::VERSION.to_string(),
            default_image: self.config.default_image.clone(),
            supports_gpu: true,
            gpu_count: 0,
        }
    }

    pub fn validate_sandbox_create(&self, sandbox: &DriverSandbox) -> Result<(), SlurmDriverError> {
        validate_sandbox_shape(sandbox, &self.config)
    }

    pub async fn create_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), SlurmDriverError> {
        self.validate_sandbox_create(sandbox)?;
        let sandbox_dir = self.sandbox_dir(&sandbox.id)?;
        if sandbox_dir.exists() {
            return Err(SlurmDriverError::AlreadyExists);
        }

        tokio::fs::create_dir_all(&sandbox_dir)
            .await
            .map_err(|err| {
                SlurmDriverError::Message(format!(
                    "create sandbox state dir '{}': {err}",
                    sandbox_dir.display()
                ))
            })?;
        set_private_dir_permissions(&sandbox_dir).await?;

        let image = resolve_image(sandbox, &self.config);
        let env_path = sandbox_dir.join("sandbox.env");
        let script_path = sandbox_dir.join("run.sh");
        let status_path = sandbox_dir.join("status.env");
        let env = sandbox_environment(sandbox, &self.config, &image)?;
        write_env_file(&env_path, &env).await?;

        let resources = slurm_resources(sandbox)?;
        let job_name = slurm_job_name(&sandbox.name, &sandbox.id);
        let script = batch_script(&script_path, &env_path, &status_path, &image, &self.config);
        write_executable_file(&script_path, &script).await?;

        let mut args = vec![
            "--parsable".to_string(),
            "--job-name".to_string(),
            job_name.clone(),
            "--output".to_string(),
            sandbox_dir.join("slurm-%j.out").display().to_string(),
            "--error".to_string(),
            sandbox_dir.join("slurm-%j.err").display().to_string(),
            "--ntasks".to_string(),
            "1".to_string(),
            "--nodes".to_string(),
            "1".to_string(),
        ];
        push_optional_sbatch_arg(&mut args, "--partition", &self.config.partition);
        push_optional_sbatch_arg(&mut args, "--account", &self.config.account);
        push_optional_sbatch_arg(&mut args, "--qos", &self.config.qos);
        push_optional_sbatch_arg(&mut args, "--time", &self.config.time_limit);
        if let Some(cpus) = resources.cpus_per_task {
            args.push("--cpus-per-task".to_string());
            args.push(cpus.to_string());
        }
        if let Some(mem) = resources.mem {
            args.push("--mem".to_string());
            args.push(mem);
        }
        if sandbox.spec.as_ref().is_some_and(|spec| spec.gpu) {
            args.push("--gres".to_string());
            args.push(format!("{}:1", self.config.gpu_resource));
        }
        args.extend(self.config.extra_sbatch_args.clone());
        args.push(script_path.display().to_string());

        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %sandbox.name,
            job_name = %job_name,
            "Submitting Slurm sandbox job"
        );
        let output = self.runner.run("sbatch", &args).await?;
        if output.status != Some(0) {
            cleanup_dir_best_effort(&sandbox_dir).await;
            return Err(SlurmDriverError::Message(format!(
                "sbatch failed: {}",
                trim_command_error(&output)
            )));
        }
        let job_id = parse_sbatch_job_id(&output.stdout).ok_or_else(|| {
            SlurmDriverError::Message(format!(
                "could not parse sbatch job id from {:?}",
                output.stdout
            ))
        })?;
        let state = SlurmSandboxState {
            sandbox_id: sandbox.id.clone(),
            sandbox_name: sandbox.name.clone(),
            job_id: job_id.clone(),
            job_name,
            created_at_ms: openshell_core::time::now_ms(),
        };
        write_state_file(&sandbox_dir.join("state.json"), &state).await?;

        let _ = self.events.send(platform_event(
            &sandbox.id,
            "Normal",
            "Submitted",
            format!("Submitted Slurm job {job_id}"),
            BTreeMap::from([("job_id".to_string(), job_id.clone())]),
        ));
        let _ = self
            .events
            .send(sandbox_event(self.sandbox_from_state(&state).await?));
        Ok(())
    }

    pub async fn stop_sandbox(&self, sandbox_name: &str) -> Result<(), SlurmDriverError> {
        let Some(state) = self.find_state_by_name(sandbox_name).await? else {
            return Ok(());
        };
        self.cancel_job(&state).await
    }

    pub async fn delete_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<bool, SlurmDriverError> {
        if sandbox_id.is_empty() {
            return Err(SlurmDriverError::Precondition(
                "sandbox id is required".to_string(),
            ));
        }
        let sandbox_dir = self.sandbox_dir(sandbox_id)?;
        let Some(state) = self.read_state(sandbox_id).await? else {
            return Ok(false);
        };
        if !sandbox_name.is_empty() && state.sandbox_name != sandbox_name {
            warn!(
                sandbox_id,
                requested_name = %sandbox_name,
                state_name = %state.sandbox_name,
                "Slurm sandbox name did not match delete request; deleting by sandbox id"
            );
        }
        self.cancel_job(&state).await?;
        cleanup_dir_best_effort(&sandbox_dir).await;
        let _ = self.events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::Deleted(
                WatchSandboxesDeletedEvent {
                    sandbox_id: sandbox_id.to_string(),
                },
            )),
        });
        Ok(true)
    }

    async fn cancel_job(&self, state: &SlurmSandboxState) -> Result<(), SlurmDriverError> {
        let args = vec!["--full".to_string(), state.job_id.clone()];
        let output = self.runner.run("scancel", &args).await?;
        if output.status == Some(0) || command_error_is_not_found(&output) {
            let _ = self.events.send(platform_event(
                &state.sandbox_id,
                "Normal",
                "Cancelled",
                format!("Cancelled Slurm job {}", state.job_id),
                BTreeMap::from([("job_id".to_string(), state.job_id.clone())]),
            ));
            return Ok(());
        }
        Err(SlurmDriverError::Message(format!(
            "scancel failed for job {}: {}",
            state.job_id,
            trim_command_error(&output)
        )))
    }

    pub async fn get_sandbox(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<Option<DriverSandbox>, SlurmDriverError> {
        if !sandbox_id.is_empty() {
            let Some(state) = self.read_state(sandbox_id).await? else {
                return Ok(None);
            };
            return self.sandbox_from_state(&state).await.map(Some);
        }
        if sandbox_name.is_empty() {
            return Err(SlurmDriverError::Precondition(
                "sandbox_id or sandbox_name is required".to_string(),
            ));
        }
        let Some(state) = self.find_state_by_name(sandbox_name).await? else {
            return Ok(None);
        };
        self.sandbox_from_state(&state).await.map(Some)
    }

    pub async fn list_sandboxes(&self) -> Result<Vec<DriverSandbox>, SlurmDriverError> {
        let states = self.list_states().await?;
        let mut sandboxes = Vec::with_capacity(states.len());
        for state in states {
            sandboxes.push(self.sandbox_from_state(&state).await?);
        }
        sandboxes.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        Ok(sandboxes)
    }

    pub async fn watch_sandboxes(&self) -> Result<WatchStream, SlurmDriverError> {
        let mut rx = self.events.subscribe();
        let driver = self.clone();
        let initial = self.list_sandboxes().await?;
        let (tx, out_rx) = mpsc::channel(WATCH_BUFFER);
        tokio::spawn(async move {
            for sandbox in initial {
                if tx.send(Ok(sandbox_event(sandbox))).await.is_err() {
                    return;
                }
            }

            let mut interval = tokio::time::interval(WATCH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match driver.list_sandboxes().await {
                            Ok(sandboxes) => {
                                for sandbox in sandboxes {
                                    if tx.send(Ok(sandbox_event(sandbox))).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(err) => {
                                if tx.send(Err(err)).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    event = rx.recv() => match event {
                        Ok(event) => {
                            if tx.send(Ok(event)).await.is_err() {
                                return;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => return,
                    }
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(out_rx)))
    }

    async fn sandbox_from_state(
        &self,
        state: &SlurmSandboxState,
    ) -> Result<DriverSandbox, SlurmDriverError> {
        let snapshot = self.job_snapshot(state).await?;
        let condition = condition_from_snapshot(&snapshot);
        Ok(DriverSandbox {
            id: state.sandbox_id.clone(),
            name: state.sandbox_name.clone(),
            namespace: String::new(),
            spec: None,
            status: Some(DriverSandboxStatus {
                sandbox_name: state.job_name.clone(),
                instance_id: state.job_id.clone(),
                agent_fd: String::new(),
                sandbox_fd: String::new(),
                conditions: vec![condition],
                deleting: false,
            }),
        })
    }

    async fn job_snapshot(
        &self,
        state: &SlurmSandboxState,
    ) -> Result<SlurmJobSnapshot, SlurmDriverError> {
        if let Some(snapshot) = self.squeue_snapshot(&state.job_id).await? {
            return Ok(snapshot);
        }
        if let Some(marker) =
            read_status_marker(&self.sandbox_dir(&state.sandbox_id)?.join("status.env")).await?
        {
            return Ok(snapshot_from_marker(marker));
        }
        if let Some(snapshot) = self.sacct_snapshot(&state.job_id).await? {
            return Ok(snapshot);
        }
        Ok(SlurmJobSnapshot {
            state: "UNKNOWN".to_string(),
            reason: "SlurmJobUnknown".to_string(),
        })
    }

    async fn squeue_snapshot(
        &self,
        job_id: &str,
    ) -> Result<Option<SlurmJobSnapshot>, SlurmDriverError> {
        let args = vec![
            "--noheader".to_string(),
            "--jobs".to_string(),
            job_id.to_string(),
            "--format".to_string(),
            "%T|%R".to_string(),
        ];
        let output = self.runner.run("squeue", &args).await?;
        if output.status != Some(0) {
            return Err(SlurmDriverError::Message(format!(
                "squeue failed for job {job_id}: {}",
                trim_command_error(&output)
            )));
        }
        let Some(line) = output.stdout.lines().find(|line| !line.trim().is_empty()) else {
            return Ok(None);
        };
        let mut parts = line.splitn(2, '|');
        let state = parts.next().unwrap_or_default().trim().to_string();
        let reason = parts.next().unwrap_or_default().trim().to_string();
        Ok(Some(SlurmJobSnapshot { state, reason }))
    }

    async fn sacct_snapshot(
        &self,
        job_id: &str,
    ) -> Result<Option<SlurmJobSnapshot>, SlurmDriverError> {
        let args = vec![
            "-X".to_string(),
            "--noheader".to_string(),
            "--parsable2".to_string(),
            "--jobs".to_string(),
            job_id.to_string(),
            "--format".to_string(),
            "JobIDRaw,State,Reason".to_string(),
        ];
        let output = self.runner.run("sacct", &args).await?;
        if output.status != Some(0) {
            return Ok(None);
        }
        for line in output.stdout.lines() {
            let parts = line.split('|').collect::<Vec<_>>();
            if parts.len() >= 2 && parts[0].trim() == job_id {
                return Ok(Some(SlurmJobSnapshot {
                    state: parts[1].trim().to_string(),
                    reason: parts.get(2).copied().unwrap_or_default().trim().to_string(),
                }));
            }
        }
        Ok(None)
    }

    fn sandbox_dir(&self, sandbox_id: &str) -> Result<PathBuf, SlurmDriverError> {
        validate_path_id(sandbox_id)?;
        Ok(self.config.work_dir.join(sandbox_id))
    }

    async fn read_state(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<SlurmSandboxState>, SlurmDriverError> {
        let path = self.sandbox_dir(sandbox_id)?.join("state.json");
        read_state_file(&path).await
    }

    async fn find_state_by_name(
        &self,
        sandbox_name: &str,
    ) -> Result<Option<SlurmSandboxState>, SlurmDriverError> {
        Ok(self
            .list_states()
            .await?
            .into_iter()
            .find(|state| state.sandbox_name == sandbox_name))
    }

    async fn list_states(&self) -> Result<Vec<SlurmSandboxState>, SlurmDriverError> {
        let mut entries = match tokio::fs::read_dir(&self.config.work_dir).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => {
                return Err(SlurmDriverError::Message(format!(
                    "read slurm work dir '{}': {err}",
                    self.config.work_dir.display()
                )));
            }
        };
        let mut states = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|err| SlurmDriverError::Message(format!("read slurm work dir: {err}")))?
        {
            let file_type = entry.file_type().await.map_err(|err| {
                SlurmDriverError::Message(format!("read slurm entry type: {err}"))
            })?;
            if !file_type.is_dir() {
                continue;
            }
            let path = entry.path().join("state.json");
            if let Some(state) = read_state_file(&path).await? {
                states.push(state);
            }
        }
        states.sort_by(|left, right| {
            left.sandbox_name
                .cmp(&right.sandbox_name)
                .then(left.sandbox_id.cmp(&right.sandbox_id))
        });
        Ok(states)
    }
}

fn validate_sandbox_shape(
    sandbox: &DriverSandbox,
    config: &SlurmComputeConfig,
) -> Result<(), SlurmDriverError> {
    if sandbox.id.trim().is_empty() {
        return Err(SlurmDriverError::Precondition(
            "sandbox id is required".to_string(),
        ));
    }
    validate_path_id(&sandbox.id)?;
    if sandbox.name.trim().is_empty() {
        return Err(SlurmDriverError::Precondition(
            "sandbox name is required".to_string(),
        ));
    }
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| SlurmDriverError::Precondition("sandbox.spec is required".to_string()))?;
    let template = spec.template.as_ref().ok_or_else(|| {
        SlurmDriverError::Precondition("sandbox.spec.template is required".to_string())
    })?;
    if template.platform_config.is_some() {
        return Err(SlurmDriverError::Precondition(
            "slurm compute driver does not support template.platform_config".to_string(),
        ));
    }
    if spec.gpu && !spec.gpu_device.trim().is_empty() {
        return Err(SlurmDriverError::Precondition(
            "slurm compute driver does not support --gpu-device in the Apptainer MVP".to_string(),
        ));
    }
    if resolve_image(sandbox, config).trim().is_empty() {
        return Err(SlurmDriverError::Precondition(
            "no sandbox image configured: set --sandbox-image on the server or provide an image in the sandbox template".to_string(),
        ));
    }
    for key in spec.environment.keys().chain(template.environment.keys()) {
        validate_env_name(key)?;
    }
    slurm_resources(sandbox)?;
    Ok(())
}

fn resolve_image(sandbox: &DriverSandbox, config: &SlurmComputeConfig) -> String {
    let image = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map(|template| template.image.as_str())
        .filter(|image| !image.trim().is_empty())
        .unwrap_or(&config.default_image);

    let image = image.trim();
    if image.is_empty() {
        return String::new();
    }
    if image.starts_with("docker://")
        || image.starts_with("oras://")
        || image.starts_with("library://")
        || Path::new(image)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sif"))
    {
        return image.to_string();
    }
    format!("docker://{image}")
}

fn sandbox_environment(
    sandbox: &DriverSandbox,
    config: &SlurmComputeConfig,
    image: &str,
) -> Result<BTreeMap<String, String>, SlurmDriverError> {
    let spec = sandbox.spec.as_ref();
    let template = spec.and_then(|spec| spec.template.as_ref());
    let mut env = BTreeMap::new();

    if let Some(spec) = spec {
        if !spec.log_level.is_empty() {
            env.insert(
                openshell_core::sandbox_env::LOG_LEVEL.to_string(),
                spec.log_level.clone(),
            );
        }
        for (key, value) in &spec.environment {
            validate_env_name(key)?;
            validate_env_value(key, value)?;
            env.insert(key.clone(), value.clone());
        }
    }
    if let Some(template) = template {
        for (key, value) in &template.environment {
            validate_env_name(key)?;
            validate_env_value(key, value)?;
            env.insert(key.clone(), value.clone());
        }
    }

    env.insert(
        openshell_core::sandbox_env::LOG_LEVEL.to_string(),
        openshell_core::driver_utils::sandbox_log_level(sandbox, &config.log_level),
    );
    env.insert(
        openshell_core::sandbox_env::SANDBOX.to_string(),
        sandbox.name.clone(),
    );
    env.insert(
        openshell_core::sandbox_env::SANDBOX_ID.to_string(),
        sandbox.id.clone(),
    );
    env.insert(
        openshell_core::sandbox_env::ENDPOINT.to_string(),
        config.grpc_endpoint.clone(),
    );
    env.insert(
        openshell_core::sandbox_env::SSH_SOCKET_PATH.to_string(),
        config.sandbox_ssh_socket_path.clone(),
    );
    env.insert(
        openshell_core::sandbox_env::SSH_HANDSHAKE_SECRET.to_string(),
        config.ssh_handshake_secret.clone(),
    );
    env.insert(
        openshell_core::sandbox_env::SSH_HANDSHAKE_SKEW_SECS.to_string(),
        config.ssh_handshake_skew_secs.to_string(),
    );
    env.insert(
        openshell_core::sandbox_env::SANDBOX_COMMAND.to_string(),
        SANDBOX_COMMAND.to_string(),
    );
    env.insert("OPENSHELL_CONTAINER_IMAGE".to_string(), image.to_string());
    env.insert("PATH".to_string(), SUPERVISOR_PATH.to_string());
    if config.tls_enabled() {
        env.insert(
            openshell_core::sandbox_env::TLS_CA.to_string(),
            TLS_CA_MOUNT_PATH.to_string(),
        );
        env.insert(
            openshell_core::sandbox_env::TLS_CERT.to_string(),
            TLS_CERT_MOUNT_PATH.to_string(),
        );
        env.insert(
            openshell_core::sandbox_env::TLS_KEY.to_string(),
            TLS_KEY_MOUNT_PATH.to_string(),
        );
    }

    for (key, value) in &env {
        validate_env_name(key)?;
        validate_env_value(key, value)?;
    }
    Ok(env)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct SlurmResources {
    cpus_per_task: Option<u32>,
    mem: Option<String>,
}

fn slurm_resources(sandbox: &DriverSandbox) -> Result<SlurmResources, SlurmDriverError> {
    let resources = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .and_then(|template| template.resources.as_ref());
    let Some(resources) = resources else {
        return Ok(SlurmResources::default());
    };
    Ok(SlurmResources {
        cpus_per_task: slurm_cpu(resources)?,
        mem: slurm_memory(resources)?,
    })
}

fn slurm_cpu(resources: &DriverResourceRequirements) -> Result<Option<u32>, SlurmDriverError> {
    let raw = first_non_empty(&[&resources.cpu_limit, &resources.cpu_request]);
    let Some(raw) = raw else {
        return Ok(None);
    };
    parse_cpu_ceil(raw).map(Some)
}

fn slurm_memory(
    resources: &DriverResourceRequirements,
) -> Result<Option<String>, SlurmDriverError> {
    let raw = first_non_empty(&[&resources.memory_limit, &resources.memory_request]);
    let Some(raw) = raw else {
        return Ok(None);
    };
    let mib = parse_memory_mib_ceil(raw)?;
    Ok(Some(format!("{mib}M")))
}

fn first_non_empty<'a>(values: &[&'a str]) -> Option<&'a str> {
    values
        .iter()
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn parse_cpu_ceil(value: &str) -> Result<u32, SlurmDriverError> {
    let value = value.trim();
    let cores = if let Some(millicores) = value.strip_suffix('m') {
        let millicores = millicores.parse::<f64>().map_err(|_| {
            SlurmDriverError::Precondition(format!(
                "invalid slurm cpu quantity '{value}'; expected cores or millicores"
            ))
        })?;
        millicores / 1000.0
    } else {
        value.parse::<f64>().map_err(|_| {
            SlurmDriverError::Precondition(format!(
                "invalid slurm cpu quantity '{value}'; expected cores or millicores"
            ))
        })?
    };
    if !cores.is_finite() || cores <= 0.0 {
        return Err(SlurmDriverError::Precondition(
            "slurm cpu quantity must be greater than zero".to_string(),
        ));
    }
    Ok(cores.ceil().max(1.0) as u32)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn parse_memory_mib_ceil(value: &str) -> Result<u64, SlurmDriverError> {
    let value = value.trim();
    let number_end = value
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(value.len());
    let number = value[..number_end].parse::<f64>().map_err(|_| {
        SlurmDriverError::Precondition(format!(
            "invalid slurm memory quantity '{value}'; expected bytes or a Kubernetes-style quantity"
        ))
    })?;
    if !number.is_finite() || number <= 0.0 {
        return Err(SlurmDriverError::Precondition(
            "slurm memory quantity must be greater than zero".to_string(),
        ));
    }
    let suffix = &value[number_end..];
    let bytes = match suffix {
        "" => number,
        "Ki" => number * 1024.0,
        "Mi" => number * 1024_f64.powi(2),
        "Gi" => number * 1024_f64.powi(3),
        "Ti" => number * 1024_f64.powi(4),
        "K" | "k" => number * 1000.0,
        "M" => number * 1000_f64.powi(2),
        "G" => number * 1000_f64.powi(3),
        "T" => number * 1000_f64.powi(4),
        other => {
            return Err(SlurmDriverError::Precondition(format!(
                "invalid slurm memory quantity suffix '{other}'"
            )));
        }
    };
    Ok((bytes / 1024_f64.powi(2)).ceil().max(1.0) as u64)
}

fn batch_script(
    script_path: &Path,
    env_path: &Path,
    status_path: &Path,
    image: &str,
    config: &SlurmComputeConfig,
) -> String {
    let mut srun_args = vec!["--ntasks=1".to_string()];
    srun_args.extend(config.extra_srun_args.clone());

    let mut apptainer_args = vec![
        "exec".to_string(),
        "--cleanenv".to_string(),
        "--env-file".to_string(),
        env_path.display().to_string(),
        "--bind".to_string(),
        format!(
            "{}:{SUPERVISOR_MOUNT_PATH}:ro",
            config.supervisor_bin.display()
        ),
    ];
    if config.tls_enabled() {
        apptainer_args.push("--bind".to_string());
        apptainer_args.push(format!(
            "{}:{TLS_CA_MOUNT_PATH}:ro",
            config
                .guest_tls_ca
                .as_ref()
                .expect("checked by tls_enabled")
                .display()
        ));
        apptainer_args.push("--bind".to_string());
        apptainer_args.push(format!(
            "{}:{TLS_CERT_MOUNT_PATH}:ro",
            config
                .guest_tls_cert
                .as_ref()
                .expect("checked by tls_enabled")
                .display()
        ));
        apptainer_args.push("--bind".to_string());
        apptainer_args.push(format!(
            "{}:{TLS_KEY_MOUNT_PATH}:ro",
            config
                .guest_tls_key
                .as_ref()
                .expect("checked by tls_enabled")
                .display()
        ));
    }
    apptainer_args.extend(config.extra_apptainer_args.clone());
    apptainer_args.push(image.to_string());
    apptainer_args.push(SUPERVISOR_MOUNT_PATH.to_string());

    let srun_args = shell_array(&srun_args);
    let apptainer_args = shell_array(&apptainer_args);
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

STATUS_FILE={status_file}
write_status() {{
  printf '%s\n' "$*" > "${{STATUS_FILE}}"
}}
finish() {{
  code=$?
  write_status "state=exited exit_code=${{code}} ended_at_ms=$(date +%s%3N)"
  exit "${{code}}"
}}
trap finish EXIT

write_status "state=starting started_at_ms=$(date +%s%3N)"
cd {script_dir}
write_status "state=running started_at_ms=$(date +%s%3N)"
srun {srun_args} {apptainer_bin} {apptainer_args}
"#,
        status_file = sh_single_quote(&status_path.display().to_string()),
        script_dir = sh_single_quote(
            &script_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .display()
                .to_string()
        ),
        srun_args = srun_args,
        apptainer_bin = sh_single_quote(&config.apptainer_bin),
        apptainer_args = apptainer_args,
    )
}

fn shell_array(values: &[String]) -> String {
    values
        .iter()
        .map(|value| sh_single_quote(value))
        .collect::<Vec<_>>()
        .join(" ")
}

fn sh_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn push_optional_sbatch_arg(args: &mut Vec<String>, name: &str, value: &Option<String>) {
    if let Some(value) = value.as_ref().filter(|value| !value.trim().is_empty()) {
        args.push(name.to_string());
        args.push(value.clone());
    }
}

fn slurm_job_name(sandbox_name: &str, sandbox_id: &str) -> String {
    let mut safe = sandbox_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    safe.truncate(48);
    let short_id = sandbox_id.chars().take(12).collect::<String>();
    format!("{SLURM_JOB_PREFIX}-{safe}-{short_id}")
}

fn parse_sbatch_job_id(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| line.trim().split(';').next())
        .map(str::trim)
        .filter(|job_id| !job_id.is_empty())
        .map(ToOwned::to_owned)
}

fn condition_from_snapshot(snapshot: &SlurmJobSnapshot) -> DriverCondition {
    let normalized = snapshot.state.to_ascii_uppercase();
    let (status, reason, message) = match normalized.as_str() {
        "BOOT_FAIL" | "CANCELLED" | "DEADLINE" | "FAILED" | "NODE_FAIL" | "OUT_OF_MEMORY"
        | "PREEMPTED" | "REVOKED" | "SPECIAL_EXIT" | "TIMEOUT" => (
            "False",
            format!("Slurm{normalized}"),
            format!("Slurm job ended with state {}", snapshot.state),
        ),
        "COMPLETED" => (
            "False",
            "SlurmCompleted".to_string(),
            "Slurm job completed before the sandbox supervisor connected".to_string(),
        ),
        "RUNNING" => (
            "False",
            "DependenciesNotReady".to_string(),
            "Slurm job is running; waiting for supervisor session".to_string(),
        ),
        "PENDING" | "CONFIGURING" | "COMPLETING" | "RESIZING" | "SIGNALING" | "SUSPENDED" => (
            "False",
            "DependenciesNotReady".to_string(),
            if snapshot.reason.is_empty() {
                format!("Slurm job is {}", snapshot.state)
            } else {
                format!("Slurm job is {}: {}", snapshot.state, snapshot.reason)
            },
        ),
        _ => (
            "Unknown",
            "SlurmJobUnknown".to_string(),
            format!("Slurm job state is {}", snapshot.state),
        ),
    };
    DriverCondition {
        r#type: "Ready".to_string(),
        status: status.to_string(),
        reason,
        message,
        last_transition_time: String::new(),
    }
}

fn snapshot_from_marker(marker: LocalStatusMarker) -> SlurmJobSnapshot {
    match marker.state {
        LocalMarkerState::Starting => SlurmJobSnapshot {
            state: "CONFIGURING".to_string(),
            reason: "BatchScriptStarting".to_string(),
        },
        LocalMarkerState::Running => SlurmJobSnapshot {
            state: "RUNNING".to_string(),
            reason: String::new(),
        },
        LocalMarkerState::Exited => {
            if marker.exit_code == Some(0) {
                SlurmJobSnapshot {
                    state: "COMPLETED".to_string(),
                    reason: String::new(),
                }
            } else {
                SlurmJobSnapshot {
                    state: "FAILED".to_string(),
                    reason: marker
                        .exit_code
                        .map_or_else(String::new, |code| format!("ExitCode={code}")),
                }
            }
        }
    }
}

fn sandbox_event(sandbox: DriverSandbox) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Sandbox(
            WatchSandboxesSandboxEvent {
                sandbox: Some(sandbox),
            },
        )),
    }
}

fn platform_event(
    sandbox_id: &str,
    event_type: &str,
    reason: &str,
    message: String,
    metadata: BTreeMap<String, String>,
) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::PlatformEvent(
            WatchSandboxesPlatformEvent {
                sandbox_id: sandbox_id.to_string(),
                event: Some(DriverPlatformEvent {
                    timestamp_ms: openshell_core::time::now_ms(),
                    source: "slurm".to_string(),
                    r#type: event_type.to_string(),
                    reason: reason.to_string(),
                    message,
                    metadata: metadata.into_iter().collect(),
                }),
            },
        )),
    }
}

async fn write_env_file(
    path: &Path,
    env: &BTreeMap<String, String>,
) -> Result<(), SlurmDriverError> {
    let content = env_file_content(env);
    tokio::fs::write(path, content)
        .await
        .map_err(|err| SlurmDriverError::Message(format!("write '{}': {err}", path.display())))?;
    set_private_file_permissions(path).await
}

fn env_file_content(env: &BTreeMap<String, String>) -> String {
    let mut content = String::new();
    for (key, value) in env {
        content.push_str(key);
        content.push('=');
        content.push_str(&sh_single_quote(value));
        content.push('\n');
    }
    content
}

async fn write_executable_file(path: &Path, content: &str) -> Result<(), SlurmDriverError> {
    tokio::fs::write(path, content)
        .await
        .map_err(|err| SlurmDriverError::Message(format!("write '{}': {err}", path.display())))?;
    set_executable_file_permissions(path).await
}

async fn write_state_file(path: &Path, state: &SlurmSandboxState) -> Result<(), SlurmDriverError> {
    let content = serde_json::to_vec_pretty(state).map_err(|err| {
        SlurmDriverError::Message(format!("serialize Slurm sandbox state: {err}"))
    })?;
    tokio::fs::write(path, content)
        .await
        .map_err(|err| SlurmDriverError::Message(format!("write '{}': {err}", path.display())))?;
    set_private_file_permissions(path).await
}

async fn read_state_file(path: &Path) -> Result<Option<SlurmSandboxState>, SlurmDriverError> {
    let content = match tokio::fs::read(path).await {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(SlurmDriverError::Message(format!(
                "read '{}': {err}",
                path.display()
            )));
        }
    };
    serde_json::from_slice(&content)
        .map(Some)
        .map_err(|err| SlurmDriverError::Message(format!("parse '{}': {err}", path.display())))
}

async fn read_status_marker(path: &Path) -> Result<Option<LocalStatusMarker>, SlurmDriverError> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(SlurmDriverError::Message(format!(
                "read '{}': {err}",
                path.display()
            )));
        }
    };
    let pairs = content
        .split_whitespace()
        .filter_map(|part| part.split_once('='))
        .collect::<BTreeMap<_, _>>();
    let state = match pairs.get("state").copied() {
        Some("starting") => LocalMarkerState::Starting,
        Some("running") => LocalMarkerState::Running,
        Some("exited") => LocalMarkerState::Exited,
        _ => return Ok(None),
    };
    let exit_code = pairs
        .get("exit_code")
        .and_then(|value| value.parse::<i32>().ok());
    Ok(Some(LocalStatusMarker { state, exit_code }))
}

async fn cleanup_dir_best_effort(path: &Path) {
    let _ = tokio::fs::remove_dir_all(path).await;
}

#[cfg(unix)]
async fn set_private_dir_permissions(path: &Path) -> Result<(), SlurmDriverError> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = std::fs::Permissions::from_mode(0o700);
    tokio::fs::set_permissions(path, permissions)
        .await
        .map_err(|err| SlurmDriverError::Message(format!("chmod '{}': {err}", path.display())))
}

#[cfg(not(unix))]
async fn set_private_dir_permissions(path: &Path) -> Result<(), SlurmDriverError> {
    let _ = path;
    Ok(())
}

#[cfg(unix)]
async fn set_private_file_permissions(path: &Path) -> Result<(), SlurmDriverError> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = std::fs::Permissions::from_mode(0o600);
    tokio::fs::set_permissions(path, permissions)
        .await
        .map_err(|err| SlurmDriverError::Message(format!("chmod '{}': {err}", path.display())))
}

#[cfg(not(unix))]
async fn set_private_file_permissions(path: &Path) -> Result<(), SlurmDriverError> {
    let _ = path;
    Ok(())
}

#[cfg(unix)]
async fn set_executable_file_permissions(path: &Path) -> Result<(), SlurmDriverError> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = std::fs::Permissions::from_mode(0o700);
    tokio::fs::set_permissions(path, permissions)
        .await
        .map_err(|err| SlurmDriverError::Message(format!("chmod '{}': {err}", path.display())))
}

#[cfg(not(unix))]
async fn set_executable_file_permissions(path: &Path) -> Result<(), SlurmDriverError> {
    let _ = path;
    Ok(())
}

fn ensure_readable_file(path: &Path, label: &str) -> Result<(), SlurmDriverError> {
    let metadata = path.metadata().map_err(|err| {
        SlurmDriverError::Precondition(format!(
            "{label} '{}' is not readable: {err}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(SlurmDriverError::Precondition(format!(
            "{label} '{}' is not a file",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_executable_file(path: &Path, label: &str) -> Result<(), SlurmDriverError> {
    ensure_readable_file(path, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = path.metadata().map_err(|err| {
            SlurmDriverError::Precondition(format!(
                "{label} '{}' is not readable: {err}",
                path.display()
            ))
        })?;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(SlurmDriverError::Precondition(format!(
                "{label} '{}' is not executable",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_path_id(value: &str) -> Result<(), SlurmDriverError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(SlurmDriverError::Precondition(
            "sandbox id must match [A-Za-z0-9._-]{1,128}".to_string(),
        ));
    }
    Ok(())
}

fn validate_env_name(value: &str) -> Result<(), SlurmDriverError> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(SlurmDriverError::Precondition(
            "environment variable name cannot be empty".to_string(),
        ));
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return Err(SlurmDriverError::Precondition(format!(
            "invalid environment variable name '{value}'"
        )));
    }
    Ok(())
}

fn validate_env_value(key: &str, value: &str) -> Result<(), SlurmDriverError> {
    if value.contains('\n') || value.contains('\0') {
        return Err(SlurmDriverError::Precondition(format!(
            "environment variable '{key}' contains an unsupported newline or NUL byte"
        )));
    }
    Ok(())
}

fn trim_command_error(output: &SlurmCommandOutput) -> String {
    let stderr = output.stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }
    let stdout = output.stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_string();
    }
    format!("exit status {:?}", output.status)
}

fn command_error_is_not_found(output: &SlurmCommandOutput) -> bool {
    let text = format!("{}{}", output.stdout, output.stderr).to_ascii_lowercase();
    text.contains("invalid job id")
        || text.contains("unknown job id")
        || text.contains("not found")
        || text.contains("already completed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::compute::v1::{
        DriverResourceRequirements, DriverSandboxSpec, DriverSandboxTemplate,
    };

    fn sandbox_with_resources(resources: DriverResourceRequirements) -> DriverSandbox {
        DriverSandbox {
            id: "sb-123".to_string(),
            name: "demo".to_string(),
            namespace: String::new(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate {
                    image: "ubuntu:24.04".to_string(),
                    resources: Some(resources),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn image_references_default_to_docker_transport() {
        let config = SlurmComputeConfig {
            default_image: "ubuntu:24.04".to_string(),
            ..SlurmComputeConfig::default()
        };
        let sandbox = sandbox_with_resources(DriverResourceRequirements::default());

        assert_eq!(resolve_image(&sandbox, &config), "docker://ubuntu:24.04");
    }

    #[test]
    fn image_references_preserve_apptainer_transports() {
        let config = SlurmComputeConfig::default();
        let mut sandbox = sandbox_with_resources(DriverResourceRequirements::default());
        sandbox
            .spec
            .as_mut()
            .unwrap()
            .template
            .as_mut()
            .unwrap()
            .image = "oras://registry.example/sandbox:latest".to_string();

        assert_eq!(
            resolve_image(&sandbox, &config),
            "oras://registry.example/sandbox:latest"
        );
    }

    #[test]
    fn resource_quantities_round_up_for_slurm() {
        let sandbox = sandbox_with_resources(DriverResourceRequirements {
            cpu_limit: "1500m".to_string(),
            memory_limit: "1536Mi".to_string(),
            ..Default::default()
        });

        let resources = slurm_resources(&sandbox).unwrap();
        assert_eq!(resources.cpus_per_task, Some(2));
        assert_eq!(resources.mem.as_deref(), Some("1536M"));
    }

    #[test]
    fn memory_quantities_accept_decimal_units() {
        assert_eq!(parse_memory_mib_ceil("1G").unwrap(), 954);
        assert_eq!(parse_memory_mib_ceil("2Gi").unwrap(), 2048);
    }

    #[test]
    fn batch_script_quotes_arguments() {
        let dir = PathBuf::from("/tmp/with space");
        let script = batch_script(
            &dir.join("run.sh"),
            &dir.join("sandbox.env"),
            &dir.join("status.env"),
            "docker://example/image:latest",
            &SlurmComputeConfig {
                apptainer_bin: "apptainer".to_string(),
                supervisor_bin: dir.join("openshell-sandbox"),
                extra_apptainer_args: vec!["--containall".to_string()],
                ..SlurmComputeConfig::default()
            },
        );

        assert!(script.contains("'--containall'"));
        assert!(script.contains(
            "'/tmp/with space/openshell-sandbox:/opt/openshell/bin/openshell-sandbox:ro'"
        ));
        assert!(script.contains("srun '--ntasks=1'"));
        assert!(!script.contains("exec srun"));
    }

    #[test]
    fn env_file_quotes_shell_values() {
        let env = BTreeMap::from([
            ("EMPTY".to_string(), String::new()),
            ("QUOTE".to_string(), "it'll work".to_string()),
            ("SPACE".to_string(), "sleep infinity".to_string()),
        ]);

        assert_eq!(
            env_file_content(&env),
            "EMPTY=''\nQUOTE='it'\"'\"'ll work'\nSPACE='sleep infinity'\n"
        );
    }

    #[test]
    fn slurm_conditions_keep_active_jobs_provisioning() {
        let condition = condition_from_snapshot(&SlurmJobSnapshot {
            state: "RUNNING".to_string(),
            reason: String::new(),
        });

        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "DependenciesNotReady");
    }

    #[test]
    fn slurm_conditions_mark_failures_terminal() {
        let condition = condition_from_snapshot(&SlurmJobSnapshot {
            state: "FAILED".to_string(),
            reason: "NonZeroExitCode".to_string(),
        });

        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "SlurmFAILED");
    }

    #[test]
    fn sbatch_parsable_job_id_is_extracted() {
        assert_eq!(
            parse_sbatch_job_id("12345;debug\n").as_deref(),
            Some("12345")
        );
    }
}
