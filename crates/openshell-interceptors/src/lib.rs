// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway operation interceptor config, planning, transport, and review runtime.

#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper_util::rt::TokioIo;
use metrics::{counter, histogram};
use openshell_core::proto::interceptor::v1::{
    InterceptorBinding, InterceptorDecision, InterceptorDescribeRequest, InterceptorManifest,
    InterceptorPrincipal, InterceptorRequestContext, InterceptorReview, JsonPatch,
    gateway_interceptor_client::GatewayInterceptorClient,
};
use prost_types::{ListValue, Struct, Value as ProtoValue, value::Kind};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use tokio::sync::Mutex;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};
use tower::service_fn;
use tracing::{debug, info, warn};
use url::Url;

pub const API_VERSION: &str = "gateway.interceptor.openshell.dev/v1";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);
pub const DEFAULT_MAX_PATCH_COUNT: usize = 32;
pub const DEFAULT_MAX_DECODING_MESSAGE_SIZE: usize = 1024 * 1024;

pub const PHASE_PRE_REQUEST: &str = "pre_request";
pub const PHASE_MODIFY_OBJECT: &str = "modify_object";
pub const PHASE_VALIDATE_OBJECT: &str = "validate_object";
pub const PHASE_VALIDATE_DRIVER: &str = "validate_driver";
pub const PHASE_POST_COMMIT: &str = "post_commit";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    FailClosed,
    FailOpen,
    Ignore,
}

impl FailurePolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::FailOpen => "fail_open",
            Self::Ignore => "ignore",
        }
    }
}

impl fmt::Display for FailurePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for FailurePolicy {
    type Err = InterceptorConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" => Err(InterceptorConfigError::InvalidFailurePolicy {
                value: value.to_string(),
            }),
            "fail_closed" => Ok(Self::FailClosed),
            "fail_open" => Ok(Self::FailOpen),
            "ignore" => Ok(Self::Ignore),
            other => Err(InterceptorConfigError::InvalidFailurePolicy {
                value: other.to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterceptorConfig {
    pub name: String,
    pub endpoint: String,
    #[serde(default)]
    pub order: i32,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub failure_policy: Option<FailurePolicy>,
    #[serde(default = "empty_toml_table")]
    pub config: toml::Value,
    #[serde(default)]
    pub overrides: Vec<BindingOverrideConfig>,
}

impl Default for InterceptorConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            endpoint: String::new(),
            order: 0,
            timeout: None,
            failure_policy: None,
            config: empty_toml_table(),
            overrides: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingOverrideConfig {
    pub binding: String,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub order: Option<i32>,
    #[serde(default)]
    pub failure_policy: Option<FailurePolicy>,
    #[serde(default, rename = "match")]
    pub match_: BindingMatchConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingMatchConfig {
    #[serde(default)]
    pub phases: Option<Vec<String>>,
    #[serde(default)]
    pub resources: Option<Vec<String>>,
    #[serde(default)]
    pub operations: Option<Vec<String>>,
    #[serde(default)]
    pub principal_kinds: Option<Vec<String>>,
    #[serde(default)]
    pub principal_groups: Option<Vec<String>>,
    #[serde(default)]
    pub labels: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub compute_drivers: Option<Vec<String>>,
}

fn empty_toml_table() -> toml::Value {
    toml::Value::Table(toml::Table::new())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptorEndpoint {
    Grpc { authority: String, tls: bool },
    Unix { path: PathBuf },
}

impl InterceptorEndpoint {
    pub fn parse(raw: &str) -> Result<Self, InterceptorConfigError> {
        let url = Url::parse(raw).map_err(|source| InterceptorConfigError::InvalidEndpoint {
            endpoint: raw.to_string(),
            message: source.to_string(),
        })?;
        match url.scheme() {
            "grpc" | "grpcs" => {
                let host =
                    url.host_str()
                        .ok_or_else(|| InterceptorConfigError::InvalidEndpoint {
                            endpoint: raw.to_string(),
                            message: "TCP endpoint requires a host".to_string(),
                        })?;
                let port = url
                    .port()
                    .ok_or_else(|| InterceptorConfigError::InvalidEndpoint {
                        endpoint: raw.to_string(),
                        message: "TCP endpoint requires an explicit port".to_string(),
                    })?;
                if !url.path().trim_matches('/').is_empty() {
                    return Err(InterceptorConfigError::InvalidEndpoint {
                        endpoint: raw.to_string(),
                        message: "TCP endpoint must not include a path".to_string(),
                    });
                }
                if url.scheme() == "grpc" && !is_loopback_host(host) {
                    warn!(
                        endpoint = %raw,
                        "plaintext grpc interceptor endpoint is not loopback; use grpcs:// for remote services"
                    );
                }
                Ok(Self::Grpc {
                    authority: format!("{host}:{port}"),
                    tls: url.scheme() == "grpcs",
                })
            }
            "unix" => {
                let path = PathBuf::from(url.path());
                if path.as_os_str().is_empty() || !path.is_absolute() {
                    return Err(InterceptorConfigError::InvalidEndpoint {
                        endpoint: raw.to_string(),
                        message: "unix endpoint requires an absolute socket path".to_string(),
                    });
                }
                Ok(Self::Unix { path })
            }
            other => Err(InterceptorConfigError::InvalidEndpoint {
                endpoint: raw.to_string(),
                message: format!("unsupported scheme '{other}'"),
            }),
        }
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[derive(Debug, thiserror::Error)]
pub enum InterceptorConfigError {
    #[error("interceptor name is required")]
    MissingName,
    #[error("interceptor '{name}' endpoint is required")]
    MissingEndpoint { name: String },
    #[error("duplicate interceptor name '{name}'")]
    DuplicateName { name: String },
    #[error("invalid interceptor endpoint '{endpoint}': {message}")]
    InvalidEndpoint { endpoint: String, message: String },
    #[error("invalid interceptor timeout '{value}'")]
    InvalidTimeout { value: String },
    #[error("invalid interceptor failure policy '{value}'")]
    InvalidFailurePolicy { value: String },
    #[error("interceptor '{interceptor}' describe failed: {message}")]
    DescribeFailed {
        interceptor: String,
        message: String,
    },
    #[error("interceptor '{interceptor}' manifest has unsupported api_version '{api_version}'")]
    UnsupportedApiVersion {
        interceptor: String,
        api_version: String,
    },
    #[error("interceptor '{interceptor}' manifest contains duplicate binding '{binding}'")]
    DuplicateBinding {
        interceptor: String,
        binding: String,
    },
    #[error("interceptor '{interceptor}' binding id is required")]
    MissingBindingId { interceptor: String },
    #[error("interceptor '{interceptor}' binding '{binding}' must declare at least one phase")]
    MissingPhases {
        interceptor: String,
        binding: String,
    },
    #[error("interceptor '{interceptor}' binding '{binding}' uses unknown phase '{phase}'")]
    UnknownPhase {
        interceptor: String,
        binding: String,
        phase: String,
    },
    #[error(
        "interceptor '{interceptor}' binding '{binding}' declares modifies=true outside modification phases"
    )]
    InvalidModifies {
        interceptor: String,
        binding: String,
    },
    #[error(
        "interceptor '{interceptor}' binding '{binding}' uses failure_policy=ignore outside post_commit"
    )]
    InvalidIgnorePolicy {
        interceptor: String,
        binding: String,
    },
    #[error("interceptor '{interceptor}' override references unknown binding '{binding}'")]
    UnknownOverrideBinding {
        interceptor: String,
        binding: String,
    },
    #[error(
        "interceptor '{interceptor}' override for binding '{binding}' expands {field} beyond the service manifest"
    )]
    OverrideExpands {
        interceptor: String,
        binding: String,
        field: &'static str,
    },
    #[error("interceptor '{interceptor}' config must be a TOML table")]
    ConfigMustBeTable { interceptor: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error("interceptor denied operation: {reason}")]
    Denied {
        interceptor: String,
        binding: String,
        phase: String,
        resource: String,
        operation: String,
        status_code: tonic::Code,
        reason: String,
    },
    #[error("{0}")]
    Failed(Status),
}

impl ReviewError {
    #[must_use]
    pub fn into_status(self) -> Status {
        match self {
            Self::Denied {
                status_code,
                reason,
                ..
            } => Status::new(status_code, reason),
            Self::Failed(status) => status,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReviewInput {
    pub phase: String,
    pub resource: String,
    pub operation: String,
    pub principal: InterceptorPrincipal,
    pub context: InterceptorRequestContext,
    pub object: JsonValue,
    pub old_object: Option<JsonValue>,
    pub request: Option<JsonValue>,
    pub modification_allowed: bool,
}

#[derive(Debug, Clone)]
pub struct ReviewOutcome {
    pub object: JsonValue,
    pub applied_patches: Vec<JsonPatch>,
    pub warnings: Vec<String>,
    pub audit_annotations: BTreeMap<String, String>,
}

struct InterceptorServiceRuntime {
    timeout: Duration,
    client: Mutex<GatewayInterceptorClient<Channel>>,
}

pub struct InterceptorRuntime {
    services: BTreeMap<String, Arc<InterceptorServiceRuntime>>,
    bindings: Vec<RuntimeBinding>,
    max_patch_count: usize,
}

impl fmt::Debug for InterceptorRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterceptorRuntime")
            .field("services", &self.services.keys().collect::<Vec<_>>())
            .field("bindings", &self.bindings)
            .field("max_patch_count", &self.max_patch_count)
            .finish()
    }
}

impl Default for InterceptorRuntime {
    fn default() -> Self {
        Self::empty()
    }
}

impl InterceptorRuntime {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            services: BTreeMap::new(),
            bindings: Vec::new(),
            max_patch_count: DEFAULT_MAX_PATCH_COUNT,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    pub async fn from_config(
        configs: &[InterceptorConfig],
    ) -> Result<Self, InterceptorConfigError> {
        if configs.is_empty() {
            return Ok(Self::empty());
        }
        let mut names = BTreeSet::new();
        for config in configs {
            let name = config.name.trim();
            if name.is_empty() {
                return Err(InterceptorConfigError::MissingName);
            }
            if !names.insert(name.to_string()) {
                return Err(InterceptorConfigError::DuplicateName {
                    name: name.to_string(),
                });
            }
            if config.endpoint.trim().is_empty() {
                return Err(InterceptorConfigError::MissingEndpoint {
                    name: name.to_string(),
                });
            }
        }

        let mut services = BTreeMap::new();
        let mut bindings = Vec::new();
        for config in configs {
            let service = build_service_runtime(config).await?;
            let mut client = service.client.lock().await;
            let manifest = describe(config, &mut client).await?;
            drop(client);
            validate_manifest(config, &manifest)?;
            bindings.extend(plan_bindings(config, &manifest)?);
            services.insert(config.name.clone(), Arc::new(service));
        }

        bindings.sort_by(|left, right| {
            left.service_order
                .cmp(&right.service_order)
                .then_with(|| left.binding_order.cmp(&right.binding_order))
                .then_with(|| left.interceptor_name.cmp(&right.interceptor_name))
                .then_with(|| left.binding_id.cmp(&right.binding_id))
        });

        Ok(Self {
            services,
            bindings,
            max_patch_count: DEFAULT_MAX_PATCH_COUNT,
        })
    }

    pub async fn review(&self, input: ReviewInput) -> Result<ReviewOutcome, ReviewError> {
        if self.bindings.is_empty() {
            return Ok(ReviewOutcome {
                object: input.object,
                applied_patches: Vec::new(),
                warnings: Vec::new(),
                audit_annotations: BTreeMap::new(),
            });
        }

        let matching = self
            .bindings
            .iter()
            .filter(|binding| binding.matches(&input))
            .collect::<Vec<_>>();
        let mut object = input.object.clone();
        let mut applied_patches = Vec::new();
        let mut warnings = Vec::new();
        let mut audit_annotations = BTreeMap::new();

        for binding in matching {
            let Some(service) = self.services.get(&binding.interceptor_name) else {
                return Err(ReviewError::Failed(Status::internal(format!(
                    "interceptor '{}' runtime is missing",
                    binding.interceptor_name
                ))));
            };

            let review = InterceptorReview {
                api_version: API_VERSION.to_string(),
                interceptor_name: binding.interceptor_name.clone(),
                binding_id: binding.binding_id.clone(),
                phase: input.phase.clone(),
                resource: input.resource.clone(),
                operation: input.operation.clone(),
                principal: Some(input.principal.clone()),
                context: Some(input.context.clone()),
                object: Some(json_to_struct(&object).map_err(|err| {
                    ReviewError::Failed(Status::internal(format!(
                        "build interceptor object payload failed: {err}"
                    )))
                })?),
                old_object: input
                    .old_object
                    .as_ref()
                    .map(json_to_struct)
                    .transpose()
                    .map_err(|err| {
                        ReviewError::Failed(Status::internal(format!(
                            "build interceptor old_object payload failed: {err}"
                        )))
                    })?,
                request: input
                    .request
                    .as_ref()
                    .map(json_to_struct)
                    .transpose()
                    .map_err(|err| {
                        ReviewError::Failed(Status::internal(format!(
                            "build interceptor request payload failed: {err}"
                        )))
                    })?,
            };

            let decision = match call_review(service, review, binding).await {
                Ok(decision) => decision,
                Err(err) => {
                    handle_interceptor_failure(binding, err)?;
                    continue;
                }
            };

            log_decision(binding, &input, &decision);
            metrics_decision(binding, &input, &decision);

            if !decision.allowed {
                let reason = if decision.reason.trim().is_empty() {
                    "interceptor denied operation".to_string()
                } else {
                    decision.reason.clone()
                };
                return Err(ReviewError::Denied {
                    interceptor: binding.interceptor_name.clone(),
                    binding: binding.binding_id.clone(),
                    phase: input.phase.clone(),
                    resource: input.resource.clone(),
                    operation: input.operation.clone(),
                    status_code: status_code(&decision.status_code),
                    reason,
                });
            }

            warnings.extend(decision.warnings);
            audit_annotations.extend(decision.audit_annotations);

            if decision.patches.is_empty() {
                continue;
            }
            if !input.modification_allowed {
                let err = Status::internal(format!(
                    "interceptor '{}' binding '{}' returned patches during non-modification phase '{}'",
                    binding.interceptor_name, binding.binding_id, input.phase
                ));
                handle_interceptor_failure(binding, err)?;
                continue;
            }
            if decision.patches.len() > self.max_patch_count {
                let err = Status::resource_exhausted(format!(
                    "interceptor '{}' binding '{}' returned {} patches; maximum is {}",
                    binding.interceptor_name,
                    binding.binding_id,
                    decision.patches.len(),
                    self.max_patch_count
                ));
                handle_interceptor_failure(binding, err)?;
                continue;
            }
            match apply_proto_patches(&mut object, &decision.patches) {
                Ok(()) => applied_patches.extend(decision.patches),
                Err(err) => {
                    let status = Status::invalid_argument(format!(
                        "interceptor '{}' binding '{}' returned invalid patches: {err}",
                        binding.interceptor_name, binding.binding_id
                    ));
                    handle_interceptor_failure(binding, status)?;
                }
            }
        }

        Ok(ReviewOutcome {
            object,
            applied_patches,
            warnings,
            audit_annotations,
        })
    }
}

async fn build_service_runtime(
    config: &InterceptorConfig,
) -> Result<InterceptorServiceRuntime, InterceptorConfigError> {
    let endpoint = InterceptorEndpoint::parse(&config.endpoint)?;
    let timeout = config
        .timeout
        .as_deref()
        .map(parse_duration)
        .transpose()?
        .unwrap_or(DEFAULT_TIMEOUT);
    let channel = connect_endpoint(&endpoint).await.map_err(|message| {
        InterceptorConfigError::DescribeFailed {
            interceptor: config.name.clone(),
            message,
        }
    })?;
    let client = GatewayInterceptorClient::new(channel)
        .max_decoding_message_size(DEFAULT_MAX_DECODING_MESSAGE_SIZE);
    Ok(InterceptorServiceRuntime {
        timeout,
        client: Mutex::new(client),
    })
}

async fn describe(
    config: &InterceptorConfig,
    client: &mut GatewayInterceptorClient<Channel>,
) -> Result<InterceptorManifest, InterceptorConfigError> {
    let request = InterceptorDescribeRequest {
        api_version: API_VERSION.to_string(),
        interceptor_name: config.name.clone(),
        config: Some(toml_value_to_struct(&config.config).map_err(|_| {
            InterceptorConfigError::ConfigMustBeTable {
                interceptor: config.name.clone(),
            }
        })?),
    };
    let timeout = config
        .timeout
        .as_deref()
        .map(parse_duration)
        .transpose()?
        .unwrap_or(DEFAULT_TIMEOUT);
    let response = tokio::time::timeout(timeout, client.describe(Request::new(request)))
        .await
        .map_err(|_| InterceptorConfigError::DescribeFailed {
            interceptor: config.name.clone(),
            message: "deadline exceeded".to_string(),
        })?
        .map_err(|status| InterceptorConfigError::DescribeFailed {
            interceptor: config.name.clone(),
            message: status.to_string(),
        })?;
    Ok(response.into_inner())
}

async fn connect_endpoint(endpoint: &InterceptorEndpoint) -> Result<Channel, String> {
    match endpoint {
        InterceptorEndpoint::Grpc { authority, tls } => {
            let scheme = if *tls { "https" } else { "http" };
            let mut endpoint = Endpoint::from_shared(format!("{scheme}://{authority}"))
                .map_err(|err| err.to_string())?;
            if *tls {
                endpoint = endpoint
                    .tls_config(ClientTlsConfig::new().with_enabled_roots())
                    .map_err(|err| err.to_string())?;
            }
            endpoint.connect().await.map_err(|err| err.to_string())
        }
        InterceptorEndpoint::Unix { path } => connect_unix(path).await,
    }
}

#[cfg(unix)]
async fn connect_unix(path: &std::path::Path) -> Result<Channel, String> {
    use tokio::net::UnixStream;

    let socket_path = path.to_path_buf();
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let socket_path = socket_path.clone();
            async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(|err| err.to_string())
}

#[cfg(not(unix))]
async fn connect_unix(path: &std::path::Path) -> Result<Channel, String> {
    Err(format!(
        "unix interceptor endpoint '{}' is not supported on this platform",
        path.display()
    ))
}

#[derive(Debug, Clone)]
struct RuntimeBinding {
    interceptor_name: String,
    binding_id: String,
    service_order: i32,
    binding_order: i32,
    phases: Vec<String>,
    resources: Vec<String>,
    operations: Vec<String>,
    failure_policy: FailurePolicy,
    selector: BindingSelector,
}

#[derive(Debug, Clone, Default)]
struct BindingSelector {
    principal_kinds: Vec<String>,
    principal_groups: Vec<String>,
    labels: BTreeMap<String, String>,
    compute_drivers: Vec<String>,
}

impl RuntimeBinding {
    fn matches(&self, input: &ReviewInput) -> bool {
        matches_string(&self.phases, &input.phase)
            && matches_string(&self.resources, &input.resource)
            && matches_string(&self.operations, &input.operation)
            && matches_string(&self.selector.principal_kinds, &input.principal.kind)
            && matches_groups(&self.selector.principal_groups, &input.principal.groups)
            && matches_string(
                &self.selector.compute_drivers,
                &input.context.compute_driver,
            )
            && matches_labels(&self.selector.labels, &input.context.labels)
    }
}

fn matches_string(selector: &[String], value: &str) -> bool {
    selector.is_empty() || selector.iter().any(|item| item == value)
}

fn matches_groups(selector: &[String], groups: &[String]) -> bool {
    selector.is_empty()
        || selector
            .iter()
            .any(|selected| groups.iter().any(|group| group == selected))
}

fn matches_labels(
    selector: &BTreeMap<String, String>,
    labels: &std::collections::HashMap<String, String>,
) -> bool {
    selector
        .iter()
        .all(|(key, value)| labels.get(key).is_some_and(|actual| actual == value))
}

fn validate_manifest(
    config: &InterceptorConfig,
    manifest: &InterceptorManifest,
) -> Result<(), InterceptorConfigError> {
    if !manifest.api_version.is_empty() && manifest.api_version != API_VERSION {
        return Err(InterceptorConfigError::UnsupportedApiVersion {
            interceptor: config.name.clone(),
            api_version: manifest.api_version.clone(),
        });
    }

    let mut ids = BTreeSet::new();
    for binding in &manifest.bindings {
        if binding.id.trim().is_empty() {
            return Err(InterceptorConfigError::MissingBindingId {
                interceptor: config.name.clone(),
            });
        }
        if !ids.insert(binding.id.clone()) {
            return Err(InterceptorConfigError::DuplicateBinding {
                interceptor: config.name.clone(),
                binding: binding.id.clone(),
            });
        }
        if binding.phases.is_empty() {
            return Err(InterceptorConfigError::MissingPhases {
                interceptor: config.name.clone(),
                binding: binding.id.clone(),
            });
        }
        for phase in &binding.phases {
            if !is_known_phase(phase) {
                return Err(InterceptorConfigError::UnknownPhase {
                    interceptor: config.name.clone(),
                    binding: binding.id.clone(),
                    phase: phase.clone(),
                });
            }
        }
        if binding.modifies
            && binding
                .phases
                .iter()
                .any(|phase| !is_modification_phase(phase))
        {
            return Err(InterceptorConfigError::InvalidModifies {
                interceptor: config.name.clone(),
                binding: binding.id.clone(),
            });
        }
    }

    for override_config in &config.overrides {
        if !ids.contains(&override_config.binding) {
            return Err(InterceptorConfigError::UnknownOverrideBinding {
                interceptor: config.name.clone(),
                binding: override_config.binding.clone(),
            });
        }
    }

    Ok(())
}

fn plan_bindings(
    config: &InterceptorConfig,
    manifest: &InterceptorManifest,
) -> Result<Vec<RuntimeBinding>, InterceptorConfigError> {
    let mut out = Vec::new();
    for binding in &manifest.bindings {
        let override_config = config
            .overrides
            .iter()
            .find(|override_config| override_config.binding == binding.id);
        if override_config.and_then(|o| o.enabled) == Some(false) {
            continue;
        }
        let phases = narrow_list(
            config,
            binding,
            "phases",
            &binding.phases,
            override_config.and_then(|o| o.match_.phases.as_ref()),
        )?;
        let resources = narrow_list(
            config,
            binding,
            "resources",
            &binding.resources,
            override_config.and_then(|o| o.match_.resources.as_ref()),
        )?;
        let operations = narrow_list(
            config,
            binding,
            "operations",
            &binding.operations,
            override_config.and_then(|o| o.match_.operations.as_ref()),
        )?;
        let selector = binding.selector.clone().unwrap_or_default();
        let principal_kinds = narrow_list(
            config,
            binding,
            "principal_kinds",
            &selector.principal_kinds,
            override_config.and_then(|o| o.match_.principal_kinds.as_ref()),
        )?;
        let principal_groups = narrow_list(
            config,
            binding,
            "principal_groups",
            &selector.principal_groups,
            override_config.and_then(|o| o.match_.principal_groups.as_ref()),
        )?;
        let compute_drivers = narrow_list(
            config,
            binding,
            "compute_drivers",
            &selector.compute_drivers,
            override_config.and_then(|o| o.match_.compute_drivers.as_ref()),
        )?;
        let labels = narrow_labels(
            config,
            binding,
            &selector.labels,
            override_config.and_then(|o| o.match_.labels.as_ref()),
        )?;
        let manifest_failure_policy = parse_manifest_failure_policy(binding).transpose()?;
        let failure_policy = override_config
            .and_then(|o| o.failure_policy)
            .or(config.failure_policy)
            .or(manifest_failure_policy)
            .unwrap_or_else(|| default_failure_policy(binding, &phases));
        if failure_policy == FailurePolicy::Ignore
            && phases.iter().any(|phase| phase != PHASE_POST_COMMIT)
        {
            return Err(InterceptorConfigError::InvalidIgnorePolicy {
                interceptor: config.name.clone(),
                binding: binding.id.clone(),
            });
        }
        let binding_order = override_config
            .and_then(|o| o.order)
            .unwrap_or(binding.order);
        out.push(RuntimeBinding {
            interceptor_name: config.name.clone(),
            binding_id: binding.id.clone(),
            service_order: config.order,
            binding_order,
            phases,
            resources,
            operations,
            failure_policy,
            selector: BindingSelector {
                principal_kinds,
                principal_groups,
                labels,
                compute_drivers,
            },
        });
    }
    Ok(out)
}

fn narrow_list(
    config: &InterceptorConfig,
    binding: &InterceptorBinding,
    field: &'static str,
    declared: &[String],
    override_values: Option<&Vec<String>>,
) -> Result<Vec<String>, InterceptorConfigError> {
    let Some(values) = override_values else {
        return Ok(declared.to_vec());
    };
    if !declared.is_empty() && values.iter().any(|value| !declared.contains(value)) {
        return Err(InterceptorConfigError::OverrideExpands {
            interceptor: config.name.clone(),
            binding: binding.id.clone(),
            field,
        });
    }
    Ok(values.clone())
}

fn narrow_labels(
    config: &InterceptorConfig,
    binding: &InterceptorBinding,
    declared: &std::collections::HashMap<String, String>,
    override_values: Option<&BTreeMap<String, String>>,
) -> Result<BTreeMap<String, String>, InterceptorConfigError> {
    let declared = declared
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let Some(values) = override_values else {
        return Ok(declared);
    };
    for (key, value) in values {
        if let Some(declared_value) = declared.get(key)
            && declared_value != value
        {
            return Err(InterceptorConfigError::OverrideExpands {
                interceptor: config.name.clone(),
                binding: binding.id.clone(),
                field: "labels",
            });
        }
    }
    let mut narrowed = declared;
    narrowed.extend(values.clone());
    Ok(narrowed)
}

fn parse_manifest_failure_policy(
    binding: &InterceptorBinding,
) -> Option<Result<FailurePolicy, InterceptorConfigError>> {
    (!binding.default_failure_policy.trim().is_empty())
        .then(|| binding.default_failure_policy.parse())
}

fn default_failure_policy(_binding: &InterceptorBinding, phases: &[String]) -> FailurePolicy {
    if phases.iter().all(|phase| phase == PHASE_POST_COMMIT) {
        FailurePolicy::Ignore
    } else {
        FailurePolicy::FailClosed
    }
}

fn is_known_phase(phase: &str) -> bool {
    matches!(
        phase,
        PHASE_PRE_REQUEST
            | PHASE_MODIFY_OBJECT
            | PHASE_VALIDATE_OBJECT
            | PHASE_VALIDATE_DRIVER
            | PHASE_POST_COMMIT
    )
}

fn is_modification_phase(phase: &str) -> bool {
    matches!(phase, PHASE_PRE_REQUEST | PHASE_MODIFY_OBJECT)
}

async fn call_review(
    service: &InterceptorServiceRuntime,
    review: InterceptorReview,
    binding: &RuntimeBinding,
) -> Result<InterceptorDecision, Status> {
    let started = Instant::now();
    let mut client = service.client.lock().await;
    let response = tokio::time::timeout(service.timeout, client.review(Request::new(review)))
        .await
        .map_err(|_| Status::deadline_exceeded("interceptor review deadline exceeded"))?
        .map_err(|status| {
            Status::new(
                status.code(),
                format!("interceptor review failed: {}", status.message()),
            )
        });
    let elapsed = started.elapsed().as_secs_f64();
    let code = response.as_ref().map_or_else(
        |status| status.code().to_string(),
        |_| tonic::Code::Ok.to_string(),
    );
    counter!(
        "openshell_gateway_interceptor_reviews_total",
        "interceptor" => binding.interceptor_name.clone(),
        "binding" => binding.binding_id.clone(),
        "code" => code.clone(),
    )
    .increment(1);
    histogram!(
        "openshell_gateway_interceptor_review_latency_seconds",
        "interceptor" => binding.interceptor_name.clone(),
        "binding" => binding.binding_id.clone(),
        "code" => code,
    )
    .record(elapsed);
    response.map(tonic::Response::into_inner)
}

fn handle_interceptor_failure(binding: &RuntimeBinding, status: Status) -> Result<(), ReviewError> {
    counter!(
        "openshell_gateway_interceptor_failures_total",
        "interceptor" => binding.interceptor_name.clone(),
        "binding" => binding.binding_id.clone(),
        "failure_policy" => binding.failure_policy.as_str(),
        "code" => status.code().to_string(),
    )
    .increment(1);
    match binding.failure_policy {
        FailurePolicy::FailClosed => Err(ReviewError::Failed(status)),
        FailurePolicy::FailOpen => {
            warn!(
                interceptor = %binding.interceptor_name,
                binding = %binding.binding_id,
                failure_policy = %binding.failure_policy,
                error = %status,
                "interceptor failure ignored by fail_open policy"
            );
            Ok(())
        }
        FailurePolicy::Ignore => {
            debug!(
                interceptor = %binding.interceptor_name,
                binding = %binding.binding_id,
                failure_policy = %binding.failure_policy,
                error = %status,
                "post_commit interceptor failure ignored"
            );
            Ok(())
        }
    }
}

fn log_decision(binding: &RuntimeBinding, input: &ReviewInput, decision: &InterceptorDecision) {
    info!(
        interceptor = %binding.interceptor_name,
        binding = %binding.binding_id,
        phase = %input.phase,
        resource = %input.resource,
        operation = %input.operation,
        principal_subject = %input.principal.subject,
        decision = if decision.allowed { "allow" } else { "deny" },
        reason = %decision.reason,
        failure_policy = %binding.failure_policy,
        patch_count = decision.patches.len(),
        audit_annotations = ?decision.audit_annotations,
        warnings = ?decision.warnings,
        "gateway interceptor decision"
    );
}

fn metrics_decision(binding: &RuntimeBinding, input: &ReviewInput, decision: &InterceptorDecision) {
    counter!(
        "openshell_gateway_interceptor_decisions_total",
        "interceptor" => binding.interceptor_name.clone(),
        "binding" => binding.binding_id.clone(),
        "phase" => input.phase.clone(),
        "resource" => input.resource.clone(),
        "operation" => input.operation.clone(),
        "decision" => if decision.allowed { "allow" } else { "deny" },
    )
    .increment(1);
}

fn status_code(value: &str) -> tonic::Code {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return tonic::Code::PermissionDenied;
    }
    match value.as_str() {
        "cancelled" | "canceled" => tonic::Code::Cancelled,
        "unknown" => tonic::Code::Unknown,
        "invalid_argument" => tonic::Code::InvalidArgument,
        "deadline_exceeded" => tonic::Code::DeadlineExceeded,
        "not_found" => tonic::Code::NotFound,
        "already_exists" => tonic::Code::AlreadyExists,
        "resource_exhausted" => tonic::Code::ResourceExhausted,
        "failed_precondition" => tonic::Code::FailedPrecondition,
        "aborted" => tonic::Code::Aborted,
        "out_of_range" => tonic::Code::OutOfRange,
        "unimplemented" => tonic::Code::Unimplemented,
        "internal" => tonic::Code::Internal,
        "unavailable" => tonic::Code::Unavailable,
        "data_loss" => tonic::Code::DataLoss,
        "unauthenticated" => tonic::Code::Unauthenticated,
        _ => tonic::Code::PermissionDenied,
    }
}

pub fn parse_duration(value: &str) -> Result<Duration, InterceptorConfigError> {
    let value = value.trim();
    let split_at = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split_at);
    if number.is_empty() || unit.is_empty() {
        return Err(InterceptorConfigError::InvalidTimeout {
            value: value.to_string(),
        });
    }
    let number = number
        .parse::<u64>()
        .map_err(|_| InterceptorConfigError::InvalidTimeout {
            value: value.to_string(),
        })?;
    match unit {
        "ms" => Ok(Duration::from_millis(number)),
        "s" => Ok(Duration::from_secs(number)),
        "m" => Ok(Duration::from_secs(number.saturating_mul(60))),
        _ => Err(InterceptorConfigError::InvalidTimeout {
            value: value.to_string(),
        }),
    }
}

pub fn apply_proto_patches(object: &mut JsonValue, patches: &[JsonPatch]) -> Result<(), String> {
    let patch = proto_patches_to_json_patch(patches)?;
    json_patch::patch(object, &patch).map_err(|err| err.to_string())
}

fn proto_patches_to_json_patch(patches: &[JsonPatch]) -> Result<json_patch::Patch, String> {
    let values = patches
        .iter()
        .map(|patch| {
            let mut object = JsonMap::new();
            object.insert("op".to_string(), JsonValue::String(patch.op.clone()));
            object.insert("path".to_string(), JsonValue::String(patch.path.clone()));
            if !patch.from.is_empty() {
                object.insert("from".to_string(), JsonValue::String(patch.from.clone()));
            }
            if let Some(value) = patch.value.as_ref() {
                object.insert("value".to_string(), proto_value_to_json(value));
            }
            JsonValue::Object(object)
        })
        .collect::<Vec<_>>();
    serde_json::from_value(JsonValue::Array(values)).map_err(|err| err.to_string())
}

pub fn json_to_struct(value: &JsonValue) -> Result<Struct, String> {
    match value {
        JsonValue::Object(object) => Ok(Struct {
            fields: object
                .iter()
                .map(|(key, value)| Ok((key.clone(), json_to_proto_value(value)?)))
                .collect::<Result<_, String>>()?,
        }),
        _ => Err("protobuf Struct payload must be a JSON object".to_string()),
    }
}

pub fn struct_to_json(value: &Struct) -> JsonValue {
    JsonValue::Object(
        value
            .fields
            .iter()
            .map(|(key, value)| (key.clone(), proto_value_to_json(value)))
            .collect(),
    )
}

pub fn json_to_proto_value(value: &JsonValue) -> Result<ProtoValue, String> {
    let kind = match value {
        JsonValue::Null => Kind::NullValue(0),
        JsonValue::Bool(value) => Kind::BoolValue(*value),
        JsonValue::Number(value) => Kind::NumberValue(
            value
                .as_f64()
                .ok_or_else(|| "JSON number is not representable as f64".to_string())?,
        ),
        JsonValue::String(value) => Kind::StringValue(value.clone()),
        JsonValue::Array(values) => Kind::ListValue(ListValue {
            values: values
                .iter()
                .map(json_to_proto_value)
                .collect::<Result<_, _>>()?,
        }),
        JsonValue::Object(values) => {
            Kind::StructValue(json_to_struct(&JsonValue::Object(values.clone()))?)
        }
    };
    Ok(ProtoValue { kind: Some(kind) })
}

pub fn proto_value_to_json(value: &ProtoValue) -> JsonValue {
    match value.kind.as_ref() {
        Some(Kind::NullValue(_)) | None => JsonValue::Null,
        Some(Kind::NumberValue(value)) => {
            serde_json::Number::from_f64(*value).map_or(JsonValue::Null, JsonValue::Number)
        }
        Some(Kind::StringValue(value)) => JsonValue::String(value.clone()),
        Some(Kind::BoolValue(value)) => JsonValue::Bool(*value),
        Some(Kind::StructValue(value)) => struct_to_json(value),
        Some(Kind::ListValue(value)) => {
            JsonValue::Array(value.values.iter().map(proto_value_to_json).collect())
        }
    }
}

pub fn toml_value_to_struct(value: &toml::Value) -> Result<Struct, String> {
    json_to_struct(&toml_to_json(value))
}

fn toml_to_json(value: &toml::Value) -> JsonValue {
    match value {
        toml::Value::String(value) => JsonValue::String(value.clone()),
        toml::Value::Integer(value) => serde_json::json!(value),
        toml::Value::Float(value) => {
            serde_json::Number::from_f64(*value).map_or(JsonValue::Null, JsonValue::Number)
        }
        toml::Value::Boolean(value) => JsonValue::Bool(*value),
        toml::Value::Datetime(value) => JsonValue::String(value.to_string()),
        toml::Value::Array(values) => JsonValue::Array(values.iter().map(toml_to_json).collect()),
        toml::Value::Table(values) => JsonValue::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), toml_to_json(value)))
                .collect(),
        ),
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use openshell_core::proto::interceptor::v1::InterceptorSelector;

    #[must_use]
    pub fn allow_manifest(binding: InterceptorBinding) -> InterceptorManifest {
        InterceptorManifest {
            api_version: API_VERSION.to_string(),
            bindings: vec![binding],
        }
    }

    #[must_use]
    pub fn binding(id: &str, phase: &str, resource: &str, operation: &str) -> InterceptorBinding {
        InterceptorBinding {
            id: id.to_string(),
            phases: vec![phase.to_string()],
            resources: vec![resource.to_string()],
            operations: vec![operation.to_string()],
            order: 0,
            modifies: matches!(phase, PHASE_PRE_REQUEST | PHASE_MODIFY_OBJECT),
            default_failure_policy: String::new(),
            selector: Some(InterceptorSelector::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::interceptor::v1::InterceptorSelector;

    #[test]
    fn parses_endpoints() {
        assert!(matches!(
            InterceptorEndpoint::parse("grpc://127.0.0.1:9000").unwrap(),
            InterceptorEndpoint::Grpc { tls: false, .. }
        ));
        assert!(matches!(
            InterceptorEndpoint::parse("grpcs://policy.example.com:443").unwrap(),
            InterceptorEndpoint::Grpc { tls: true, .. }
        ));
        assert!(matches!(
            InterceptorEndpoint::parse("unix:///tmp/interceptor.sock").unwrap(),
            InterceptorEndpoint::Unix { .. }
        ));
        assert!(InterceptorEndpoint::parse("http://127.0.0.1:9000").is_err());
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert!(parse_duration("1hour").is_err());
    }

    #[test]
    fn applies_json_patch() {
        let mut object = serde_json::json!({"metadata": {"name": "demo"}});
        let patches = vec![JsonPatch {
            op: "replace".to_string(),
            path: "/metadata/name".to_string(),
            from: String::new(),
            value: Some(json_to_proto_value(&serde_json::json!("nvidia-demo")).unwrap()),
        }];
        apply_proto_patches(&mut object, &patches).unwrap();
        assert_eq!(object["metadata"]["name"], "nvidia-demo");
    }

    #[test]
    fn override_cannot_expand_declared_resources() {
        let config = InterceptorConfig {
            name: "org".to_string(),
            endpoint: "grpc://127.0.0.1:9000".to_string(),
            overrides: vec![BindingOverrideConfig {
                binding: "b".to_string(),
                match_: BindingMatchConfig {
                    resources: Some(vec!["provider".to_string()]),
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let manifest = InterceptorManifest {
            api_version: API_VERSION.to_string(),
            bindings: vec![InterceptorBinding {
                id: "b".to_string(),
                phases: vec![PHASE_VALIDATE_OBJECT.to_string()],
                resources: vec!["sandbox".to_string()],
                operations: vec!["create".to_string()],
                order: 0,
                modifies: false,
                default_failure_policy: String::new(),
                selector: Some(InterceptorSelector::default()),
            }],
        };
        let err = plan_bindings(&config, &manifest).unwrap_err();
        assert!(matches!(
            err,
            InterceptorConfigError::OverrideExpands {
                field: "resources",
                ..
            }
        ));
    }

    #[test]
    fn manifest_rejects_modifying_validation_binding() {
        let config = InterceptorConfig {
            name: "org".to_string(),
            endpoint: "grpc://127.0.0.1:9000".to_string(),
            ..Default::default()
        };
        let manifest = InterceptorManifest {
            api_version: API_VERSION.to_string(),
            bindings: vec![InterceptorBinding {
                id: "b".to_string(),
                phases: vec![PHASE_VALIDATE_OBJECT.to_string()],
                resources: vec!["sandbox".to_string()],
                operations: vec!["create".to_string()],
                order: 0,
                modifies: true,
                default_failure_policy: String::new(),
                selector: Some(InterceptorSelector::default()),
            }],
        };
        let err = validate_manifest(&config, &manifest).unwrap_err();
        assert!(matches!(
            err,
            InterceptorConfigError::InvalidModifies { .. }
        ));
    }

    #[test]
    fn post_commit_defaults_to_ignore() {
        let config = InterceptorConfig {
            name: "org".to_string(),
            endpoint: "grpc://127.0.0.1:9000".to_string(),
            ..Default::default()
        };
        let manifest = InterceptorManifest {
            api_version: API_VERSION.to_string(),
            bindings: vec![InterceptorBinding {
                id: "audit".to_string(),
                phases: vec![PHASE_POST_COMMIT.to_string()],
                resources: vec!["sandbox".to_string()],
                operations: vec!["create".to_string()],
                order: 0,
                modifies: false,
                default_failure_policy: String::new(),
                selector: Some(InterceptorSelector::default()),
            }],
        };
        let bindings = plan_bindings(&config, &manifest).unwrap();
        assert_eq!(bindings[0].failure_policy, FailurePolicy::Ignore);
    }

    #[test]
    fn selector_matches_driver_and_labels() {
        let config = InterceptorConfig {
            name: "org".to_string(),
            endpoint: "grpc://127.0.0.1:9000".to_string(),
            ..Default::default()
        };
        let manifest = InterceptorManifest {
            api_version: API_VERSION.to_string(),
            bindings: vec![InterceptorBinding {
                id: "sandbox-policy".to_string(),
                phases: vec![PHASE_VALIDATE_OBJECT.to_string()],
                resources: vec!["sandbox".to_string()],
                operations: vec!["create".to_string()],
                order: 0,
                modifies: false,
                default_failure_policy: String::new(),
                selector: Some(InterceptorSelector {
                    principal_kinds: Vec::new(),
                    principal_groups: Vec::new(),
                    labels: BTreeMap::from([("team".to_string(), "platform".to_string())])
                        .into_iter()
                        .collect(),
                    compute_drivers: vec!["docker".to_string()],
                }),
            }],
        };
        let binding = plan_bindings(&config, &manifest).unwrap().remove(0);
        let mut labels = std::collections::HashMap::new();
        labels.insert("team".to_string(), "platform".to_string());
        let input = ReviewInput {
            phase: PHASE_VALIDATE_OBJECT.to_string(),
            resource: "sandbox".to_string(),
            operation: "create".to_string(),
            principal: InterceptorPrincipal {
                kind: "user".to_string(),
                subject: "alice".to_string(),
                groups: Vec::new(),
            },
            context: InterceptorRequestContext {
                request_id: "req-1".to_string(),
                gateway_replica_id: "gateway".to_string(),
                compute_driver: "docker".to_string(),
                dry_run: false,
                labels,
            },
            object: serde_json::json!({}),
            old_object: None,
            request: None,
            modification_allowed: false,
        };
        assert!(binding.matches(&input));
    }
}
