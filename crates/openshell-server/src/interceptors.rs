// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Server-side gateway interceptor integration helpers.

#![allow(
    clippy::result_large_err,
    clippy::redundant_pub_crate,
    clippy::too_many_arguments,
    clippy::unnecessary_wraps
)]

use std::collections::HashMap;

use base64::Engine as _;
use openshell_core::proto::compute::v1::{
    DriverResourceRequirements, DriverSandbox, DriverSandboxSpec, DriverSandboxStatus,
    DriverSandboxTemplate,
};
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::interceptor::v1::InterceptorRequestContext as ProtoInterceptorRequestContext;
use openshell_core::proto::setting_value;
use openshell_core::proto::{
    AddAllowRules, AddDenyRules, AddNetworkRule, CreateProviderRequest, CreateSandboxRequest,
    DetachSandboxProviderRequest, FilesystemPolicy, GraphqlOperation,
    ImportProviderProfilesRequest, L7Allow, L7DenyRule, L7QueryMatcher, L7Rule, LandlockPolicy,
    NetworkBinary, NetworkEndpoint, NetworkPolicyRule, PolicyMergeOperation, ProcessPolicy,
    Provider, ProviderCredentialRefresh, ProviderCredentialRefreshMaterial,
    ProviderCredentialTokenGrant, ProviderCredentialTokenGrantAudienceOverride, ProviderProfile,
    ProviderProfileDiscovery, ProviderProfileImportItem, RemoveNetworkBinary,
    RemoveNetworkEndpoint, RemoveNetworkRule, Sandbox, SandboxCondition, SandboxPolicy,
    SandboxSpec, SandboxStatus, SandboxTemplate, SettingValue, UpdateConfigRequest,
    UpdateProviderRequest, policy_merge_operation,
};
use openshell_interceptors::{
    PHASE_MODIFY_OBJECT, PHASE_PRE_REQUEST, ReviewError, ReviewInput, ReviewOutcome,
    apply_proto_patches,
};
use openshell_interceptors::{json_to_struct, struct_to_json};
use openshell_ocsf::{
    ActionId, ActivityId, DetectionFindingBuilder, DispositionId, FindingInfo, OCSF_TARGET,
    OcsfEvent, RiskLevelId, SandboxContext, SeverityId,
};
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use tonic::{Request, Status};
use tracing::info;

use crate::ServerState;
use crate::auth::principal::Principal;

pub(crate) const RESOURCE_SANDBOX: &str = "sandbox";
pub(crate) const RESOURCE_PROVIDER: &str = "provider";
pub(crate) const RESOURCE_PROVIDER_PROFILE: &str = "provider_profile";
pub(crate) const RESOURCE_CONFIG: &str = "config";
pub(crate) const RESOURCE_DRIVER_SANDBOX: &str = "driver_sandbox";

pub(crate) const OP_CREATE: &str = "create";
pub(crate) const OP_UPDATE: &str = "update";
pub(crate) const OP_DELETE: &str = "delete";
pub(crate) const OP_IMPORT: &str = "import";
pub(crate) const OP_ATTACH_PROVIDER: &str = "attach_provider";
pub(crate) const OP_DETACH_PROVIDER: &str = "detach_provider";
pub(crate) const OP_MERGE: &str = "merge";
pub(crate) const OP_VALIDATE: &str = "validate";

#[derive(Debug, Clone)]
pub(crate) struct InterceptorRequestInfo {
    principal: openshell_core::proto::interceptor::v1::InterceptorPrincipal,
    request_id: String,
}

pub(crate) fn request_info<T>(request: &Request<T>) -> InterceptorRequestInfo {
    InterceptorRequestInfo {
        principal: interceptor_principal(request.extensions().get::<Principal>()),
        request_id: request
            .metadata()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .map_or_else(|| uuid::Uuid::new_v4().to_string(), ToString::to_string),
    }
}

pub(crate) async fn review_json(
    state: &ServerState,
    info: &InterceptorRequestInfo,
    phase: &str,
    resource: &str,
    operation: &str,
    object: JsonValue,
    old_object: Option<JsonValue>,
    request: Option<JsonValue>,
    labels: HashMap<String, String>,
) -> Result<ReviewOutcome, Status> {
    if state.interceptors.is_empty() {
        return Ok(ReviewOutcome {
            object,
            applied_patches: Vec::new(),
            warnings: Vec::new(),
            audit_annotations: std::collections::BTreeMap::new(),
        });
    }
    let input = ReviewInput {
        phase: phase.to_string(),
        resource: resource.to_string(),
        operation: operation.to_string(),
        principal: info.principal.clone(),
        context: ProtoInterceptorRequestContext {
            request_id: info.request_id.clone(),
            gateway_replica_id: "openshell-gateway".to_string(),
            compute_driver: state
                .compute
                .driver_kind()
                .map_or_else(String::new, |driver| driver.as_str().to_string()),
            dry_run: false,
            labels,
        },
        object,
        old_object,
        request,
        modification_allowed: matches!(phase, PHASE_PRE_REQUEST | PHASE_MODIFY_OBJECT),
    };
    state
        .interceptors
        .review(input)
        .await
        .map_err(|error| review_error_to_status(error, phase, resource, operation))
}

fn review_error_to_status(
    error: ReviewError,
    phase: &str,
    resource: &str,
    operation: &str,
) -> Status {
    match &error {
        ReviewError::Denied {
            interceptor,
            binding,
            phase,
            resource,
            operation,
            reason,
            ..
        } => {
            emit_interceptor_denial(interceptor, binding, phase, resource, operation, reason);
        }
        ReviewError::Failed(status) => {
            emit_interceptor_failure(phase, resource, operation, status);
        }
    }
    error.into_status()
}

fn emit_interceptor_denial(
    interceptor: &str,
    binding: &str,
    phase: &str,
    resource: &str,
    operation: &str,
    reason: &str,
) {
    let ctx = gateway_ocsf_ctx();
    let event = DetectionFindingBuilder::new(&ctx)
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::High)
        .risk_level(RiskLevelId::High)
        .finding_info(
            FindingInfo::new("gateway_interceptor_denial", "Gateway interceptor denial")
                .with_desc(reason),
        )
        .evidence_pairs(&[
            ("interceptor", interceptor),
            ("binding", binding),
            ("phase", phase),
            ("resource", resource),
            ("operation", operation),
        ])
        .message(format!(
            "Gateway interceptor denied {resource}.{operation} during {phase}: {reason}"
        ))
        .build();
    emit_gateway_ocsf_event(event);
}

fn emit_interceptor_failure(phase: &str, resource: &str, operation: &str, status: &Status) {
    let ctx = gateway_ocsf_ctx();
    let code = status.code().to_string();
    let event = DetectionFindingBuilder::new(&ctx)
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::High)
        .risk_level(RiskLevelId::High)
        .finding_info(
            FindingInfo::new("gateway_interceptor_failure", "Gateway interceptor failure")
                .with_desc(status.message()),
        )
        .evidence_pairs(&[
            ("phase", phase),
            ("resource", resource),
            ("operation", operation),
            ("code", code.as_str()),
        ])
        .message(format!(
            "Gateway interceptor failed {resource}.{operation} during {phase}: {}",
            status.message()
        ))
        .build();
    emit_gateway_ocsf_event(event);
}

fn emit_gateway_ocsf_event(event: OcsfEvent) {
    let message = event.format_shorthand();
    info!(target: OCSF_TARGET, sandbox_id = "", message = %message);
}

fn gateway_ocsf_ctx() -> SandboxContext {
    SandboxContext {
        sandbox_id: String::new(),
        sandbox_name: String::new(),
        container_image: "openshell/gateway".to_string(),
        hostname: "openshell-gateway".to_string(),
        product_version: openshell_core::VERSION.to_string(),
        proxy_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        proxy_port: 0,
    }
}

fn interceptor_principal(
    principal: Option<&Principal>,
) -> openshell_core::proto::interceptor::v1::InterceptorPrincipal {
    match principal {
        Some(Principal::User(user)) => {
            openshell_core::proto::interceptor::v1::InterceptorPrincipal {
                kind: "user".to_string(),
                subject: user.identity.subject.clone(),
                groups: user.identity.roles.clone(),
            }
        }
        Some(Principal::Sandbox(sandbox)) => {
            openshell_core::proto::interceptor::v1::InterceptorPrincipal {
                kind: "sandbox".to_string(),
                subject: sandbox.sandbox_id.clone(),
                groups: Vec::new(),
            }
        }
        Some(Principal::Anonymous) | None => {
            openshell_core::proto::interceptor::v1::InterceptorPrincipal {
                kind: "anonymous".to_string(),
                subject: String::new(),
                groups: Vec::new(),
            }
        }
    }
}

pub(crate) fn provider_patch_targets_allowed(
    patches: &[openshell_core::proto::interceptor::v1::JsonPatch],
) -> Result<(), Status> {
    for patch in patches {
        if patch.path == "/credentials" || patch.path.starts_with("/credentials/") {
            return Err(Status::permission_denied(
                "interceptor patches cannot modify provider credential values",
            ));
        }
        if patch.from == "/credentials" || patch.from.starts_with("/credentials/") {
            return Err(Status::permission_denied(
                "interceptor patches cannot read provider credential values",
            ));
        }
    }
    Ok(())
}

pub(crate) fn apply_patches_to_original(
    mut object: JsonValue,
    patches: &[openshell_core::proto::interceptor::v1::JsonPatch],
) -> Result<JsonValue, Status> {
    apply_proto_patches(&mut object, patches).map_err(|err| {
        Status::invalid_argument(format!("apply interceptor patches failed: {err}"))
    })?;
    Ok(object)
}

pub(crate) fn create_sandbox_request_to_json(request: &CreateSandboxRequest) -> JsonValue {
    json!({
        "spec": request.spec.as_ref().map(sandbox_spec_to_json),
        "name": request.name,
        "labels": request.labels,
    })
}

pub(crate) fn create_sandbox_request_from_json(
    value: &JsonValue,
) -> Result<CreateSandboxRequest, Status> {
    let object = expect_object(value, "CreateSandboxRequest")?;
    Ok(CreateSandboxRequest {
        spec: optional_object_field(object, "spec")?
            .map(sandbox_spec_from_json)
            .transpose()?,
        name: string_field(object, "name")?,
        labels: string_map_field(object, "labels")?,
    })
}

pub(crate) fn attach_provider_request_to_json(
    sandbox_name: &str,
    provider_name: &str,
    expected_resource_version: u64,
) -> JsonValue {
    json!({
        "sandbox_name": sandbox_name,
        "provider_name": provider_name,
        "expected_resource_version": expected_resource_version,
    })
}

pub(crate) fn attach_provider_request_from_json(
    value: &JsonValue,
) -> Result<(String, String, u64), Status> {
    let object = expect_object(value, "AttachSandboxProviderRequest")?;
    Ok((
        string_field(object, "sandbox_name")?,
        string_field(object, "provider_name")?,
        u64_field(object, "expected_resource_version")?,
    ))
}

pub(crate) fn detach_provider_request_to_json(request: &DetachSandboxProviderRequest) -> JsonValue {
    json!({
        "sandbox_name": request.sandbox_name,
        "provider_name": request.provider_name,
        "expected_resource_version": request.expected_resource_version,
    })
}

pub(crate) fn detach_provider_request_from_json(
    value: &JsonValue,
) -> Result<DetachSandboxProviderRequest, Status> {
    let object = expect_object(value, "DetachSandboxProviderRequest")?;
    Ok(DetachSandboxProviderRequest {
        sandbox_name: string_field(object, "sandbox_name")?,
        provider_name: string_field(object, "provider_name")?,
        expected_resource_version: u64_field(object, "expected_resource_version")?,
    })
}

pub(crate) fn sandbox_to_json(sandbox: &Sandbox) -> JsonValue {
    json!({
        "metadata": sandbox.metadata.as_ref().map(object_meta_to_json),
        "spec": sandbox.spec.as_ref().map(sandbox_spec_to_json),
        "status": sandbox.status.as_ref().map(sandbox_status_to_json),
    })
}

pub(crate) fn sandbox_from_json(value: &JsonValue) -> Result<Sandbox, Status> {
    let object = expect_object(value, "Sandbox")?;
    Ok(Sandbox {
        metadata: optional_object_field(object, "metadata")?
            .map(object_meta_from_json)
            .transpose()?,
        spec: optional_object_field(object, "spec")?
            .map(sandbox_spec_from_json)
            .transpose()?,
        status: optional_object_field(object, "status")?
            .map(sandbox_status_from_json)
            .transpose()?,
    })
}

pub(crate) fn driver_sandbox_to_json(sandbox: &DriverSandbox) -> JsonValue {
    json!({
        "id": sandbox.id,
        "name": sandbox.name,
        "namespace": sandbox.namespace,
        "spec": sandbox.spec.as_ref().map(driver_sandbox_spec_to_json),
        "status": sandbox.status.as_ref().map(driver_sandbox_status_to_json),
    })
}

pub(crate) fn create_provider_request_to_json(
    request: &CreateProviderRequest,
    redact_credentials: bool,
) -> JsonValue {
    json!({
        "provider": request.provider.as_ref().map(|provider| provider_to_json(provider, redact_credentials)),
    })
}

pub(crate) fn create_provider_request_from_json(
    value: &JsonValue,
) -> Result<CreateProviderRequest, Status> {
    let object = expect_object(value, "CreateProviderRequest")?;
    Ok(CreateProviderRequest {
        provider: optional_object_field(object, "provider")?
            .map(provider_from_json)
            .transpose()?,
    })
}

pub(crate) fn update_provider_request_to_json(
    request: &UpdateProviderRequest,
    redact_credentials: bool,
) -> JsonValue {
    json!({
        "provider": request.provider.as_ref().map(|provider| provider_to_json(provider, redact_credentials)),
        "credential_expires_at_ms": request.credential_expires_at_ms,
    })
}

pub(crate) fn update_provider_request_from_json(
    value: &JsonValue,
) -> Result<UpdateProviderRequest, Status> {
    let object = expect_object(value, "UpdateProviderRequest")?;
    Ok(UpdateProviderRequest {
        provider: optional_object_field(object, "provider")?
            .map(provider_from_json)
            .transpose()?,
        credential_expires_at_ms: i64_map_field(object, "credential_expires_at_ms")?,
    })
}

pub(crate) fn provider_to_json(provider: &Provider, redact_credentials: bool) -> JsonValue {
    let credentials = if redact_credentials {
        provider
            .credentials
            .keys()
            .map(|key| (key.clone(), JsonValue::String("REDACTED".to_string())))
            .collect::<JsonMap<_, _>>()
    } else {
        provider
            .credentials
            .iter()
            .map(|(key, value)| (key.clone(), JsonValue::String(value.clone())))
            .collect::<JsonMap<_, _>>()
    };
    json!({
        "metadata": provider.metadata.as_ref().map(object_meta_to_json),
        "type": provider.r#type,
        "credentials": credentials,
        "config": provider.config,
        "credential_expires_at_ms": provider.credential_expires_at_ms,
    })
}

pub(crate) fn provider_from_json(value: &JsonValue) -> Result<Provider, Status> {
    let object = expect_object(value, "Provider")?;
    Ok(Provider {
        metadata: optional_object_field(object, "metadata")?
            .map(object_meta_from_json)
            .transpose()?,
        r#type: string_field(object, "type")?,
        credentials: string_map_field(object, "credentials")?,
        config: string_map_field(object, "config")?,
        credential_expires_at_ms: i64_map_field(object, "credential_expires_at_ms")?,
    })
}

pub(crate) fn import_provider_profiles_request_to_json(
    request: &ImportProviderProfilesRequest,
) -> JsonValue {
    json!({
        "profiles": request.profiles.iter().map(provider_profile_import_item_to_json).collect::<Vec<_>>(),
    })
}

pub(crate) fn import_provider_profiles_request_from_json(
    value: &JsonValue,
) -> Result<ImportProviderProfilesRequest, Status> {
    let object = expect_object(value, "ImportProviderProfilesRequest")?;
    Ok(ImportProviderProfilesRequest {
        profiles: array_field(object, "profiles")?
            .iter()
            .map(provider_profile_import_item_from_json)
            .collect::<Result<_, _>>()?,
    })
}

pub(crate) fn update_config_request_to_json(request: &UpdateConfigRequest) -> JsonValue {
    json!({
        "name": request.name,
        "policy": request.policy.as_ref().map(sandbox_policy_to_json),
        "setting_key": request.setting_key,
        "setting_value": request.setting_value.as_ref().map(setting_value_to_json),
        "delete_setting": request.delete_setting,
        "global": request.global,
        "merge_operations": request.merge_operations.iter().map(policy_merge_operation_to_json).collect::<Vec<_>>(),
        "expected_resource_version": request.expected_resource_version,
    })
}

pub(crate) fn update_config_request_from_json(
    value: &JsonValue,
) -> Result<UpdateConfigRequest, Status> {
    let object = expect_object(value, "UpdateConfigRequest")?;
    Ok(UpdateConfigRequest {
        name: string_field(object, "name")?,
        policy: optional_object_field(object, "policy")?
            .map(sandbox_policy_from_json)
            .transpose()?,
        setting_key: string_field(object, "setting_key")?,
        setting_value: optional_object_field(object, "setting_value")?
            .map(setting_value_from_json)
            .transpose()?,
        delete_setting: bool_field(object, "delete_setting")?,
        global: bool_field(object, "global")?,
        merge_operations: array_field(object, "merge_operations")?
            .iter()
            .map(policy_merge_operation_from_json)
            .collect::<Result<_, _>>()?,
        expected_resource_version: u64_field(object, "expected_resource_version")?,
    })
}

fn object_meta_to_json(metadata: &ObjectMeta) -> JsonValue {
    json!({
        "id": metadata.id,
        "name": metadata.name,
        "created_at_ms": metadata.created_at_ms,
        "labels": metadata.labels,
        "resource_version": metadata.resource_version,
    })
}

fn object_meta_from_json(value: &JsonValue) -> Result<ObjectMeta, Status> {
    let object = expect_object(value, "ObjectMeta")?;
    Ok(ObjectMeta {
        id: string_field(object, "id")?,
        name: string_field(object, "name")?,
        created_at_ms: i64_field(object, "created_at_ms")?,
        labels: string_map_field(object, "labels")?,
        resource_version: u64_field(object, "resource_version")?,
    })
}

fn sandbox_spec_to_json(spec: &SandboxSpec) -> JsonValue {
    json!({
        "log_level": spec.log_level,
        "environment": spec.environment,
        "template": spec.template.as_ref().map(sandbox_template_to_json),
        "policy": spec.policy.as_ref().map(sandbox_policy_to_json),
        "providers": spec.providers,
        "gpu": spec.gpu,
    })
}

fn sandbox_spec_from_json(value: &JsonValue) -> Result<SandboxSpec, Status> {
    let object = expect_object(value, "SandboxSpec")?;
    Ok(SandboxSpec {
        log_level: string_field(object, "log_level")?,
        environment: string_map_field(object, "environment")?,
        template: optional_object_field(object, "template")?
            .map(sandbox_template_from_json)
            .transpose()?,
        policy: optional_object_field(object, "policy")?
            .map(sandbox_policy_from_json)
            .transpose()?,
        providers: string_array_field(object, "providers")?,
        gpu: bool_field(object, "gpu")?,
    })
}

fn sandbox_template_to_json(template: &SandboxTemplate) -> JsonValue {
    json!({
        "image": template.image,
        "runtime_class_name": template.runtime_class_name,
        "agent_socket": template.agent_socket,
        "labels": template.labels,
        "annotations": template.annotations,
        "environment": template.environment,
        "resources": template.resources.as_ref().map(struct_to_json),
        "volume_claim_templates": template.volume_claim_templates.as_ref().map(struct_to_json),
        "user_namespaces": template.user_namespaces,
        "driver_config": template.driver_config.as_ref().map(struct_to_json),
    })
}

fn sandbox_template_from_json(value: &JsonValue) -> Result<SandboxTemplate, Status> {
    let object = expect_object(value, "SandboxTemplate")?;
    Ok(SandboxTemplate {
        image: string_field(object, "image")?,
        runtime_class_name: string_field(object, "runtime_class_name")?,
        agent_socket: string_field(object, "agent_socket")?,
        labels: string_map_field(object, "labels")?,
        annotations: string_map_field(object, "annotations")?,
        environment: string_map_field(object, "environment")?,
        resources: optional_json_field(object, "resources")
            .map(json_to_struct_status)
            .transpose()?,
        volume_claim_templates: optional_json_field(object, "volume_claim_templates")
            .map(json_to_struct_status)
            .transpose()?,
        user_namespaces: optional_bool_field(object, "user_namespaces")?,
        driver_config: optional_json_field(object, "driver_config")
            .map(json_to_struct_status)
            .transpose()?,
    })
}

fn sandbox_status_to_json(status: &SandboxStatus) -> JsonValue {
    json!({
        "sandbox_name": status.sandbox_name,
        "agent_pod": status.agent_pod,
        "agent_fd": status.agent_fd,
        "sandbox_fd": status.sandbox_fd,
        "conditions": status.conditions.iter().map(sandbox_condition_to_json).collect::<Vec<_>>(),
        "phase": status.phase,
        "current_policy_version": status.current_policy_version,
    })
}

fn sandbox_status_from_json(value: &JsonValue) -> Result<SandboxStatus, Status> {
    let object = expect_object(value, "SandboxStatus")?;
    Ok(SandboxStatus {
        sandbox_name: string_field(object, "sandbox_name")?,
        agent_pod: string_field(object, "agent_pod")?,
        agent_fd: string_field(object, "agent_fd")?,
        sandbox_fd: string_field(object, "sandbox_fd")?,
        conditions: array_field(object, "conditions")?
            .iter()
            .map(sandbox_condition_from_json)
            .collect::<Result<_, _>>()?,
        phase: i32_field(object, "phase")?,
        current_policy_version: u32_field(object, "current_policy_version")?,
    })
}

fn sandbox_condition_to_json(condition: &SandboxCondition) -> JsonValue {
    json!({
        "type": condition.r#type,
        "status": condition.status,
        "reason": condition.reason,
        "message": condition.message,
        "last_transition_time": condition.last_transition_time,
    })
}

fn sandbox_condition_from_json(value: &JsonValue) -> Result<SandboxCondition, Status> {
    let object = expect_object(value, "SandboxCondition")?;
    Ok(SandboxCondition {
        r#type: string_field(object, "type")?,
        status: string_field(object, "status")?,
        reason: string_field(object, "reason")?,
        message: string_field(object, "message")?,
        last_transition_time: string_field(object, "last_transition_time")?,
    })
}

fn sandbox_policy_to_json(policy: &SandboxPolicy) -> JsonValue {
    json!({
        "version": policy.version,
        "filesystem": policy.filesystem.as_ref().map(filesystem_policy_to_json),
        "landlock": policy.landlock.as_ref().map(landlock_policy_to_json),
        "process": policy.process.as_ref().map(process_policy_to_json),
        "network_policies": policy.network_policies.iter().map(|(key, value)| (key.clone(), network_policy_rule_to_json(value))).collect::<JsonMap<_, _>>(),
    })
}

fn sandbox_policy_from_json(value: &JsonValue) -> Result<SandboxPolicy, Status> {
    let object = expect_object(value, "SandboxPolicy")?;
    Ok(SandboxPolicy {
        version: u32_field(object, "version")?,
        filesystem: optional_object_field(object, "filesystem")?
            .map(filesystem_policy_from_json)
            .transpose()?,
        landlock: optional_object_field(object, "landlock")?
            .map(landlock_policy_from_json)
            .transpose()?,
        process: optional_object_field(object, "process")?
            .map(process_policy_from_json)
            .transpose()?,
        network_policies: object
            .get("network_policies")
            .and_then(JsonValue::as_object)
            .map_or_else(
                || Ok(HashMap::new()),
                |policies| {
                    policies
                        .iter()
                        .map(|(key, value)| {
                            Ok((key.clone(), network_policy_rule_from_json(value)?))
                        })
                        .collect::<Result<HashMap<String, NetworkPolicyRule>, Status>>()
                },
            )?,
    })
}

fn filesystem_policy_to_json(policy: &FilesystemPolicy) -> JsonValue {
    json!({
        "include_workdir": policy.include_workdir,
        "read_only": policy.read_only,
        "read_write": policy.read_write,
    })
}

fn filesystem_policy_from_json(value: &JsonValue) -> Result<FilesystemPolicy, Status> {
    let object = expect_object(value, "FilesystemPolicy")?;
    Ok(FilesystemPolicy {
        include_workdir: bool_field(object, "include_workdir")?,
        read_only: string_array_field(object, "read_only")?,
        read_write: string_array_field(object, "read_write")?,
    })
}

fn landlock_policy_to_json(policy: &LandlockPolicy) -> JsonValue {
    json!({ "compatibility": policy.compatibility })
}

fn landlock_policy_from_json(value: &JsonValue) -> Result<LandlockPolicy, Status> {
    let object = expect_object(value, "LandlockPolicy")?;
    Ok(LandlockPolicy {
        compatibility: string_field(object, "compatibility")?,
    })
}

fn process_policy_to_json(policy: &ProcessPolicy) -> JsonValue {
    json!({
        "run_as_user": policy.run_as_user,
        "run_as_group": policy.run_as_group,
    })
}

fn process_policy_from_json(value: &JsonValue) -> Result<ProcessPolicy, Status> {
    let object = expect_object(value, "ProcessPolicy")?;
    Ok(ProcessPolicy {
        run_as_user: string_field(object, "run_as_user")?,
        run_as_group: string_field(object, "run_as_group")?,
    })
}

fn network_policy_rule_to_json(rule: &NetworkPolicyRule) -> JsonValue {
    json!({
        "name": rule.name,
        "endpoints": rule.endpoints.iter().map(network_endpoint_to_json).collect::<Vec<_>>(),
        "binaries": rule.binaries.iter().map(network_binary_to_json).collect::<Vec<_>>(),
    })
}

fn network_policy_rule_from_json(value: &JsonValue) -> Result<NetworkPolicyRule, Status> {
    let object = expect_object(value, "NetworkPolicyRule")?;
    Ok(NetworkPolicyRule {
        name: string_field(object, "name")?,
        endpoints: array_field(object, "endpoints")?
            .iter()
            .map(network_endpoint_from_json)
            .collect::<Result<_, _>>()?,
        binaries: array_field(object, "binaries")?
            .iter()
            .map(network_binary_from_json)
            .collect::<Result<_, _>>()?,
    })
}

fn network_endpoint_to_json(endpoint: &NetworkEndpoint) -> JsonValue {
    json!({
        "host": endpoint.host,
        "port": endpoint.port,
        "protocol": endpoint.protocol,
        "tls": endpoint.tls,
        "enforcement": endpoint.enforcement,
        "access": endpoint.access,
        "rules": endpoint.rules.iter().map(l7_rule_to_json).collect::<Vec<_>>(),
        "allowed_ips": endpoint.allowed_ips,
        "ports": endpoint.ports,
        "deny_rules": endpoint.deny_rules.iter().map(l7_deny_rule_to_json).collect::<Vec<_>>(),
        "allow_encoded_slash": endpoint.allow_encoded_slash,
        "persisted_queries": endpoint.persisted_queries,
        "graphql_persisted_queries": endpoint.graphql_persisted_queries.iter().map(|(key, value)| (key.clone(), graphql_operation_to_json(value))).collect::<JsonMap<_, _>>(),
        "graphql_max_body_bytes": endpoint.graphql_max_body_bytes,
        "path": endpoint.path,
        "websocket_credential_rewrite": endpoint.websocket_credential_rewrite,
        "request_body_credential_rewrite": endpoint.request_body_credential_rewrite,
        "advisor_proposed": endpoint.advisor_proposed,
    })
}

fn network_endpoint_from_json(value: &JsonValue) -> Result<NetworkEndpoint, Status> {
    let object = expect_object(value, "NetworkEndpoint")?;
    Ok(NetworkEndpoint {
        host: string_field(object, "host")?,
        port: u32_field(object, "port")?,
        protocol: string_field(object, "protocol")?,
        tls: string_field(object, "tls")?,
        enforcement: string_field(object, "enforcement")?,
        access: string_field(object, "access")?,
        rules: array_field(object, "rules")?
            .iter()
            .map(l7_rule_from_json)
            .collect::<Result<_, _>>()?,
        allowed_ips: string_array_field(object, "allowed_ips")?,
        ports: u32_array_field(object, "ports")?,
        deny_rules: array_field(object, "deny_rules")?
            .iter()
            .map(l7_deny_rule_from_json)
            .collect::<Result<_, _>>()?,
        allow_encoded_slash: bool_field(object, "allow_encoded_slash")?,
        persisted_queries: string_field(object, "persisted_queries")?,
        graphql_persisted_queries: object
            .get("graphql_persisted_queries")
            .and_then(JsonValue::as_object)
            .map_or_else(
                || Ok(HashMap::new()),
                |queries| {
                    queries
                        .iter()
                        .map(|(key, value)| Ok((key.clone(), graphql_operation_from_json(value)?)))
                        .collect::<Result<HashMap<String, GraphqlOperation>, Status>>()
                },
            )?,
        graphql_max_body_bytes: u32_field(object, "graphql_max_body_bytes")?,
        path: string_field(object, "path")?,
        websocket_credential_rewrite: bool_field(object, "websocket_credential_rewrite")?,
        request_body_credential_rewrite: bool_field(object, "request_body_credential_rewrite")?,
        advisor_proposed: bool_field(object, "advisor_proposed")?,
    })
}

#[allow(deprecated)]
fn network_binary_to_json(binary: &NetworkBinary) -> JsonValue {
    json!({ "path": binary.path, "harness": binary.harness })
}

#[allow(deprecated)]
fn network_binary_from_json(value: &JsonValue) -> Result<NetworkBinary, Status> {
    let object = expect_object(value, "NetworkBinary")?;
    Ok(NetworkBinary {
        path: string_field(object, "path")?,
        harness: bool_field(object, "harness")?,
    })
}

fn l7_rule_to_json(rule: &L7Rule) -> JsonValue {
    json!({ "allow": rule.allow.as_ref().map(l7_allow_to_json) })
}

fn l7_rule_from_json(value: &JsonValue) -> Result<L7Rule, Status> {
    let object = expect_object(value, "L7Rule")?;
    Ok(L7Rule {
        allow: optional_object_field(object, "allow")?
            .map(l7_allow_from_json)
            .transpose()?,
    })
}

fn l7_allow_to_json(allow: &L7Allow) -> JsonValue {
    json!({
        "method": allow.method,
        "path": allow.path,
        "command": allow.command,
        "query": allow.query.iter().map(|(key, value)| (key.clone(), l7_query_matcher_to_json(value))).collect::<JsonMap<_, _>>(),
        "operation_type": allow.operation_type,
        "operation_name": allow.operation_name,
        "fields": allow.fields,
    })
}

fn l7_allow_from_json(value: &JsonValue) -> Result<L7Allow, Status> {
    let object = expect_object(value, "L7Allow")?;
    Ok(L7Allow {
        method: string_field(object, "method")?,
        path: string_field(object, "path")?,
        command: string_field(object, "command")?,
        query: query_matcher_map_field(object, "query")?,
        operation_type: string_field(object, "operation_type")?,
        operation_name: string_field(object, "operation_name")?,
        fields: string_array_field(object, "fields")?,
    })
}

fn l7_deny_rule_to_json(rule: &L7DenyRule) -> JsonValue {
    json!({
        "method": rule.method,
        "path": rule.path,
        "command": rule.command,
        "query": rule.query.iter().map(|(key, value)| (key.clone(), l7_query_matcher_to_json(value))).collect::<JsonMap<_, _>>(),
        "operation_type": rule.operation_type,
        "operation_name": rule.operation_name,
        "fields": rule.fields,
    })
}

fn l7_deny_rule_from_json(value: &JsonValue) -> Result<L7DenyRule, Status> {
    let object = expect_object(value, "L7DenyRule")?;
    Ok(L7DenyRule {
        method: string_field(object, "method")?,
        path: string_field(object, "path")?,
        command: string_field(object, "command")?,
        query: query_matcher_map_field(object, "query")?,
        operation_type: string_field(object, "operation_type")?,
        operation_name: string_field(object, "operation_name")?,
        fields: string_array_field(object, "fields")?,
    })
}

fn l7_query_matcher_to_json(matcher: &L7QueryMatcher) -> JsonValue {
    json!({ "glob": matcher.glob, "any": matcher.any })
}

fn l7_query_matcher_from_json(value: &JsonValue) -> Result<L7QueryMatcher, Status> {
    let object = expect_object(value, "L7QueryMatcher")?;
    Ok(L7QueryMatcher {
        glob: string_field(object, "glob")?,
        any: string_array_field(object, "any")?,
    })
}

fn query_matcher_map_field(
    object: &JsonMap<String, JsonValue>,
    field: &str,
) -> Result<HashMap<String, L7QueryMatcher>, Status> {
    object
        .get(field)
        .and_then(JsonValue::as_object)
        .map_or_else(
            || Ok(HashMap::new()),
            |values| {
                values
                    .iter()
                    .map(|(key, value)| Ok((key.clone(), l7_query_matcher_from_json(value)?)))
                    .collect()
            },
        )
}

fn graphql_operation_to_json(operation: &GraphqlOperation) -> JsonValue {
    json!({
        "operation_type": operation.operation_type,
        "operation_name": operation.operation_name,
        "fields": operation.fields,
    })
}

fn graphql_operation_from_json(value: &JsonValue) -> Result<GraphqlOperation, Status> {
    let object = expect_object(value, "GraphqlOperation")?;
    Ok(GraphqlOperation {
        operation_type: string_field(object, "operation_type")?,
        operation_name: string_field(object, "operation_name")?,
        fields: string_array_field(object, "fields")?,
    })
}

fn provider_profile_import_item_to_json(item: &ProviderProfileImportItem) -> JsonValue {
    json!({
        "profile": item.profile.as_ref().map(provider_profile_to_json),
        "source": item.source,
    })
}

fn provider_profile_import_item_from_json(
    value: &JsonValue,
) -> Result<ProviderProfileImportItem, Status> {
    let object = expect_object(value, "ProviderProfileImportItem")?;
    Ok(ProviderProfileImportItem {
        profile: optional_object_field(object, "profile")?
            .map(provider_profile_from_json)
            .transpose()?,
        source: string_field(object, "source")?,
    })
}

fn provider_profile_to_json(profile: &ProviderProfile) -> JsonValue {
    json!({
        "id": profile.id,
        "display_name": profile.display_name,
        "description": profile.description,
        "category": profile.category,
        "credentials": profile.credentials.iter().map(provider_profile_credential_to_json).collect::<Vec<_>>(),
        "endpoints": profile.endpoints.iter().map(network_endpoint_to_json).collect::<Vec<_>>(),
        "binaries": profile.binaries.iter().map(network_binary_to_json).collect::<Vec<_>>(),
        "inference_capable": profile.inference_capable,
        "discovery": profile.discovery.as_ref().map(provider_profile_discovery_to_json),
    })
}

fn provider_profile_from_json(value: &JsonValue) -> Result<ProviderProfile, Status> {
    let object = expect_object(value, "ProviderProfile")?;
    Ok(ProviderProfile {
        id: string_field(object, "id")?,
        display_name: string_field(object, "display_name")?,
        description: string_field(object, "description")?,
        category: i32_field(object, "category")?,
        credentials: array_field(object, "credentials")?
            .iter()
            .map(provider_profile_credential_from_json)
            .collect::<Result<_, _>>()?,
        endpoints: array_field(object, "endpoints")?
            .iter()
            .map(network_endpoint_from_json)
            .collect::<Result<_, _>>()?,
        binaries: array_field(object, "binaries")?
            .iter()
            .map(network_binary_from_json)
            .collect::<Result<_, _>>()?,
        inference_capable: bool_field(object, "inference_capable")?,
        discovery: optional_object_field(object, "discovery")?
            .map(provider_profile_discovery_from_json)
            .transpose()?,
    })
}

fn provider_profile_credential_to_json(
    credential: &openshell_core::proto::ProviderProfileCredential,
) -> JsonValue {
    json!({
        "name": credential.name,
        "description": credential.description,
        "env_vars": credential.env_vars,
        "required": credential.required,
        "auth_style": credential.auth_style,
        "header_name": credential.header_name,
        "query_param": credential.query_param,
        "refresh": credential.refresh.as_ref().map(provider_credential_refresh_to_json),
        "path_template": credential.path_template,
        "token_grant": credential.token_grant.as_ref().map(provider_credential_token_grant_to_json),
    })
}

fn provider_profile_credential_from_json(
    value: &JsonValue,
) -> Result<openshell_core::proto::ProviderProfileCredential, Status> {
    let object = expect_object(value, "ProviderProfileCredential")?;
    Ok(openshell_core::proto::ProviderProfileCredential {
        name: string_field(object, "name")?,
        description: string_field(object, "description")?,
        env_vars: string_array_field(object, "env_vars")?,
        required: bool_field(object, "required")?,
        auth_style: string_field(object, "auth_style")?,
        header_name: string_field(object, "header_name")?,
        query_param: string_field(object, "query_param")?,
        refresh: optional_object_field(object, "refresh")?
            .map(provider_credential_refresh_from_json)
            .transpose()?,
        path_template: string_field(object, "path_template")?,
        token_grant: optional_object_field(object, "token_grant")?
            .map(provider_credential_token_grant_from_json)
            .transpose()?,
    })
}

fn provider_credential_refresh_to_json(refresh: &ProviderCredentialRefresh) -> JsonValue {
    json!({
        "strategy": refresh.strategy,
        "token_url": refresh.token_url,
        "scopes": refresh.scopes,
        "refresh_before_seconds": refresh.refresh_before_seconds,
        "max_lifetime_seconds": refresh.max_lifetime_seconds,
        "material": refresh.material.iter().map(provider_credential_refresh_material_to_json).collect::<Vec<_>>(),
    })
}

fn provider_credential_refresh_from_json(
    value: &JsonValue,
) -> Result<ProviderCredentialRefresh, Status> {
    let object = expect_object(value, "ProviderCredentialRefresh")?;
    Ok(ProviderCredentialRefresh {
        strategy: i32_field(object, "strategy")?,
        token_url: string_field(object, "token_url")?,
        scopes: string_array_field(object, "scopes")?,
        refresh_before_seconds: i64_field(object, "refresh_before_seconds")?,
        max_lifetime_seconds: i64_field(object, "max_lifetime_seconds")?,
        material: array_field(object, "material")?
            .iter()
            .map(provider_credential_refresh_material_from_json)
            .collect::<Result<_, _>>()?,
    })
}

fn provider_credential_refresh_material_to_json(
    material: &ProviderCredentialRefreshMaterial,
) -> JsonValue {
    json!({
        "name": material.name,
        "description": material.description,
        "required": material.required,
        "secret": material.secret,
    })
}

fn provider_credential_refresh_material_from_json(
    value: &JsonValue,
) -> Result<ProviderCredentialRefreshMaterial, Status> {
    let object = expect_object(value, "ProviderCredentialRefreshMaterial")?;
    Ok(ProviderCredentialRefreshMaterial {
        name: string_field(object, "name")?,
        description: string_field(object, "description")?,
        required: bool_field(object, "required")?,
        secret: bool_field(object, "secret")?,
    })
}

fn provider_credential_token_grant_to_json(grant: &ProviderCredentialTokenGrant) -> JsonValue {
    json!({
        "token_endpoint": grant.token_endpoint,
        "audience": grant.audience,
        "jwt_svid_audience": grant.jwt_svid_audience,
        "scopes": grant.scopes,
        "cache_ttl_seconds": grant.cache_ttl_seconds,
        "audience_overrides": grant.audience_overrides.iter().map(provider_credential_token_grant_override_to_json).collect::<Vec<_>>(),
        "client_assertion_type": grant.client_assertion_type,
    })
}

fn provider_credential_token_grant_from_json(
    value: &JsonValue,
) -> Result<ProviderCredentialTokenGrant, Status> {
    let object = expect_object(value, "ProviderCredentialTokenGrant")?;
    Ok(ProviderCredentialTokenGrant {
        token_endpoint: string_field(object, "token_endpoint")?,
        audience: string_field(object, "audience")?,
        jwt_svid_audience: string_field(object, "jwt_svid_audience")?,
        scopes: string_array_field(object, "scopes")?,
        cache_ttl_seconds: i64_field(object, "cache_ttl_seconds")?,
        audience_overrides: array_field(object, "audience_overrides")?
            .iter()
            .map(provider_credential_token_grant_override_from_json)
            .collect::<Result<_, _>>()?,
        client_assertion_type: string_field(object, "client_assertion_type")?,
    })
}

fn provider_credential_token_grant_override_to_json(
    override_config: &ProviderCredentialTokenGrantAudienceOverride,
) -> JsonValue {
    json!({
        "host": override_config.host,
        "port": override_config.port,
        "path": override_config.path,
        "audience": override_config.audience,
        "scopes": override_config.scopes,
    })
}

fn provider_credential_token_grant_override_from_json(
    value: &JsonValue,
) -> Result<ProviderCredentialTokenGrantAudienceOverride, Status> {
    let object = expect_object(value, "ProviderCredentialTokenGrantAudienceOverride")?;
    Ok(ProviderCredentialTokenGrantAudienceOverride {
        host: string_field(object, "host")?,
        port: u32_field(object, "port")?,
        path: string_field(object, "path")?,
        audience: string_field(object, "audience")?,
        scopes: string_array_field(object, "scopes")?,
    })
}

fn provider_profile_discovery_to_json(discovery: &ProviderProfileDiscovery) -> JsonValue {
    json!({ "credentials": discovery.credentials })
}

fn provider_profile_discovery_from_json(
    value: &JsonValue,
) -> Result<ProviderProfileDiscovery, Status> {
    let object = expect_object(value, "ProviderProfileDiscovery")?;
    Ok(ProviderProfileDiscovery {
        credentials: string_array_field(object, "credentials")?,
    })
}

fn setting_value_to_json(value: &SettingValue) -> JsonValue {
    match value.value.as_ref() {
        Some(setting_value::Value::StringValue(value)) => {
            json!({ "string_value": value })
        }
        Some(setting_value::Value::BoolValue(value)) => {
            json!({ "bool_value": value })
        }
        Some(setting_value::Value::IntValue(value)) => {
            json!({ "int_value": value })
        }
        Some(setting_value::Value::BytesValue(value)) => {
            json!({ "bytes_value": base64::engine::general_purpose::STANDARD.encode(value) })
        }
        None => JsonValue::Object(JsonMap::new()),
    }
}

fn setting_value_from_json(value: &JsonValue) -> Result<SettingValue, Status> {
    let object = expect_object(value, "SettingValue")?;
    let value = if let Some(value) = object.get("string_value") {
        Some(setting_value::Value::StringValue(
            value.as_str().unwrap_or_default().to_string(),
        ))
    } else if let Some(value) = object.get("bool_value") {
        Some(setting_value::Value::BoolValue(
            value.as_bool().unwrap_or_default(),
        ))
    } else if let Some(value) = object.get("int_value") {
        Some(setting_value::Value::IntValue(json_i64(
            value,
            "int_value",
        )?))
    } else if let Some(value) = object.get("bytes_value") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value.as_str().unwrap_or_default())
            .map_err(|err| Status::invalid_argument(format!("invalid bytes_value: {err}")))?;
        Some(setting_value::Value::BytesValue(bytes))
    } else {
        None
    };
    Ok(SettingValue { value })
}

fn policy_merge_operation_to_json(operation: &PolicyMergeOperation) -> JsonValue {
    match operation.operation.as_ref() {
        Some(policy_merge_operation::Operation::AddRule(value)) => {
            json!({ "add_rule": add_network_rule_to_json(value) })
        }
        Some(policy_merge_operation::Operation::RemoveEndpoint(value)) => {
            json!({ "remove_endpoint": remove_network_endpoint_to_json(value) })
        }
        Some(policy_merge_operation::Operation::RemoveRule(value)) => {
            json!({ "remove_rule": remove_network_rule_to_json(value) })
        }
        Some(policy_merge_operation::Operation::AddDenyRules(value)) => {
            json!({ "add_deny_rules": add_deny_rules_to_json(value) })
        }
        Some(policy_merge_operation::Operation::AddAllowRules(value)) => {
            json!({ "add_allow_rules": add_allow_rules_to_json(value) })
        }
        Some(policy_merge_operation::Operation::RemoveBinary(value)) => {
            json!({ "remove_binary": remove_network_binary_to_json(value) })
        }
        None => JsonValue::Object(JsonMap::new()),
    }
}

fn policy_merge_operation_from_json(value: &JsonValue) -> Result<PolicyMergeOperation, Status> {
    let object = expect_object(value, "PolicyMergeOperation")?;
    let operation = if let Some(value) = object.get("add_rule") {
        Some(policy_merge_operation::Operation::AddRule(
            add_network_rule_from_json(value)?,
        ))
    } else if let Some(value) = object.get("remove_endpoint") {
        Some(policy_merge_operation::Operation::RemoveEndpoint(
            remove_network_endpoint_from_json(value)?,
        ))
    } else if let Some(value) = object.get("remove_rule") {
        Some(policy_merge_operation::Operation::RemoveRule(
            remove_network_rule_from_json(value)?,
        ))
    } else if let Some(value) = object.get("add_deny_rules") {
        Some(policy_merge_operation::Operation::AddDenyRules(
            add_deny_rules_from_json(value)?,
        ))
    } else if let Some(value) = object.get("add_allow_rules") {
        Some(policy_merge_operation::Operation::AddAllowRules(
            add_allow_rules_from_json(value)?,
        ))
    } else if let Some(value) = object.get("remove_binary") {
        Some(policy_merge_operation::Operation::RemoveBinary(
            remove_network_binary_from_json(value)?,
        ))
    } else {
        None
    };
    Ok(PolicyMergeOperation { operation })
}

fn add_network_rule_to_json(value: &AddNetworkRule) -> JsonValue {
    json!({ "rule_name": value.rule_name, "rule": value.rule.as_ref().map(network_policy_rule_to_json) })
}

fn add_network_rule_from_json(value: &JsonValue) -> Result<AddNetworkRule, Status> {
    let object = expect_object(value, "AddNetworkRule")?;
    Ok(AddNetworkRule {
        rule_name: string_field(object, "rule_name")?,
        rule: optional_object_field(object, "rule")?
            .map(network_policy_rule_from_json)
            .transpose()?,
    })
}

fn remove_network_endpoint_to_json(value: &RemoveNetworkEndpoint) -> JsonValue {
    json!({ "rule_name": value.rule_name, "host": value.host, "port": value.port })
}

fn remove_network_endpoint_from_json(value: &JsonValue) -> Result<RemoveNetworkEndpoint, Status> {
    let object = expect_object(value, "RemoveNetworkEndpoint")?;
    Ok(RemoveNetworkEndpoint {
        rule_name: string_field(object, "rule_name")?,
        host: string_field(object, "host")?,
        port: u32_field(object, "port")?,
    })
}

fn remove_network_rule_to_json(value: &RemoveNetworkRule) -> JsonValue {
    json!({ "rule_name": value.rule_name })
}

fn remove_network_rule_from_json(value: &JsonValue) -> Result<RemoveNetworkRule, Status> {
    let object = expect_object(value, "RemoveNetworkRule")?;
    Ok(RemoveNetworkRule {
        rule_name: string_field(object, "rule_name")?,
    })
}

fn add_deny_rules_to_json(value: &AddDenyRules) -> JsonValue {
    json!({
        "host": value.host,
        "port": value.port,
        "deny_rules": value.deny_rules.iter().map(l7_deny_rule_to_json).collect::<Vec<_>>(),
    })
}

fn add_deny_rules_from_json(value: &JsonValue) -> Result<AddDenyRules, Status> {
    let object = expect_object(value, "AddDenyRules")?;
    Ok(AddDenyRules {
        host: string_field(object, "host")?,
        port: u32_field(object, "port")?,
        deny_rules: array_field(object, "deny_rules")?
            .iter()
            .map(l7_deny_rule_from_json)
            .collect::<Result<_, _>>()?,
    })
}

fn add_allow_rules_to_json(value: &AddAllowRules) -> JsonValue {
    json!({
        "host": value.host,
        "port": value.port,
        "rules": value.rules.iter().map(l7_rule_to_json).collect::<Vec<_>>(),
    })
}

fn add_allow_rules_from_json(value: &JsonValue) -> Result<AddAllowRules, Status> {
    let object = expect_object(value, "AddAllowRules")?;
    Ok(AddAllowRules {
        host: string_field(object, "host")?,
        port: u32_field(object, "port")?,
        rules: array_field(object, "rules")?
            .iter()
            .map(l7_rule_from_json)
            .collect::<Result<_, _>>()?,
    })
}

fn remove_network_binary_to_json(value: &RemoveNetworkBinary) -> JsonValue {
    json!({ "rule_name": value.rule_name, "binary_path": value.binary_path })
}

fn remove_network_binary_from_json(value: &JsonValue) -> Result<RemoveNetworkBinary, Status> {
    let object = expect_object(value, "RemoveNetworkBinary")?;
    Ok(RemoveNetworkBinary {
        rule_name: string_field(object, "rule_name")?,
        binary_path: string_field(object, "binary_path")?,
    })
}

fn driver_sandbox_spec_to_json(spec: &DriverSandboxSpec) -> JsonValue {
    json!({
        "log_level": spec.log_level,
        "environment": spec.environment,
        "template": spec.template.as_ref().map(driver_sandbox_template_to_json),
        "gpu": spec.gpu,
        "sandbox_token": if spec.sandbox_token.is_empty() { "" } else { "REDACTED" },
    })
}

fn driver_sandbox_template_to_json(template: &DriverSandboxTemplate) -> JsonValue {
    json!({
        "image": template.image,
        "agent_socket_path": template.agent_socket_path,
        "labels": template.labels,
        "environment": template.environment,
        "resources": template.resources.as_ref().map(driver_resource_requirements_to_json),
        "platform_config": template.platform_config.as_ref().map(struct_to_json),
        "driver_config": template.driver_config.as_ref().map(struct_to_json),
    })
}

fn driver_resource_requirements_to_json(resources: &DriverResourceRequirements) -> JsonValue {
    json!({
        "cpu_request": resources.cpu_request,
        "cpu_limit": resources.cpu_limit,
        "memory_request": resources.memory_request,
        "memory_limit": resources.memory_limit,
    })
}

fn driver_sandbox_status_to_json(status: &DriverSandboxStatus) -> JsonValue {
    json!({
        "sandbox_name": status.sandbox_name,
        "instance_id": status.instance_id,
        "agent_fd": status.agent_fd,
        "sandbox_fd": status.sandbox_fd,
        "conditions": status.conditions.iter().map(|condition| json!({
            "type": condition.r#type,
            "status": condition.status,
            "reason": condition.reason,
            "message": condition.message,
            "last_transition_time": condition.last_transition_time,
        })).collect::<Vec<_>>(),
        "deleting": status.deleting,
    })
}

fn expect_object<'a>(
    value: &'a JsonValue,
    type_name: &str,
) -> Result<&'a JsonMap<String, JsonValue>, Status> {
    value
        .as_object()
        .ok_or_else(|| Status::invalid_argument(format!("{type_name} must be a JSON object")))
}

fn optional_object_field<'a>(
    object: &'a JsonMap<String, JsonValue>,
    field: &str,
) -> Result<Option<&'a JsonValue>, Status> {
    match object.get(field) {
        Some(JsonValue::Null) | None => Ok(None),
        Some(value) if value.is_object() => Ok(Some(value)),
        Some(_) => Err(Status::invalid_argument(format!(
            "{field} must be an object"
        ))),
    }
}

fn optional_json_field<'a>(
    object: &'a JsonMap<String, JsonValue>,
    field: &str,
) -> Option<&'a JsonValue> {
    match object.get(field) {
        Some(JsonValue::Null) | None => None,
        Some(value) => Some(value),
    }
}

fn string_field(object: &JsonMap<String, JsonValue>, field: &str) -> Result<String, Status> {
    Ok(object
        .get(field)
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .to_string())
}

fn bool_field(object: &JsonMap<String, JsonValue>, field: &str) -> Result<bool, Status> {
    Ok(object
        .get(field)
        .and_then(JsonValue::as_bool)
        .unwrap_or_default())
}

fn optional_bool_field(
    object: &JsonMap<String, JsonValue>,
    field: &str,
) -> Result<Option<bool>, Status> {
    Ok(match object.get(field) {
        Some(JsonValue::Null) | None => None,
        Some(value) => Some(value.as_bool().ok_or_else(|| {
            Status::invalid_argument(format!("{field} must be a boolean or null"))
        })?),
    })
}

fn i32_field(object: &JsonMap<String, JsonValue>, field: &str) -> Result<i32, Status> {
    let value = i64_field(object, field)?;
    i32::try_from(value).map_err(|_| Status::invalid_argument(format!("{field} is out of range")))
}

fn u32_field(object: &JsonMap<String, JsonValue>, field: &str) -> Result<u32, Status> {
    let value = u64_field(object, field)?;
    u32::try_from(value).map_err(|_| Status::invalid_argument(format!("{field} is out of range")))
}

fn u64_field(object: &JsonMap<String, JsonValue>, field: &str) -> Result<u64, Status> {
    object
        .get(field)
        .map_or(Ok(0), |value| json_u64(value, field))
}

fn i64_field(object: &JsonMap<String, JsonValue>, field: &str) -> Result<i64, Status> {
    object
        .get(field)
        .map_or(Ok(0), |value| json_i64(value, field))
}

fn json_u64(value: &JsonValue, field: &str) -> Result<u64, Status> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
        .or_else(|| {
            value
                .as_f64()
                .and_then(|value| exact_unsigned_integer_float(value))
        })
        .ok_or_else(|| Status::invalid_argument(format!("{field} must be an unsigned integer")))
}

fn json_i64(value: &JsonValue, field: &str) -> Result<i64, Status> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| {
            value
                .as_f64()
                .and_then(|value| exact_signed_integer_float(value))
        })
        .ok_or_else(|| Status::invalid_argument(format!("{field} must be an integer")))
}

fn exact_unsigned_integer_float(value: f64) -> Option<u64> {
    const MAX_EXACT_INTEGER: f64 = 9_007_199_254_740_991.0;
    if value.is_finite() && value >= 0.0 && value <= MAX_EXACT_INTEGER && value.fract() == 0.0 {
        Some(value as u64)
    } else {
        None
    }
}

fn exact_signed_integer_float(value: f64) -> Option<i64> {
    const MIN_EXACT_INTEGER: f64 = -9_007_199_254_740_991.0;
    const MAX_EXACT_INTEGER: f64 = 9_007_199_254_740_991.0;
    if value.is_finite()
        && (MIN_EXACT_INTEGER..=MAX_EXACT_INTEGER).contains(&value)
        && value.fract() == 0.0
    {
        Some(value as i64)
    } else {
        None
    }
}

fn array_field<'a>(
    object: &'a JsonMap<String, JsonValue>,
    field: &str,
) -> Result<&'a Vec<JsonValue>, Status> {
    match object.get(field) {
        Some(JsonValue::Array(values)) => Ok(values),
        Some(JsonValue::Null) | None => Ok(empty_array()),
        Some(_) => Err(Status::invalid_argument(format!(
            "{field} must be an array"
        ))),
    }
}

fn empty_array() -> &'static Vec<JsonValue> {
    static EMPTY: std::sync::OnceLock<Vec<JsonValue>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(Vec::new)
}

fn string_array_field(
    object: &JsonMap<String, JsonValue>,
    field: &str,
) -> Result<Vec<String>, Status> {
    array_field(object, field)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or_else(|| Status::invalid_argument(format!("{field} entries must be strings")))
        })
        .collect()
}

fn u32_array_field(object: &JsonMap<String, JsonValue>, field: &str) -> Result<Vec<u32>, Status> {
    array_field(object, field)?
        .iter()
        .map(|value| {
            let value = json_u64(value, field)?;
            u32::try_from(value)
                .map_err(|_| Status::invalid_argument(format!("{field} entry is out of range")))
        })
        .collect()
}

fn string_map_field(
    object: &JsonMap<String, JsonValue>,
    field: &str,
) -> Result<HashMap<String, String>, Status> {
    Ok(object
        .get(field)
        .and_then(JsonValue::as_object)
        .map_or_else(HashMap::new, json_string_map))
}

fn json_string_map(object: &JsonMap<String, JsonValue>) -> HashMap<String, String> {
    object
        .iter()
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
        .collect()
}

fn i64_map_field(
    object: &JsonMap<String, JsonValue>,
    field: &str,
) -> Result<HashMap<String, i64>, Status> {
    object
        .get(field)
        .and_then(JsonValue::as_object)
        .map_or_else(
            || Ok(HashMap::new()),
            |values| {
                values
                    .iter()
                    .map(|(key, value)| Ok((key.clone(), json_i64(value, field)?)))
                    .collect()
            },
        )
}

fn json_to_struct_status(value: &JsonValue) -> Result<prost_types::Struct, Status> {
    json_to_struct(value)
        .map_err(|err| Status::invalid_argument(format!("invalid protobuf Struct JSON: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_policy_from_json_accepts_protobuf_struct_integer_floats() {
        let policy = sandbox_policy_from_json(&json!({
            "version": 1.0,
            "network_policies": {},
        }))
        .expect("policy adapter should accept exact integer-valued floats");

        assert_eq!(policy.version, 1);
    }

    #[test]
    fn json_integer_fields_reject_fractional_floats() {
        let err = json_u64(&json!(1.5), "version").expect_err("fractional value must fail");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("unsigned integer"));
    }
}
