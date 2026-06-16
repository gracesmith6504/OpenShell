// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example gateway interceptor enforcing a fixed source-control governance baseline.

#![allow(clippy::result_large_err)]

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use openshell_core::proto::interceptor::v1::gateway_interceptor_server::GatewayInterceptor;
use openshell_core::proto::interceptor::v1::{
    InterceptorBinding, InterceptorDecision, InterceptorDescribeRequest, InterceptorManifest,
    InterceptorReview, InterceptorSelector, JsonPatch,
};
use openshell_core::proto::{
    GraphqlOperation, L7DenyRule, L7QueryMatcher, L7Rule, NetworkEndpoint, NetworkPolicyRule,
    SandboxPolicy,
};
use openshell_interceptors::{
    API_VERSION, PHASE_MODIFY_OBJECT, PHASE_VALIDATE_OBJECT, json_to_proto_value, json_to_struct,
    struct_to_json,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

const POLICY_YAML: &str = include_str!("../policy.yaml");
const PROVIDER_GITHUB: &str = "github";
const PROVIDER_GITLAB: &str = "gitlab";
const PROVIDERS: [&str; 2] = [PROVIDER_GITHUB, PROVIDER_GITLAB];
const LABEL_SIGNATURE: &str = "governance.nvidia.com/signature";
const SIGNATURE_VERSION: &str = "1";
const SIGNATURE_VALID_FROM: &str = "2026-01-01";
const SIGNATURE_EXPIRES_AT: &str = "9999-12-31";
const SIGNATURE_ISSUER: &str = "policy-governance";
const SIGNATURE_SUBJECT: &str = "source-control-sandbox-policy";
const SIGNATURE_NBF: u64 = 1_767_225_600;
const SIGNATURE_EXP: u64 = 253_402_300_799;
const ARTIFACT_FRESHNESS_WINDOW_SECS: u64 = 3600;
const REVOKED_POLICY_DIGESTS: &[&str] = &[];
const POLICY_SIGNATURE_SECRET: &[u8] =
    b"policy-governance-interceptor-example-signing-key-not-for-production";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PolicySignatureClaims {
    iss: String,
    sub: String,
    nbf: u64,
    exp: u64,
    version: String,
    valid_from: String,
    expires_at: String,
    issuer: String,
    policy_digest: String,
}

#[derive(Debug, Clone)]
struct RetrievedPolicyArtifact {
    policy_yaml: &'static str,
    version: String,
    issuer: String,
    valid_from: String,
    expires_at: String,
    policy_digest: String,
    signature: String,
    retrieved_at_unix_secs: u64,
    freshness_window_secs: u64,
}

#[derive(Debug, Clone)]
struct VerifiedPolicyArtifact {
    policy: JsonValue,
    providers: JsonValue,
    policy_digest: String,
    version: String,
    issuer: String,
    signature: String,
    policy_signature_label: String,
    cache_valid_until_unix_secs: u64,
}

#[derive(Debug, Clone)]
pub struct GovernanceInterceptor {
    verified_policy: VerifiedPolicyArtifact,
    revoked_policy_digests: HashSet<String>,
}

impl GovernanceInterceptor {
    pub fn new() -> Result<Self, String> {
        let retrieved_at_unix_secs = current_unix_secs()?;
        let artifact = retrieve_policy_artifact(retrieved_at_unix_secs)?;
        let verified_policy = verify_policy_artifact(artifact)?;
        Ok(Self {
            verified_policy,
            revoked_policy_digests: REVOKED_POLICY_DIGESTS
                .iter()
                .map(|digest| (*digest).to_string())
                .collect(),
        })
    }

    pub fn manifest() -> InterceptorManifest {
        InterceptorManifest {
            api_version: API_VERSION.to_string(),
            bindings: vec![
                binding(
                    "sandbox-create-defaults",
                    PHASE_MODIFY_OBJECT,
                    "sandbox",
                    "create",
                    true,
                ),
                binding(
                    "sandbox-create-validate",
                    PHASE_VALIDATE_OBJECT,
                    "sandbox",
                    "create",
                    false,
                ),
                binding(
                    "sandbox-provider-attach",
                    PHASE_VALIDATE_OBJECT,
                    "sandbox",
                    "attach_provider",
                    false,
                ),
                binding(
                    "sandbox-provider-detach",
                    PHASE_VALIDATE_OBJECT,
                    "sandbox",
                    "detach_provider",
                    false,
                ),
                binding(
                    "provider-record-create",
                    PHASE_VALIDATE_OBJECT,
                    "provider",
                    "create",
                    false,
                ),
                binding(
                    "provider-record-update",
                    PHASE_VALIDATE_OBJECT,
                    "provider",
                    "update",
                    false,
                ),
                binding(
                    "provider-record-delete",
                    PHASE_VALIDATE_OBJECT,
                    "provider",
                    "delete",
                    false,
                ),
                binding(
                    "provider-profile-import-lockdown",
                    PHASE_VALIDATE_OBJECT,
                    "provider_profile",
                    "import",
                    false,
                ),
                binding(
                    "provider-profile-delete-lockdown",
                    PHASE_VALIDATE_OBJECT,
                    "provider_profile",
                    "delete",
                    false,
                ),
                binding(
                    "policy-config-update-lockdown",
                    PHASE_VALIDATE_OBJECT,
                    "config",
                    "update",
                    false,
                ),
                binding(
                    "policy-config-merge-lockdown",
                    PHASE_VALIDATE_OBJECT,
                    "config",
                    "merge",
                    false,
                ),
                binding(
                    "policy-config-delete-lockdown",
                    PHASE_VALIDATE_OBJECT,
                    "config",
                    "delete",
                    false,
                ),
            ],
        }
    }

    pub fn review_decision(&self, review: InterceptorReview) -> InterceptorDecision {
        match (
            review.phase.as_str(),
            review.resource.as_str(),
            review.operation.as_str(),
        ) {
            (PHASE_MODIFY_OBJECT, "sandbox", "create") => match self.require_usable_policy() {
                Ok(policy) => self.review_sandbox_create_modify(&review, policy),
                Err(err) => deny(&format!("policy artifact unavailable: {err}")),
            },
            (PHASE_VALIDATE_OBJECT, "sandbox", "create") => match self.require_usable_policy() {
                Ok(policy) => self.review_sandbox_create_validate(&review, policy),
                Err(err) => deny(&format!("policy artifact unavailable: {err}")),
            },
            (PHASE_VALIDATE_OBJECT, "sandbox", "attach_provider" | "detach_provider") => {
                match self.require_usable_policy() {
                    Ok(_) => deny(
                        "sandbox provider attachments are managed by the governance interceptor",
                    ),
                    Err(err) => deny(&format!("policy artifact unavailable: {err}")),
                }
            }
            (PHASE_VALIDATE_OBJECT, "provider", "create") => match self.require_usable_policy() {
                Ok(_) => review_provider_create(&review),
                Err(err) => deny(&format!("policy artifact unavailable: {err}")),
            },
            (PHASE_VALIDATE_OBJECT, "provider", "update") => match self.require_usable_policy() {
                Ok(_) => deny("governed provider records cannot be modified"),
                Err(err) => deny(&format!("policy artifact unavailable: {err}")),
            },
            (PHASE_VALIDATE_OBJECT, "provider", "delete") => match self.require_usable_policy() {
                Ok(_) => deny("governed provider records cannot be deleted"),
                Err(err) => deny(&format!("policy artifact unavailable: {err}")),
            },
            (PHASE_VALIDATE_OBJECT, "provider_profile", _) => match self.require_usable_policy() {
                Ok(_) => deny("provider profiles are fixed by this governance example"),
                Err(err) => deny(&format!("policy artifact unavailable: {err}")),
            },
            (PHASE_VALIDATE_OBJECT, "config", _) => match self.require_usable_policy() {
                Ok(_) => review_config_update(&review),
                Err(err) => deny(&format!("policy artifact unavailable: {err}")),
            },
            _ => allow(),
        }
    }

    fn review_sandbox_create_modify(
        &self,
        review: &InterceptorReview,
        policy: &VerifiedPolicyArtifact,
    ) -> InterceptorDecision {
        let Some(object) = review.object.as_ref().map(struct_to_json) else {
            return deny("sandbox create review missing object");
        };
        let Some(spec) = object.get("spec").and_then(JsonValue::as_object) else {
            return deny("sandbox create review missing spec");
        };

        if !providers_are_subset(spec.get("providers")) {
            return deny("sandbox create requested providers outside the governed set");
        }
        if let Some(requested_policy) = spec.get("policy")
            && !requested_policy.is_null()
            && requested_policy != &policy.policy
        {
            return deny("sandbox create requested a non-governed policy");
        }

        let mut patches = Vec::new();
        if spec.get("policy").is_none_or(JsonValue::is_null) {
            patches.push(add("/spec/policy", policy.policy.clone()));
        }
        if !providers_are_exact(spec.get("providers")) {
            patches.push(add("/spec/providers", policy.providers.clone()));
        }
        if let Some(decision) =
            add_signature_label_patch(&object, &mut patches, &policy.policy_signature_label)
        {
            return decision;
        }

        allow_with_patches(patches)
    }

    fn review_sandbox_create_validate(
        &self,
        review: &InterceptorReview,
        policy: &VerifiedPolicyArtifact,
    ) -> InterceptorDecision {
        let Some(object) = review.object.as_ref().map(struct_to_json) else {
            return deny("sandbox create validation missing object");
        };
        let Some(spec) = object.get("spec").and_then(JsonValue::as_object) else {
            return deny("sandbox create validation missing spec");
        };

        if !providers_are_exact(spec.get("providers")) {
            return deny("sandbox must use exactly the governed providers: github, gitlab");
        }
        if spec.get("policy") != Some(&policy.policy) {
            return deny("sandbox must use the governed policy");
        }
        if !signature_label_matches(&object, &policy.policy_signature_label) {
            return deny("sandbox must carry the governed policy signature");
        }

        allow()
    }

    fn require_usable_policy(&self) -> Result<&VerifiedPolicyArtifact, String> {
        let now = current_unix_secs()?;
        self.require_usable_policy_at(now)
    }

    fn require_usable_policy_at(
        &self,
        now_unix_secs: u64,
    ) -> Result<&VerifiedPolicyArtifact, String> {
        let claims = verify_policy_signature(&self.verified_policy.signature)
            .map_err(|err| format!("policy signature validation failed: {err}"))?;
        if claims.version != self.verified_policy.version {
            return Err("signed policy version does not match cached artifact".to_string());
        }
        if claims.issuer != self.verified_policy.issuer {
            return Err("signed policy issuer does not match cached artifact".to_string());
        }
        if claims.policy_digest != self.verified_policy.policy_digest {
            return Err("signed policy digest does not match cached artifact".to_string());
        }
        if now_unix_secs > self.verified_policy.cache_valid_until_unix_secs {
            return Err("cached policy artifact is stale".to_string());
        }
        if self
            .revoked_policy_digests
            .contains(&self.verified_policy.policy_digest)
        {
            return Err("cached policy artifact is revoked".to_string());
        }

        Ok(&self.verified_policy)
    }
}

#[tonic::async_trait]
impl GatewayInterceptor for GovernanceInterceptor {
    async fn describe(
        &self,
        _request: Request<InterceptorDescribeRequest>,
    ) -> Result<Response<InterceptorManifest>, Status> {
        Ok(Response::new(Self::manifest()))
    }

    async fn review(
        &self,
        request: Request<InterceptorReview>,
    ) -> Result<Response<InterceptorDecision>, Status> {
        Ok(Response::new(self.review_decision(request.into_inner())))
    }
}

fn binding(
    id: &str,
    phase: &str,
    resource: &str,
    operation: &str,
    modifies: bool,
) -> InterceptorBinding {
    InterceptorBinding {
        id: id.to_string(),
        phases: vec![phase.to_string()],
        resources: vec![resource.to_string()],
        operations: vec![operation.to_string()],
        order: 0,
        modifies,
        default_failure_policy: "fail_closed".to_string(),
        selector: Some(InterceptorSelector::default()),
    }
}

fn review_provider_create(review: &InterceptorReview) -> InterceptorDecision {
    let Some(object) = review.object.as_ref().map(struct_to_json) else {
        return deny("provider review missing object");
    };
    let name = object
        .pointer("/metadata/name")
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    let provider_type = object
        .get("type")
        .and_then(JsonValue::as_str)
        .unwrap_or_default();

    if (name == PROVIDER_GITHUB && provider_type == PROVIDER_GITHUB)
        || (name == PROVIDER_GITLAB && provider_type == PROVIDER_GITLAB)
    {
        allow()
    } else {
        deny("only github and gitlab provider records are allowed")
    }
}

fn review_config_update(review: &InterceptorReview) -> InterceptorDecision {
    let Some(object) = review.object.as_ref().map(struct_to_json) else {
        return deny("config review missing object");
    };

    let policy_present = object.get("policy").is_some_and(|value| !value.is_null());
    let merge_present = object
        .get("merge_operations")
        .and_then(JsonValue::as_array)
        .is_some_and(|operations| !operations.is_empty());
    let setting_key = object
        .get("setting_key")
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .trim();

    if policy_present || merge_present || setting_key == "policy" {
        deny("sandbox policy updates are blocked by the governance interceptor")
    } else {
        allow()
    }
}

fn allow() -> InterceptorDecision {
    InterceptorDecision {
        allowed: true,
        ..Default::default()
    }
}

fn allow_with_patches(patches: Vec<JsonPatch>) -> InterceptorDecision {
    InterceptorDecision {
        allowed: true,
        patches,
        ..Default::default()
    }
}

fn deny(reason: &str) -> InterceptorDecision {
    InterceptorDecision {
        allowed: false,
        reason: reason.to_string(),
        status_code: "permission_denied".to_string(),
        ..Default::default()
    }
}

fn add(path: &str, value: JsonValue) -> JsonPatch {
    JsonPatch {
        op: "add".to_string(),
        path: path.to_string(),
        from: String::new(),
        value: Some(json_to_proto_value(&value).expect("canonical policy JSON is valid protobuf")),
    }
}

fn providers_are_subset(value: Option<&JsonValue>) -> bool {
    let Some(providers) = value.and_then(JsonValue::as_array) else {
        return true;
    };
    providers.iter().all(|provider| {
        provider
            .as_str()
            .is_some_and(|name| PROVIDERS.contains(&name))
    })
}

fn providers_are_exact(value: Option<&JsonValue>) -> bool {
    let Some(providers) = value.and_then(JsonValue::as_array) else {
        return false;
    };
    if providers.len() != PROVIDERS.len() {
        return false;
    }
    let actual = providers
        .iter()
        .filter_map(JsonValue::as_str)
        .collect::<HashSet<_>>();
    actual == PROVIDERS.into_iter().collect::<HashSet<_>>()
}

fn governed_providers_json() -> JsonValue {
    JsonValue::Array(
        PROVIDERS
            .into_iter()
            .map(|provider| JsonValue::String(provider.to_string()))
            .collect(),
    )
}

fn retrieve_policy_artifact(
    retrieved_at_unix_secs: u64,
) -> Result<RetrievedPolicyArtifact, String> {
    let policy_digest = short_policy_digest(POLICY_YAML.as_bytes());
    let claims = policy_signature_claims(policy_digest.clone());
    let signature = sign_policy_signature(&claims)?;
    Ok(RetrievedPolicyArtifact {
        policy_yaml: POLICY_YAML,
        version: SIGNATURE_VERSION.to_string(),
        issuer: SIGNATURE_ISSUER.to_string(),
        valid_from: SIGNATURE_VALID_FROM.to_string(),
        expires_at: SIGNATURE_EXPIRES_AT.to_string(),
        policy_digest,
        signature,
        retrieved_at_unix_secs,
        freshness_window_secs: ARTIFACT_FRESHNESS_WINDOW_SECS,
    })
}

fn verify_policy_artifact(
    artifact: RetrievedPolicyArtifact,
) -> Result<VerifiedPolicyArtifact, String> {
    let expected_digest = short_policy_digest(artifact.policy_yaml.as_bytes());
    if artifact.policy_digest != expected_digest {
        return Err("retrieved policy digest does not match policy payload".to_string());
    }

    let claims = verify_policy_signature(&artifact.signature)?;
    if claims.version != artifact.version {
        return Err("signed policy version does not match retrieved artifact".to_string());
    }
    if claims.issuer != artifact.issuer {
        return Err("signed policy issuer does not match retrieved artifact".to_string());
    }
    if claims.valid_from != artifact.valid_from {
        return Err("signed policy valid_from does not match retrieved artifact".to_string());
    }
    if claims.expires_at != artifact.expires_at {
        return Err("signed policy expires_at does not match retrieved artifact".to_string());
    }
    if claims.policy_digest != artifact.policy_digest {
        return Err("signed policy digest does not match retrieved artifact".to_string());
    }

    let policy = openshell_policy::parse_sandbox_policy(artifact.policy_yaml)
        .map_err(|err| err.to_string())?;
    let cache_valid_until_unix_secs = artifact
        .retrieved_at_unix_secs
        .checked_add(artifact.freshness_window_secs)
        .ok_or_else(|| "policy artifact freshness window overflowed".to_string())?;
    Ok(VerifiedPolicyArtifact {
        policy: normalize_review_json(&sandbox_policy_to_review_json(&policy))?,
        providers: governed_providers_json(),
        policy_digest: artifact.policy_digest,
        version: artifact.version,
        issuer: artifact.issuer,
        signature: artifact.signature.clone(),
        policy_signature_label: policy_signature_label_value(&artifact.signature)?,
        cache_valid_until_unix_secs,
    })
}

fn policy_signature_claims(policy_digest: String) -> PolicySignatureClaims {
    PolicySignatureClaims {
        iss: SIGNATURE_ISSUER.to_string(),
        sub: SIGNATURE_SUBJECT.to_string(),
        nbf: SIGNATURE_NBF,
        exp: SIGNATURE_EXP,
        version: SIGNATURE_VERSION.to_string(),
        valid_from: SIGNATURE_VALID_FROM.to_string(),
        expires_at: SIGNATURE_EXPIRES_AT.to_string(),
        issuer: SIGNATURE_ISSUER.to_string(),
        policy_digest,
    }
}

fn sign_policy_signature(claims: &PolicySignatureClaims) -> Result<String, String> {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(POLICY_SIGNATURE_SECRET),
    )
    .map_err(|err| err.to_string())
}

fn verify_policy_signature(token: &str) -> Result<PolicySignatureClaims, String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_nbf = true;
    validation.set_issuer(&[SIGNATURE_ISSUER]);
    validation.set_required_spec_claims(&["exp", "iss", "nbf", "sub"]);
    let claims = decode::<PolicySignatureClaims>(
        token,
        &DecodingKey::from_secret(POLICY_SIGNATURE_SECRET),
        &validation,
    )
    .map_err(|err| err.to_string())?
    .claims;
    validate_policy_signature_claims(&claims)?;
    Ok(claims)
}

fn validate_policy_signature_claims(claims: &PolicySignatureClaims) -> Result<(), String> {
    let expected = policy_signature_claims(short_policy_digest(POLICY_YAML.as_bytes()));
    if claims != &expected {
        return Err("policy signature claims do not match vendored policy".to_string());
    }
    Ok(())
}

fn policy_signature_label_value(token: &str) -> Result<String, String> {
    if token.split('.').count() != 3 {
        return Err("policy signature JWT must have three segments".to_string());
    }
    Ok(token.to_string())
}

fn add_signature_label_patch(
    object: &JsonValue,
    patches: &mut Vec<JsonPatch>,
    signature: &str,
) -> Option<InterceptorDecision> {
    match object.pointer("/metadata/labels") {
        Some(JsonValue::Object(_)) => {}
        Some(JsonValue::Null) | None => {
            patches.push(add("/metadata/labels", signature_label_json(signature)));
            return None;
        }
        Some(_) => return Some(deny("sandbox metadata labels must be a JSON object")),
    }

    match object.pointer(&signature_label_pointer()) {
        Some(existing) if existing.as_str() == Some(signature) => {}
        Some(_) => {
            return Some(deny(&format!(
                "sandbox create requested reserved signature label '{LABEL_SIGNATURE}'"
            )));
        }
        None => patches.push(add(
            &signature_label_pointer(),
            JsonValue::String(signature.to_string()),
        )),
    }

    None
}

fn signature_label_matches(object: &JsonValue, signature: &str) -> bool {
    object
        .pointer(&signature_label_pointer())
        .and_then(JsonValue::as_str)
        == Some(signature)
}

fn signature_label_json(signature: &str) -> JsonValue {
    JsonValue::Object(
        [(
            LABEL_SIGNATURE.to_string(),
            JsonValue::String(signature.to_string()),
        )]
        .into_iter()
        .collect(),
    )
}

fn signature_label_pointer() -> String {
    format!("/metadata/labels/{}", json_pointer_escape(LABEL_SIGNATURE))
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn short_policy_digest(policy_yaml: &[u8]) -> String {
    let digest = Sha256::digest(policy_yaml);
    format!("sha256-{}", hex_prefix(&digest, 16))
}

fn current_unix_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())
        .map(|duration| duration.as_secs())
}

fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(chars);
    for byte in bytes {
        if out.len() == chars {
            break;
        }
        out.push(HEX[(byte >> 4) as usize] as char);
        if out.len() == chars {
            break;
        }
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn normalize_review_json(value: &JsonValue) -> Result<JsonValue, String> {
    json_to_struct(value).map(|value| struct_to_json(&value))
}

fn sandbox_policy_to_review_json(policy: &SandboxPolicy) -> JsonValue {
    json!({
        "version": policy.version,
        "filesystem": policy.filesystem.as_ref().map(|filesystem| json!({
            "include_workdir": filesystem.include_workdir,
            "read_only": filesystem.read_only,
            "read_write": filesystem.read_write,
        })),
        "landlock": policy.landlock.as_ref().map(|landlock| json!({
            "compatibility": landlock.compatibility,
        })),
        "process": policy.process.as_ref().map(|process| json!({
            "run_as_user": process.run_as_user,
            "run_as_group": process.run_as_group,
        })),
        "network_policies": policy.network_policies.iter().map(|(key, value)| {
            (key.clone(), network_policy_rule_to_json(value))
        }).collect::<JsonMap<_, _>>(),
    })
}

#[allow(deprecated)]
fn network_policy_rule_to_json(rule: &NetworkPolicyRule) -> JsonValue {
    json!({
        "name": rule.name,
        "endpoints": rule.endpoints.iter().map(network_endpoint_to_json).collect::<Vec<_>>(),
        "binaries": rule.binaries.iter().map(|binary| {
            json!({ "path": binary.path, "harness": binary.harness })
        }).collect::<Vec<_>>(),
    })
}

#[allow(deprecated)]
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
        "graphql_persisted_queries": endpoint.graphql_persisted_queries.iter().map(|(key, value)| {
            (key.clone(), graphql_operation_to_json(value))
        }).collect::<JsonMap<_, _>>(),
        "graphql_max_body_bytes": endpoint.graphql_max_body_bytes,
        "path": endpoint.path,
        "websocket_credential_rewrite": endpoint.websocket_credential_rewrite,
        "request_body_credential_rewrite": endpoint.request_body_credential_rewrite,
        "advisor_proposed": endpoint.advisor_proposed,
    })
}

fn l7_rule_to_json(rule: &L7Rule) -> JsonValue {
    json!({ "allow": rule.allow.as_ref().map(|allow| json!({
        "method": allow.method,
        "path": allow.path,
        "command": allow.command,
        "query": query_map_to_json(&allow.query),
        "operation_type": allow.operation_type,
        "operation_name": allow.operation_name,
        "fields": allow.fields,
    })) })
}

fn l7_deny_rule_to_json(rule: &L7DenyRule) -> JsonValue {
    json!({
        "method": rule.method,
        "path": rule.path,
        "command": rule.command,
        "query": query_map_to_json(&rule.query),
        "operation_type": rule.operation_type,
        "operation_name": rule.operation_name,
        "fields": rule.fields,
    })
}

fn query_map_to_json(query: &std::collections::HashMap<String, L7QueryMatcher>) -> JsonValue {
    JsonValue::Object(
        query
            .iter()
            .map(|(key, matcher)| {
                let value = if matcher.any.is_empty() {
                    JsonValue::String(matcher.glob.clone())
                } else {
                    json!({ "any": matcher.any })
                };
                (key.clone(), value)
            })
            .collect(),
    )
}

fn graphql_operation_to_json(operation: &GraphqlOperation) -> JsonValue {
    json!({
        "operation_type": operation.operation_type,
        "operation_name": operation.operation_name,
        "fields": operation.fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_interceptors::apply_proto_patches;

    fn interceptor() -> GovernanceInterceptor {
        GovernanceInterceptor::new().expect("policy should parse")
    }

    fn review(
        phase: &str,
        resource: &str,
        operation: &str,
        object: JsonValue,
    ) -> InterceptorDecision {
        review_with(&interceptor(), phase, resource, operation, object)
    }

    fn review_with(
        interceptor: &GovernanceInterceptor,
        phase: &str,
        resource: &str,
        operation: &str,
        object: JsonValue,
    ) -> InterceptorDecision {
        interceptor.review_decision(InterceptorReview {
            api_version: API_VERSION.to_string(),
            interceptor_name: "governance".to_string(),
            binding_id: "test".to_string(),
            phase: phase.to_string(),
            resource: resource.to_string(),
            operation: operation.to_string(),
            object: Some(json_to_struct(&object).expect("object should convert")),
            ..Default::default()
        })
    }

    fn sandbox_object(policy: JsonValue, providers: JsonValue) -> JsonValue {
        json!({
            "metadata": { "name": "demo", "labels": {} },
            "spec": {
                "policy": policy,
                "providers": providers,
            },
        })
    }

    fn vended_policy() -> JsonValue {
        interceptor().verified_policy.policy
    }

    fn signature_label() -> String {
        interceptor().verified_policy.policy_signature_label
    }

    fn assert_signature_label(object: &JsonValue) {
        assert_eq!(
            object.pointer(&signature_label_pointer()),
            Some(&JsonValue::String(signature_label()))
        );
    }

    #[test]
    fn manifest_declares_governance_bindings() {
        let manifest = GovernanceInterceptor::manifest();
        assert_eq!(manifest.api_version, API_VERSION);
        let unique_ids = manifest
            .bindings
            .iter()
            .map(|binding| binding.id.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(unique_ids.len(), manifest.bindings.len());
        assert!(
            manifest
                .bindings
                .iter()
                .any(|binding| { binding.id == "sandbox-create-defaults" && binding.modifies })
        );
        assert!(manifest.bindings.iter().any(|binding| {
            binding.resource_matches("config") && binding.operation_matches("merge")
        }));
    }

    #[test]
    fn sandbox_create_vends_missing_policy_and_governed_providers() {
        let mut object = sandbox_object(JsonValue::Null, json!([]));
        let decision = review(PHASE_MODIFY_OBJECT, "sandbox", "create", object.clone());
        assert!(decision.allowed);
        assert_eq!(decision.patches.len(), 3);

        apply_proto_patches(&mut object, &decision.patches).expect("patches should apply");
        assert_eq!(
            object.pointer("/spec/providers"),
            Some(&governed_providers_json())
        );
        assert_eq!(object.pointer("/spec/policy"), Some(&vended_policy()));
        assert_signature_label(&object);
    }

    #[test]
    fn sandbox_create_vends_policy_when_spec_omits_it() {
        let mut object = json!({
            "metadata": { "name": "demo" },
            "spec": {},
        });
        let decision = review(PHASE_MODIFY_OBJECT, "sandbox", "create", object.clone());
        assert!(decision.allowed);
        assert_eq!(decision.patches.len(), 3);

        apply_proto_patches(&mut object, &decision.patches).expect("patches should apply");
        assert_eq!(
            object.pointer("/spec/providers"),
            Some(&governed_providers_json())
        );
        assert_eq!(object.pointer("/spec/policy"), Some(&vended_policy()));
        assert_signature_label(&object);
    }

    #[test]
    fn sandbox_create_allows_exact_governed_values_and_adds_missing_signature() {
        let object = sandbox_object(vended_policy(), governed_providers_json());
        let decision = review(PHASE_MODIFY_OBJECT, "sandbox", "create", object);
        assert!(decision.allowed);
        assert_eq!(decision.patches.len(), 1);
    }

    #[test]
    fn sandbox_create_preserves_matching_signature() {
        let mut object = sandbox_object(vended_policy(), governed_providers_json());
        object["metadata"]["labels"] = signature_label_json(&signature_label());
        let decision = review(PHASE_MODIFY_OBJECT, "sandbox", "create", object);
        assert!(decision.allowed);
        assert!(decision.patches.is_empty());
    }

    #[test]
    fn sandbox_create_denies_conflicting_signature_label() {
        let mut object = sandbox_object(JsonValue::Null, json!([]));
        object["metadata"]["labels"] = json!({
            "governance.nvidia.com/signature": "caller-supplied",
        });

        let decision = review(PHASE_MODIFY_OBJECT, "sandbox", "create", object);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("reserved signature label"));
    }

    #[test]
    fn signature_label_is_signed_jwt_for_vendored_policy() {
        let token = signature_label();
        let claims = verify_policy_signature(&token).expect("signature label should verify");

        assert_eq!(
            claims.policy_digest,
            short_policy_digest(POLICY_YAML.as_bytes())
        );
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn policy_signature_jwt_verifies_to_expected_claims() {
        let claims = verify_policy_signature(&interceptor().verified_policy.signature)
            .expect("policy signature should verify");

        assert_eq!(claims.iss, SIGNATURE_ISSUER);
        assert_eq!(claims.sub, SIGNATURE_SUBJECT);
        assert_eq!(claims.version, SIGNATURE_VERSION);
        assert_eq!(claims.valid_from, SIGNATURE_VALID_FROM);
        assert_eq!(claims.expires_at, SIGNATURE_EXPIRES_AT);
        assert_eq!(claims.issuer, SIGNATURE_ISSUER);
        assert_eq!(
            claims.policy_digest,
            short_policy_digest(POLICY_YAML.as_bytes())
        );
    }

    #[test]
    fn sandbox_create_denies_when_policy_signature_is_invalid() {
        let mut interceptor = interceptor();
        interceptor.verified_policy.signature.push_str("tampered");

        let decision = review_with(
            &interceptor,
            PHASE_MODIFY_OBJECT,
            "sandbox",
            "create",
            sandbox_object(JsonValue::Null, json!([])),
        );

        assert!(!decision.allowed);
        assert!(
            decision
                .reason
                .contains("policy signature validation failed")
        );
    }

    #[test]
    fn sandbox_create_denies_when_cached_policy_is_stale() {
        let mut interceptor = interceptor();
        interceptor.verified_policy.cache_valid_until_unix_secs = 0;

        let decision = review_with(
            &interceptor,
            PHASE_MODIFY_OBJECT,
            "sandbox",
            "create",
            sandbox_object(JsonValue::Null, json!([])),
        );

        assert!(!decision.allowed);
        assert!(decision.reason.contains("stale"));
    }

    #[test]
    fn sandbox_create_denies_when_policy_digest_is_revoked() {
        let mut interceptor = interceptor();
        interceptor
            .revoked_policy_digests
            .insert(interceptor.verified_policy.policy_digest.clone());

        let decision = review_with(
            &interceptor,
            PHASE_MODIFY_OBJECT,
            "sandbox",
            "create",
            sandbox_object(JsonValue::Null, json!([])),
        );

        assert!(!decision.allowed);
        assert!(decision.reason.contains("revoked"));
    }

    #[test]
    fn provider_create_fails_closed_when_cached_policy_is_stale() {
        let mut interceptor = interceptor();
        interceptor.verified_policy.cache_valid_until_unix_secs = 0;

        let decision = review_with(
            &interceptor,
            PHASE_VALIDATE_OBJECT,
            "provider",
            "create",
            json!({ "metadata": { "name": "github" }, "type": "github" }),
        );

        assert!(!decision.allowed);
        assert!(decision.reason.contains("stale"));
    }

    #[test]
    fn sandbox_create_denies_extra_provider() {
        let object = sandbox_object(JsonValue::Null, json!(["github", "gitlab", "slack"]));
        let decision = review(PHASE_MODIFY_OBJECT, "sandbox", "create", object);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("providers"));
    }

    #[test]
    fn sandbox_create_denies_non_governed_policy() {
        let object = sandbox_object(json!({ "version": 1, "network_policies": {} }), json!([]));
        let decision = review(PHASE_MODIFY_OBJECT, "sandbox", "create", object);
        assert!(!decision.allowed);
        assert!(decision.reason.contains("policy"));
    }

    #[test]
    fn sandbox_validate_requires_exact_governed_values() {
        let mut object = sandbox_object(vended_policy(), governed_providers_json());
        object["metadata"]["labels"] = signature_label_json(&signature_label());
        let decision = review(PHASE_VALIDATE_OBJECT, "sandbox", "create", object);
        assert!(decision.allowed);

        let object = sandbox_object(JsonValue::Null, governed_providers_json());
        let decision = review(PHASE_VALIDATE_OBJECT, "sandbox", "create", object);
        assert!(!decision.allowed);
    }

    #[test]
    fn provider_attach_and_detach_are_denied() {
        let attach = review(
            PHASE_VALIDATE_OBJECT,
            "sandbox",
            "attach_provider",
            json!({}),
        );
        assert!(!attach.allowed);
        let detach = review(
            PHASE_VALIDATE_OBJECT,
            "sandbox",
            "detach_provider",
            json!({}),
        );
        assert!(!detach.allowed);
    }

    #[test]
    fn policy_config_updates_are_denied_but_settings_are_allowed() {
        let policy_update = review(
            PHASE_VALIDATE_OBJECT,
            "config",
            "update",
            json!({ "policy": vended_policy(), "merge_operations": [], "setting_key": "" }),
        );
        assert!(!policy_update.allowed);

        let merge = review(
            PHASE_VALIDATE_OBJECT,
            "config",
            "merge",
            json!({ "policy": null, "merge_operations": [{ "op": "noop" }], "setting_key": "" }),
        );
        assert!(!merge.allowed);

        let setting = review(
            PHASE_VALIDATE_OBJECT,
            "config",
            "update",
            json!({ "policy": null, "merge_operations": [], "setting_key": "providers_v2_enabled" }),
        );
        assert!(setting.allowed);
    }

    #[test]
    fn only_governed_provider_records_are_allowed() {
        let github = review(
            PHASE_VALIDATE_OBJECT,
            "provider",
            "create",
            json!({ "metadata": { "name": "github" }, "type": "github" }),
        );
        assert!(github.allowed);

        let wrong_type = review(
            PHASE_VALIDATE_OBJECT,
            "provider",
            "create",
            json!({ "metadata": { "name": "github" }, "type": "gitlab" }),
        );
        assert!(!wrong_type.allowed);

        let extra = review(
            PHASE_VALIDATE_OBJECT,
            "provider",
            "create",
            json!({ "metadata": { "name": "slack" }, "type": "generic" }),
        );
        assert!(!extra.allowed);
    }

    #[test]
    fn provider_update_delete_and_profile_changes_are_denied() {
        assert!(
            !review(
                PHASE_VALIDATE_OBJECT,
                "provider",
                "update",
                json!({ "metadata": { "name": "github" }, "type": "github" })
            )
            .allowed
        );
        assert!(!review(PHASE_VALIDATE_OBJECT, "provider", "delete", json!({})).allowed);
        assert!(
            !review(
                PHASE_VALIDATE_OBJECT,
                "provider_profile",
                "import",
                json!({})
            )
            .allowed
        );
        assert!(
            !review(
                PHASE_VALIDATE_OBJECT,
                "provider_profile",
                "delete",
                json!({})
            )
            .allowed
        );
    }

    trait BindingTestExt {
        fn resource_matches(&self, resource: &str) -> bool;
        fn operation_matches(&self, operation: &str) -> bool;
    }

    impl BindingTestExt for InterceptorBinding {
        fn resource_matches(&self, resource: &str) -> bool {
            self.resources.iter().any(|value| value == resource)
        }

        fn operation_matches(&self, operation: &str) -> bool {
            self.operations.iter().any(|value| value == operation)
        }
    }
}
