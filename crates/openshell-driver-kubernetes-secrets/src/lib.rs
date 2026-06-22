// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential driver backed by Kubernetes Secret objects.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{DeleteParams, Patch, PatchParams, PostParams};
use kube::{Api, Client};
use openshell_core::proto::CredentialHandle;
use openshell_core::proto::credentials::v1::{
    DeleteCredentialRequest, ResolveCredentialRequest, ResolvedCredential, StoreCredentialRequest,
};
use openshell_core::{Error, Result as CoreResult};
use sha2::{Digest, Sha256};
use tonic::Status;

const SERVICE_ACCOUNT_NAMESPACE_PATH: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
const HANDLE_VERSION: &str = "v1";

pub struct KubernetesSecretsCredentialDriver {
    client: Client,
    settings: KubernetesSecretsDriverSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesSecretsDriverSettings {
    namespace: String,
    allow_reference_namespace: bool,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesSecretsDriverConfig {
    namespace: Option<String>,
    allow_reference_namespace: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KubernetesSecretReference {
    namespace: String,
    secret_name: String,
    key: String,
}

impl KubernetesSecretsCredentialDriver {
    pub const NAME: &'static str = "kubernetes-secrets";

    pub async fn from_config(config: &toml::Table) -> CoreResult<Self> {
        let settings = KubernetesSecretsDriverSettings::from_table(config)?;
        let client = Client::try_default().await.map_err(|err| {
            Error::config(format!(
                "failed to configure kubernetes-secrets credential driver: {err}"
            ))
        })?;
        Ok(Self { client, settings })
    }

    fn handle_from_request(
        request_id: &str,
        handle: Option<CredentialHandle>,
    ) -> Result<CredentialHandle, Status> {
        handle.ok_or_else(|| {
            Status::invalid_argument(format!(
                "kubernetes-secrets credential request '{request_id}' is missing handle"
            ))
        })
    }

    fn resolve_handle(
        handle: &CredentialHandle,
        credential_key: &str,
    ) -> Result<KubernetesSecretReference, Status> {
        let parts = handle.handle.split(':').collect::<Vec<_>>();
        if parts.len() != 3 || parts[0] != HANDLE_VERSION {
            return Err(Status::invalid_argument(
                "kubernetes-secrets credential handle is malformed",
            ));
        }
        let namespace = required_handle_component("namespace", parts[1])?;
        if !is_dns_label(namespace) {
            return Err(Status::invalid_argument(
                "kubernetes-secrets credential handle namespace is invalid",
            ));
        }
        let secret_name = required_handle_component("secret", parts[2])?;
        if !is_dns_subdomain(secret_name) {
            return Err(Status::invalid_argument(
                "kubernetes-secrets credential handle Secret name is invalid",
            ));
        }
        let key = required_handle_component("credential_key", credential_key)?;
        if !is_secret_data_key(key) {
            return Err(Status::invalid_argument(
                "kubernetes-secrets credential key must be a valid Kubernetes Secret data key",
            ));
        }

        Ok(KubernetesSecretReference {
            namespace: namespace.to_string(),
            secret_name: secret_name.to_string(),
            key: key.to_string(),
        })
    }

    pub async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        let reference = if let Some(existing_handle) = request.existing_handle.as_ref() {
            Self::resolve_handle(existing_handle, &request.credential_key)?
        } else {
            KubernetesSecretReference {
                namespace: self.settings.namespace.clone(),
                secret_name: managed_secret_name(&request.provider_name, &request.credential_key),
                key: required_handle_component("credential_key", &request.credential_key)?
                    .to_string(),
            }
        };
        if !is_secret_data_key(&reference.key) {
            return Err(Status::invalid_argument(
                "kubernetes-secrets credential key must be a valid Kubernetes Secret data key",
            ));
        }
        self.store_secret_value(&reference, &request.value).await?;
        Ok(CredentialHandle {
            driver: Self::NAME.to_string(),
            handle: format!(
                "{HANDLE_VERSION}:{}:{}",
                reference.namespace, reference.secret_name
            ),
            metadata: std::collections::HashMap::new(),
        })
    }

    pub async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        let handle = Self::handle_from_request("delete", request.handle)?;
        let reference = Self::resolve_handle(&handle, &request.credential_key)?;
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &reference.namespace);
        match api
            .delete(&reference.secret_name, &DeleteParams::default())
            .await
        {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(api_err)) if api_err.code == 404 => Ok(()),
            Err(kube::Error::Api(api_err)) if api_err.code == 403 => {
                Err(Status::permission_denied(format!(
                    "gateway is not allowed to delete Kubernetes Secret '{}' in namespace '{}'",
                    reference.secret_name, reference.namespace
                )))
            }
            Err(err) => Err(Status::unavailable(format!(
                "failed to delete Kubernetes Secret '{}' in namespace '{}': {err}",
                reference.secret_name, reference.namespace
            ))),
        }
    }

    pub async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        let mut responses = Vec::with_capacity(requests.len());
        for request in requests {
            let handle = Self::handle_from_request(&request.request_id, request.handle)?;
            let reference = Self::resolve_handle(&handle, &request.credential_key)?;
            let value = self.resolve_secret_value(&reference).await?;
            responses.push(ResolvedCredential {
                request_id: request.request_id,
                value,
                expires_at_ms: 0,
            });
        }
        Ok(responses)
    }

    async fn store_secret_value(
        &self,
        reference: &KubernetesSecretReference,
        value: &str,
    ) -> Result<(), Status> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &reference.namespace);
        let secret = managed_secret(&reference.secret_name, &reference.key, value);
        match api.create(&PostParams::default(), &secret).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(api_err)) if api_err.code == 409 => api
                .patch(
                    &reference.secret_name,
                    &PatchParams::default(),
                    &Patch::Merge(&secret),
                )
                .await
                .map(|_| ())
                .map_err(|err| {
                    kube_write_error_to_status(&reference.namespace, &reference.secret_name, err)
                }),
            Err(err) => Err(kube_write_error_to_status(
                &reference.namespace,
                &reference.secret_name,
                err,
            )),
        }
    }

    async fn resolve_secret_value(
        &self,
        reference: &KubernetesSecretReference,
    ) -> Result<String, Status> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &reference.namespace);
        let secret = api.get(&reference.secret_name).await.map_err(|err| {
            kube_error_to_status(&reference.namespace, &reference.secret_name, err)
        })?;
        let data = secret.data.ok_or_else(|| {
            Status::not_found(format!(
                "Kubernetes Secret '{}' in namespace '{}' has no data",
                reference.secret_name, reference.namespace
            ))
        })?;
        let value = data.get(&reference.key).ok_or_else(|| {
            Status::not_found(format!(
                "Kubernetes Secret '{}' in namespace '{}' does not contain key '{}'",
                reference.secret_name, reference.namespace, reference.key
            ))
        })?;
        String::from_utf8(value.0.clone()).map_err(|_| {
            Status::invalid_argument(format!(
                "Kubernetes Secret '{}' in namespace '{}' key '{}' is not valid UTF-8",
                reference.secret_name, reference.namespace, reference.key
            ))
        })
    }
}

impl std::fmt::Debug for KubernetesSecretsCredentialDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubernetesSecretsCredentialDriver")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl KubernetesSecretsDriverSettings {
    fn from_table(config: &toml::Table) -> CoreResult<Self> {
        let config: KubernetesSecretsDriverConfig = toml::Value::Table(config.clone())
            .try_into()
            .map_err(|err| {
            Error::config(format!(
                "invalid [openshell.credential_drivers.kubernetes-secrets]: {err}"
            ))
        })?;
        let namespace = match config.namespace {
            Some(namespace) => {
                let namespace = trimmed_config_string("namespace", &namespace)?;
                if !is_dns_label(namespace) {
                    return Err(Error::config(
                        "[openshell.credential_drivers.kubernetes-secrets] namespace must be a Kubernetes namespace name",
                    ));
                }
                namespace.to_string()
            }
            None => default_namespace(),
        };

        Ok(Self {
            namespace,
            allow_reference_namespace: config.allow_reference_namespace,
        })
    }
}

fn kube_error_to_status(namespace: &str, secret_name: &str, err: kube::Error) -> Status {
    match err {
        kube::Error::Api(api_err) if api_err.code == 404 => Status::not_found(format!(
            "Kubernetes Secret '{secret_name}' in namespace '{namespace}' was not found"
        )),
        kube::Error::Api(api_err) if api_err.code == 403 => Status::permission_denied(format!(
            "gateway is not allowed to read Kubernetes Secret '{secret_name}' in namespace '{namespace}'"
        )),
        other => Status::unavailable(format!(
            "failed to read Kubernetes Secret '{secret_name}' in namespace '{namespace}': {other}"
        )),
    }
}

fn default_namespace() -> String {
    std::fs::read_to_string(SERVICE_ACCOUNT_NAMESPACE_PATH)
        .ok()
        .map(|namespace| namespace.trim().to_string())
        .filter(|namespace| !namespace.is_empty() && is_dns_label(namespace))
        .unwrap_or_else(|| "default".to_string())
}

fn kube_write_error_to_status(namespace: &str, secret_name: &str, err: kube::Error) -> Status {
    match err {
        kube::Error::Api(api_err) if api_err.code == 403 => Status::permission_denied(format!(
            "gateway is not allowed to write Kubernetes Secret '{secret_name}' in namespace '{namespace}'"
        )),
        other => Status::unavailable(format!(
            "failed to write Kubernetes Secret '{secret_name}' in namespace '{namespace}': {other}"
        )),
    }
}

fn managed_secret(secret_name: &str, key: &str, value: &str) -> Secret {
    let labels = BTreeMap::from([(
        "app.kubernetes.io/managed-by".to_string(),
        "openshell".to_string(),
    )]);
    Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        string_data: Some(BTreeMap::from([(key.to_string(), value.to_string())])),
        type_: Some("Opaque".to_string()),
        ..Default::default()
    }
}

fn managed_secret_name(provider_name: &str, credential_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(provider_name.as_bytes());
    hasher.update([0]);
    hasher.update(credential_key.as_bytes());
    let digest = hasher.finalize();
    let hex = format!("{digest:x}");
    format!("openshell-cred-{}", &hex[..40])
}

fn trimmed_config_string<'a>(field_name: &str, value: &'a str) -> CoreResult<&'a str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::config(format!(
            "[openshell.credential_drivers.kubernetes-secrets] {field_name} must not be empty"
        )));
    }
    if trimmed.len() != value.len() {
        return Err(Error::config(format!(
            "[openshell.credential_drivers.kubernetes-secrets] {field_name} must not contain leading or trailing whitespace"
        )));
    }
    Ok(trimmed)
}

fn required_handle_component<'a>(field_name: &str, value: &'a str) -> Result<&'a str, Status> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Status::invalid_argument(format!(
            "kubernetes-secrets credential handle {field_name} is required"
        )));
    }
    if trimmed.len() != value.len() {
        return Err(Status::invalid_argument(format!(
            "kubernetes-secrets credential handle {field_name} must not contain leading or trailing whitespace"
        )));
    }
    Ok(trimmed)
}

fn is_dns_subdomain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(is_dns_label)
        && !value.contains("..")
}

fn is_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn is_secret_data_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    fn handle(value: &str) -> CredentialHandle {
        CredentialHandle {
            driver: "kubernetes-secrets".to_string(),
            handle: value.to_string(),
            metadata: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn settings_parse_configured_namespace() {
        let settings = KubernetesSecretsDriverSettings::from_table(&toml::toml! {
            namespace = "openshell"
            allow_reference_namespace = true
        })
        .unwrap();

        assert_eq!(settings.namespace, "openshell");
        assert!(settings.allow_reference_namespace);
    }

    #[test]
    fn settings_reject_unknown_fields() {
        let err = KubernetesSecretsDriverSettings::from_table(&toml::toml! {
            namespace = "openshell"
            unknown = "value"
        })
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn settings_reject_invalid_namespace() {
        let err = KubernetesSecretsDriverSettings::from_table(&toml::toml! {
            namespace = "OpenShell"
        })
        .unwrap_err();

        assert!(err.to_string().contains("namespace"));
    }

    #[test]
    fn handle_resolves_secret_reference() {
        let reference = KubernetesSecretsCredentialDriver::resolve_handle(
            &handle("v1:openshell:provider-secret"),
            "API_KEY",
        )
        .unwrap();

        assert_eq!(reference.namespace, "openshell");
        assert_eq!(reference.secret_name, "provider-secret");
        assert_eq!(reference.key, "API_KEY");
    }

    #[test]
    fn handle_rejects_malformed_value() {
        let err = KubernetesSecretsCredentialDriver::resolve_handle(
            &handle("provider-secret"),
            "API_KEY",
        )
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("malformed"));
    }

    #[test]
    fn handle_rejects_invalid_namespace() {
        let err = KubernetesSecretsCredentialDriver::resolve_handle(
            &handle("v1:OpenShell:provider-secret"),
            "API_KEY",
        )
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("namespace"));
    }

    #[test]
    fn handle_rejects_invalid_secret_name() {
        let err = KubernetesSecretsCredentialDriver::resolve_handle(
            &handle("v1:openshell:ProviderSecret"),
            "API_KEY",
        )
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("Secret name"));
    }

    #[test]
    fn handle_rejects_invalid_credential_key() {
        let err = KubernetesSecretsCredentialDriver::resolve_handle(
            &handle("v1:openshell:provider-secret"),
            "api/key",
        )
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("data key"));
    }

    #[test]
    fn managed_secret_names_are_stable_dns_subdomains() {
        let name = managed_secret_name("openai-prod", "OPENAI_API_KEY");

        assert!(name.starts_with("openshell-cred-"));
        assert!(is_dns_subdomain(&name));
        assert_eq!(name, managed_secret_name("openai-prod", "OPENAI_API_KEY"));
    }
}
