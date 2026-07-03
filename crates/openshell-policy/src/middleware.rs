// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! YAML schema and protobuf conversion for supervisor middleware policies.

use std::collections::{BTreeMap, HashSet};

use openshell_core::proto::{MiddlewareEndpointSelector, NetworkMiddlewareConfig, SandboxPolicy};
use openshell_core::proto_struct::{
    ProtoStructError, json_object_to_struct, struct_to_json_object,
};
use serde::{Deserialize, Serialize};

use super::PolicyViolation;

pub use openshell_core::middleware::host_matches as middleware_host_matches;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkMiddlewareConfigDef {
    name: String,
    middleware: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    config: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    on_error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoints: Option<MiddlewareEndpointSelectorDef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MiddlewareEndpointSelectorDef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    include: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    exclude: Vec<String>,
}

pub fn into_proto(
    definitions: Vec<NetworkMiddlewareConfigDef>,
) -> Result<Vec<NetworkMiddlewareConfig>, ProtoStructError> {
    definitions
        .into_iter()
        .map(|definition| {
            Ok(NetworkMiddlewareConfig {
                name: definition.name,
                middleware: definition.middleware,
                config: Some(json_object_to_struct(
                    definition.config.into_iter().collect(),
                )?),
                on_error: definition.on_error,
                endpoints: definition
                    .endpoints
                    .map(|selector| MiddlewareEndpointSelector {
                        include: selector.include,
                        exclude: selector.exclude,
                    }),
            })
        })
        .collect()
}

pub fn from_proto(middlewares: &[NetworkMiddlewareConfig]) -> Vec<NetworkMiddlewareConfigDef> {
    middlewares
        .iter()
        .map(|middleware| NetworkMiddlewareConfigDef {
            name: middleware.name.clone(),
            middleware: middleware.middleware.clone(),
            config: middleware
                .config
                .as_ref()
                .map(struct_to_json_object)
                .unwrap_or_default()
                .into_iter()
                .collect(),
            on_error: middleware.on_error.clone(),
            endpoints: middleware.endpoints.as_ref().map(|selector| {
                MiddlewareEndpointSelectorDef {
                    include: selector.include.clone(),
                    exclude: selector.exclude.clone(),
                }
            }),
        })
        .collect()
}

fn selector_matches_host(middleware: &NetworkMiddlewareConfig, host: &str) -> Result<bool, String> {
    let Some(selector) = &middleware.endpoints else {
        return Ok(false);
    };
    let matches_include = selector
        .include
        .iter()
        .try_fold(false, |matched, pattern| {
            middleware_host_matches(pattern, host).map(|matches| matched || matches)
        })?;
    let matches_exclude = selector
        .exclude
        .iter()
        .try_fold(false, |matched, pattern| {
            middleware_host_matches(pattern, host).map(|matches| matched || matches)
        })?;
    Ok(matches_include && !matches_exclude)
}

pub fn validate(policy: &SandboxPolicy) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    let mut names = HashSet::new();

    for middleware in &policy.network_middlewares {
        if middleware.name.is_empty() {
            violations.push(PolicyViolation::InvalidMiddlewareConfig {
                name: middleware.name.clone(),
                reason: "name must not be empty".to_string(),
            });
        } else if !names.insert(middleware.name.clone()) {
            violations.push(PolicyViolation::DuplicateMiddlewareConfigName {
                name: middleware.name.clone(),
            });
        }

        if middleware.middleware.is_empty() {
            violations.push(PolicyViolation::InvalidMiddlewareConfig {
                name: middleware.name.clone(),
                reason: "implementation must not be empty".to_string(),
            });
        } else if middleware.middleware.starts_with("openshell/")
            && middleware.middleware != openshell_core::middleware::BUILTIN_SECRETS
        {
            violations.push(PolicyViolation::InvalidMiddlewareConfig {
                name: middleware.name.clone(),
                reason: format!("unsupported built-in '{}'", middleware.middleware),
            });
        }

        if !matches!(
            middleware.on_error.as_str(),
            "" | "fail_closed" | "fail_open"
        ) {
            violations.push(PolicyViolation::InvalidMiddlewareConfig {
                name: middleware.name.clone(),
                reason: format!("invalid on_error '{}'", middleware.on_error),
            });
        }

        let Some(selector) = &middleware.endpoints else {
            violations.push(PolicyViolation::InvalidMiddlewareConfig {
                name: middleware.name.clone(),
                reason: "endpoint selector is required".to_string(),
            });
            continue;
        };
        if selector.include.is_empty() {
            violations.push(PolicyViolation::InvalidMiddlewareConfig {
                name: middleware.name.clone(),
                reason: "endpoint selector must include at least one host pattern".to_string(),
            });
        }
        for pattern in selector.include.iter().chain(&selector.exclude) {
            if let Err(reason) = middleware_host_matches(pattern, "validation.invalid") {
                violations.push(PolicyViolation::InvalidMiddlewareConfig {
                    name: middleware.name.clone(),
                    reason: format!("endpoint selector pattern '{pattern}' is invalid: {reason}"),
                });
            }
        }

        if middleware.middleware == openshell_core::middleware::BUILTIN_SECRETS {
            let config = middleware.config.clone().unwrap_or_default();
            if let Err(error) =
                openshell_core::middleware::validate_builtin_config(&middleware.middleware, &config)
            {
                violations.push(PolicyViolation::InvalidBuiltinMiddlewareConfig {
                    name: middleware.name.clone(),
                    reason: error.to_string(),
                });
            }
        }

        for (key, rule) in &policy.network_policies {
            let policy_name = if rule.name.is_empty() {
                key
            } else {
                &rule.name
            };
            for endpoint in &rule.endpoints {
                if endpoint.tls == "skip"
                    && selector_matches_host(middleware, &endpoint.host).unwrap_or(false)
                {
                    violations.push(PolicyViolation::MiddlewareTlsSkipConflict {
                        middleware_name: middleware.name.clone(),
                        policy_name: policy_name.clone(),
                        host: endpoint.host.clone(),
                    });
                }
            }
        }
    }

    violations
}
