// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! YAML schema and protobuf conversion for supervisor middleware policies.

use std::collections::{BTreeMap, HashSet};

use openshell_core::proto::{
    MiddlewareEndpointSelector, NetworkEndpoint, NetworkMiddlewareConfig, NetworkPolicyRule,
    SandboxPolicy,
};
use openshell_core::proto_struct::{
    ProtoStructError, json_object_to_struct, struct_to_json_object,
};
use serde::{Deserialize, Serialize};

use super::PolicyViolation;

pub use openshell_core::host_pattern::host_matches as middleware_host_matches;
use openshell_core::host_pattern::{HostPattern, HostSelector};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkMiddlewareConfigDef {
    name: String,
    middleware: String,
    #[serde(default, skip_serializing_if = "is_default")]
    order: i32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    config: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    on_error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoints: Option<MiddlewareEndpointSelectorDef>,
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    value == &T::default()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MiddlewareEndpointSelectorDef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    include: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    exclude: Vec<String>,
}

/// Middleware-relevant projection of the runtime policy JSON accepted by the
/// supervisor's local-file mode. Unrelated network and L7 fields are ignored;
/// middleware entries retain their strict canonical schema.
#[derive(Debug, Default, Deserialize)]
struct MiddlewareValidationPolicyDef {
    #[serde(default)]
    network_middlewares: Vec<NetworkMiddlewareConfigDef>,
    #[serde(default)]
    network_policies: BTreeMap<String, MiddlewareValidationNetworkPolicyDef>,
}

#[derive(Debug, Default, Deserialize)]
struct MiddlewareValidationNetworkPolicyDef {
    #[serde(default)]
    name: String,
    #[serde(default)]
    endpoints: Vec<MiddlewareValidationEndpointDef>,
}

#[derive(Debug, Default, Deserialize)]
struct MiddlewareValidationEndpointDef {
    #[serde(default)]
    host: String,
    #[serde(default)]
    tls: String,
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
                order: definition.order,
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
            order: middleware.order,
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

/// Validate middleware configuration from the supervisor's runtime policy
/// JSON through the same typed validator used for protobuf policies.
pub fn validate_json(data: &serde_json::Value) -> Result<Vec<PolicyViolation>, String> {
    let definition: MiddlewareValidationPolicyDef = serde_json::from_value(data.clone())
        .map_err(|error| format!("failed to parse network middleware policy: {error}"))?;
    let network_middlewares = into_proto(definition.network_middlewares)
        .map_err(|error| format!("failed to convert network middleware config: {error}"))?;
    let network_policies = definition
        .network_policies
        .into_iter()
        .map(|(key, rule)| {
            let rule = NetworkPolicyRule {
                name: rule.name,
                endpoints: rule
                    .endpoints
                    .into_iter()
                    .map(|endpoint| NetworkEndpoint {
                        host: endpoint.host,
                        tls: endpoint.tls,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            };
            (key, rule)
        })
        .collect();
    Ok(validate(&SandboxPolicy {
        network_middlewares,
        network_policies,
        ..Default::default()
    }))
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
        let mut selector_valid = !selector.include.is_empty();
        for pattern in selector.include.iter().chain(&selector.exclude) {
            if let Err(reason) = HostPattern::new(pattern) {
                selector_valid = false;
                violations.push(PolicyViolation::InvalidMiddlewareConfig {
                    name: middleware.name.clone(),
                    reason: format!("endpoint selector pattern '{pattern}' is invalid: {reason}"),
                });
            }
        }
        let compiled_selector = if selector_valid {
            HostSelector::new(&selector.include, &selector.exclude).ok()
        } else {
            None
        };

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
                let overlaps_tls_skip = endpoint.tls == "skip"
                    && compiled_selector.as_ref().is_some_and(|selector| {
                        HostPattern::new(&endpoint.host)
                            .is_ok_and(|endpoint| selector.may_match_pattern(&endpoint))
                    });
                if overlaps_tls_skip {
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
