// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared supervisor middleware identifiers and policy validation contracts.

use miette::{Result, miette};
use serde::Deserialize;

/// Binding identifier for the built-in secret redaction middleware.
pub const BUILTIN_SECRETS: &str = "openshell/secrets";

/// Policy-owned configuration for the built-in `openshell/secrets` middleware.
///
/// Unknown fields and wrong-typed values are rejected so a config typo fails
/// policy validation instead of silently running with defaults.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretsConfig {
    /// Redaction mode. Omitting the field selects [`SecretsMode::Redact`].
    pub secrets: SecretsMode,
}

/// Supported `openshell/secrets` modes. Phase 1 supports only `redact`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretsMode {
    #[default]
    Redact,
}

impl SecretsConfig {
    /// Parse and validate a policy-owned protobuf config.
    pub fn from_struct(config: &prost_types::Struct) -> Result<Self> {
        serde_json::from_value(crate::proto_struct::struct_to_json_value(config)).map_err(|error| {
            miette!(
                "invalid {BUILTIN_SECRETS} config: {error}; phase 1 supports only secrets: redact"
            )
        })
    }
}

/// Validate policy-owned configuration for a built-in middleware.
pub fn validate_builtin_config(implementation: &str, config: &prost_types::Struct) -> Result<()> {
    match implementation {
        BUILTIN_SECRETS => SecretsConfig::from_struct(config).map(|_| ()),
        other => Err(miette!(
            "middleware implementation '{other}' is not available in phase 1"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_config(key: &str, value: &str) -> prost_types::Struct {
        prost_types::Struct {
            fields: std::iter::once((
                key.to_string(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(value.into())),
                },
            ))
            .collect(),
        }
    }

    #[test]
    fn secrets_config_defaults_to_redact() {
        let config = SecretsConfig::from_struct(&prost_types::Struct::default()).unwrap();
        assert_eq!(config.secrets, SecretsMode::Redact);
    }

    #[test]
    fn secrets_config_accepts_explicit_redact() {
        let config = SecretsConfig::from_struct(&string_config("secrets", "redact")).unwrap();
        assert_eq!(config.secrets, SecretsMode::Redact);
    }

    #[test]
    fn secrets_config_rejects_unsupported_mode() {
        let error = validate_builtin_config(BUILTIN_SECRETS, &string_config("secrets", "allow"))
            .unwrap_err();
        assert!(error.to_string().contains("supports only secrets: redact"));
    }

    #[test]
    fn secrets_config_rejects_unknown_field() {
        let error = validate_builtin_config(BUILTIN_SECRETS, &string_config("secret", "redact"))
            .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn secrets_config_rejects_non_string_mode() {
        let config = prost_types::Struct {
            fields: std::iter::once((
                "secrets".to_string(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::NumberValue(42.0)),
                },
            ))
            .collect(),
        };

        let error = validate_builtin_config(BUILTIN_SECRETS, &config).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid openshell/secrets config")
        );
    }

    #[test]
    fn rejects_unknown_builtin() {
        let error = validate_builtin_config("openshell/unknown", &prost_types::Struct::default())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("implementation 'openshell/unknown' is not available")
        );
    }
}
