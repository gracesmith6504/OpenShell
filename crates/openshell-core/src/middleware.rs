// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared supervisor middleware identifiers and policy validation contracts.

use miette::{Result, miette};

/// Binding identifier for the built-in secret redaction middleware.
pub const BUILTIN_SECRETS: &str = "openshell/secrets";

/// Validate policy-owned configuration for a built-in middleware.
pub fn validate_builtin_config(implementation: &str, config: &prost_types::Struct) -> Result<()> {
    match implementation {
        BUILTIN_SECRETS => validate_secrets_config(config),
        other => Err(miette!(
            "middleware implementation '{other}' is not available in phase 1"
        )),
    }
}

fn validate_secrets_config(config: &prost_types::Struct) -> Result<()> {
    let mode = config
        .fields
        .get("secrets")
        .and_then(|value| match value.kind.as_ref() {
            Some(prost_types::value::Kind::StringValue(value)) => Some(value.as_str()),
            _ => None,
        })
        .unwrap_or("redact");
    if mode != "redact" {
        return Err(miette!(
            "{BUILTIN_SECRETS} only supports config.secrets: redact in phase 1"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_config_defaults_to_redact() {
        validate_builtin_config(BUILTIN_SECRETS, &prost_types::Struct::default()).unwrap();
    }

    #[test]
    fn secrets_config_rejects_unsupported_mode() {
        let config = prost_types::Struct {
            fields: std::iter::once((
                "secrets".to_string(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("allow".into())),
                },
            ))
            .collect(),
        };

        let error = validate_builtin_config(BUILTIN_SECRETS, &config).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("only supports config.secrets: redact")
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
