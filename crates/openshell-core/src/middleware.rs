// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared supervisor middleware identifiers and policy validation contracts.

use miette::{Result, miette};

/// Binding identifier for the built-in secret redaction middleware.
pub const BUILTIN_SECRETS: &str = "openshell/secrets";

/// Match a middleware host selector pattern using the runtime's glob semantics.
///
/// Matching is case-insensitive. Invalid or empty patterns return an error
/// instead of silently becoming a non-match.
pub fn host_matches(pattern: &str, host: &str) -> std::result::Result<bool, String> {
    if pattern.is_empty() {
        return Err("host pattern must not be empty".to_string());
    }
    if pattern.chars().any(char::is_whitespace) {
        return Err("host pattern must not contain whitespace".to_string());
    }

    let pattern = glob::Pattern::new(&pattern.to_ascii_lowercase())
        .map_err(|error| format!("invalid host pattern: {error}"))?;
    Ok(pattern.matches(&host.to_ascii_lowercase()))
}

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
    fn host_matching_is_case_insensitive() {
        assert!(host_matches("*.Example.COM", "API.example.com").unwrap());
        assert!(!host_matches("*.example.com", "example.com").unwrap());
        assert!(host_matches("*", "deep.api.example.com").unwrap());
    }

    #[test]
    fn host_matching_rejects_invalid_patterns() {
        assert!(host_matches("", "api.example.com").is_err());
        assert!(host_matches("api .example.com", "api.example.com").is_err());
        assert!(host_matches("api[.example.com", "api.example.com").is_err());
    }

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
