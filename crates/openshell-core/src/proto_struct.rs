// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for converting `google.protobuf.Struct` values to and from JSON.

use serde::{Deserialize, Deserializer, de::Error as _};

/// Errors converting JSON values into protobuf well-known types.
#[derive(Debug, thiserror::Error)]
pub enum ProtoStructError {
    /// A JSON number cannot be represented by protobuf's double value.
    #[error("JSON number {0} cannot be represented as a protobuf double")]
    UnrepresentableNumber(serde_json::Number),
}

/// Convert a JSON object into a protobuf Struct.
pub fn json_object_to_struct(
    object: serde_json::Map<String, serde_json::Value>,
) -> Result<prost_types::Struct, ProtoStructError> {
    Ok(prost_types::Struct {
        fields: object
            .into_iter()
            .map(|(key, value)| json_value_to_proto(value).map(|value| (key, value)))
            .collect::<Result<_, _>>()?,
    })
}

/// Convert a JSON value into a protobuf Value.
pub fn json_value_to_proto(
    value: serde_json::Value,
) -> Result<prost_types::Value, ProtoStructError> {
    use prost_types::{ListValue, Value, value::Kind};

    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(value) => Kind::BoolValue(value),
        serde_json::Value::Number(value) => Kind::NumberValue(
            value
                .as_f64()
                .ok_or_else(|| ProtoStructError::UnrepresentableNumber(value.clone()))?,
        ),
        serde_json::Value::String(value) => Kind::StringValue(value),
        serde_json::Value::Array(values) => Kind::ListValue(ListValue {
            values: values
                .into_iter()
                .map(json_value_to_proto)
                .collect::<Result<_, _>>()?,
        }),
        serde_json::Value::Object(object) => Kind::StructValue(json_object_to_struct(object)?),
    };

    Ok(Value { kind: Some(kind) })
}

/// Convert a protobuf Struct into a JSON object for typed serde decoding.
#[must_use]
pub fn struct_to_json_object(
    config: &prost_types::Struct,
) -> serde_json::Map<String, serde_json::Value> {
    config
        .fields
        .iter()
        .map(|(key, value)| (key.clone(), value_to_json(value)))
        .collect()
}

/// Convert a protobuf Struct into a JSON value for typed serde decoding.
#[must_use]
pub fn struct_to_json_value(config: &prost_types::Struct) -> serde_json::Value {
    serde_json::Value::Object(struct_to_json_object(config))
}

/// Convert a protobuf Value into a JSON value for typed serde decoding.
#[must_use]
pub fn value_to_json(value: &prost_types::Value) -> serde_json::Value {
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::NumberValue(num)) => serde_json::Number::from_f64(*num)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Some(prost_types::value::Kind::StringValue(val)) => serde_json::Value::String(val.clone()),
        Some(prost_types::value::Kind::BoolValue(val)) => serde_json::Value::Bool(*val),
        Some(prost_types::value::Kind::StructValue(val)) => {
            serde_json::Value::Object(struct_to_json_object(val))
        }
        Some(prost_types::value::Kind::ListValue(list)) => {
            serde_json::Value::Array(list.values.iter().map(value_to_json).collect())
        }
        Some(prost_types::value::Kind::NullValue(_)) | None => serde_json::Value::Null,
    }
}

/// Deserialize a present field as a non-empty list of non-empty strings.
///
/// Use with `#[serde(default, deserialize_with = "...")]` on
/// `Option<Vec<String>>` fields. Missing fields use the option default; present
/// fields must be arrays and cannot be empty.
pub fn deserialize_optional_non_empty_string_list<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    if values.is_empty() {
        return Err(D::Error::custom("must be a non-empty list of strings"));
    }

    for (idx, value) in values.iter().enumerate() {
        if value.trim().is_empty() {
            return Err(D::Error::custom(format!(
                "[{idx}] must be a non-empty string"
            )));
        }
    }

    Ok(Some(values))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_and_proto_values_round_trip() {
        let json = serde_json::json!({
            "null": null,
            "bool": true,
            "number": 42.5,
            "string": "value",
            "list": [1.0, {"nested": "value"}],
        });
        let serde_json::Value::Object(object) = json.clone() else {
            unreachable!();
        };

        let proto = json_object_to_struct(object).unwrap();

        assert_eq!(struct_to_json_value(&proto), json);
    }

    #[derive(Debug, Default, Deserialize)]
    #[serde(default)]
    struct TestConfig {
        #[serde(
            default,
            deserialize_with = "deserialize_optional_non_empty_string_list"
        )]
        devices: Option<Vec<String>>,
    }

    #[test]
    fn optional_non_empty_string_list_defaults_when_absent() {
        let config: TestConfig = serde_json::from_value(serde_json::json!({})).unwrap();

        assert_eq!(config.devices, None);
    }

    #[test]
    fn optional_non_empty_string_list_parses_present_list() {
        let config: TestConfig =
            serde_json::from_value(serde_json::json!({"devices": ["nvidia.com/gpu=0"]})).unwrap();

        assert_eq!(config.devices, Some(vec!["nvidia.com/gpu=0".to_string()]));
    }

    #[test]
    fn optional_non_empty_string_list_rejects_empty_list() {
        let err =
            serde_json::from_value::<TestConfig>(serde_json::json!({"devices": []})).unwrap_err();

        assert!(err.to_string().contains("non-empty list"));
    }

    #[test]
    fn optional_non_empty_string_list_rejects_empty_string() {
        let err =
            serde_json::from_value::<TestConfig>(serde_json::json!({"devices": [""]})).unwrap_err();

        assert!(err.to_string().contains("non-empty string"));
    }
}
