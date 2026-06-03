// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared GPU request helpers.

use crate::config::CDI_GPU_DEVICE_ALL;
use crate::proto::compute::v1::DriverGpuResourceRequirement;
use std::collections::HashSet;

/// Resolve a driver GPU request into CDI device identifiers.
///
/// `None` means no GPU was requested. Presence with a positive count and
/// explicit device IDs passes those IDs through. Other present GPU requests use
/// the CDI all-GPU request.
#[must_use]
pub fn cdi_gpu_device_ids(
    gpu: Option<&DriverGpuResourceRequirement>,
    driver_config_device_ids: &[String],
) -> Option<Vec<String>> {
    match gpu {
        Some(gpu)
            if gpu.count.is_some_and(|count| count > 0) && !driver_config_device_ids.is_empty() =>
        {
            Some(driver_config_device_ids.to_vec())
        }
        Some(_) if driver_config_device_ids.is_empty() => {
            Some(vec![CDI_GPU_DEVICE_ALL.to_string()])
        }
        Some(_) => Some(vec![CDI_GPU_DEVICE_ALL.to_string()]),
        None => None,
    }
}

/// Validate that explicit driver GPU device IDs line up with the portable GPU count.
pub fn validate_gpu_device_ids_count(
    gpu: Option<&DriverGpuResourceRequirement>,
    gpu_device_ids: &[String],
) -> Result<(), String> {
    if gpu_device_ids.is_empty() {
        return Ok(());
    }

    let Some(count) = gpu.and_then(|gpu| gpu.count) else {
        return Err(
            "template.driver_config.gpu_device_ids requires resource_requirements.gpu.count"
                .to_string(),
        );
    };
    if count == 0 {
        return Err("resource_requirements.gpu.count must be greater than 0".to_string());
    }

    let unique = gpu_device_ids.iter().collect::<HashSet<_>>().len();
    if unique != gpu_device_ids.len() {
        return Err(
            "template.driver_config.gpu_device_ids must not contain duplicates".to_string(),
        );
    }
    if unique != count as usize {
        return Err(
            "template.driver_config.gpu_device_ids unique entry count must equal resource_requirements.gpu.count"
                .to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdi_gpu_device_ids_returns_none_when_absent() {
        assert_eq!(cdi_gpu_device_ids(None, &[]), None);
    }

    #[test]
    fn cdi_gpu_device_ids_defaults_empty_request_to_all_gpus() {
        let request = DriverGpuResourceRequirement { count: None };

        assert_eq!(
            cdi_gpu_device_ids(Some(&request), &[]),
            Some(vec![CDI_GPU_DEVICE_ALL.to_string()])
        );
    }

    #[test]
    fn cdi_gpu_device_ids_passes_single_device_id_through() {
        let request = DriverGpuResourceRequirement { count: Some(1) };
        let device_ids = vec!["nvidia.com/gpu=0".to_string()];

        assert_eq!(
            cdi_gpu_device_ids(Some(&request), &device_ids),
            Some(vec!["nvidia.com/gpu=0".to_string()])
        );
    }

    #[test]
    fn cdi_gpu_device_ids_passes_multiple_device_ids_through() {
        let request = DriverGpuResourceRequirement { count: Some(2) };
        let device_ids = vec![
            "nvidia.com/gpu=0".to_string(),
            "nvidia.com/gpu=1".to_string(),
        ];

        assert_eq!(
            cdi_gpu_device_ids(Some(&request), &device_ids),
            Some(vec![
                "nvidia.com/gpu=0".to_string(),
                "nvidia.com/gpu=1".to_string()
            ])
        );
    }

    #[test]
    fn cdi_gpu_device_ids_ignores_device_ids_without_count() {
        let request = DriverGpuResourceRequirement { count: None };
        let device_ids = vec!["nvidia.com/gpu=0".to_string()];

        assert_eq!(
            cdi_gpu_device_ids(Some(&request), &device_ids),
            Some(vec![CDI_GPU_DEVICE_ALL.to_string()])
        );
    }

    #[test]
    fn cdi_gpu_device_ids_ignores_device_ids_with_zero_count() {
        let request = DriverGpuResourceRequirement { count: Some(0) };
        let device_ids = vec!["nvidia.com/gpu=0".to_string()];

        assert_eq!(
            cdi_gpu_device_ids(Some(&request), &device_ids),
            Some(vec![CDI_GPU_DEVICE_ALL.to_string()])
        );
    }

    #[test]
    fn validate_gpu_device_ids_count_requires_gpu_count() {
        let request = DriverGpuResourceRequirement { count: None };
        let device_ids = vec!["nvidia.com/gpu=0".to_string()];

        assert!(validate_gpu_device_ids_count(Some(&request), &device_ids).is_err());
    }

    #[test]
    fn validate_gpu_device_ids_count_rejects_zero_count() {
        let request = DriverGpuResourceRequirement { count: Some(0) };
        let device_ids = vec!["nvidia.com/gpu=0".to_string()];

        assert!(validate_gpu_device_ids_count(Some(&request), &device_ids).is_err());
    }

    #[test]
    fn validate_gpu_device_ids_count_accepts_matching_unique_ids() {
        let request = DriverGpuResourceRequirement { count: Some(2) };
        let device_ids = vec![
            "nvidia.com/gpu=0".to_string(),
            "nvidia.com/gpu=1".to_string(),
        ];

        validate_gpu_device_ids_count(Some(&request), &device_ids).unwrap();
    }

    #[test]
    fn validate_gpu_device_ids_count_rejects_duplicate_ids() {
        let request = DriverGpuResourceRequirement { count: Some(1) };
        let device_ids = vec![
            "nvidia.com/gpu=0".to_string(),
            "nvidia.com/gpu=0".to_string(),
        ];

        assert!(validate_gpu_device_ids_count(Some(&request), &device_ids).is_err());
    }

    #[test]
    fn validate_gpu_device_ids_count_rejects_count_mismatch() {
        let request = DriverGpuResourceRequirement { count: Some(2) };
        let device_ids = vec!["nvidia.com/gpu=0".to_string()];

        assert!(validate_gpu_device_ids_count(Some(&request), &device_ids).is_err());
    }
}
