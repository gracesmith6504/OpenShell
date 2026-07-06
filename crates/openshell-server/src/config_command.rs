// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI handlers for inspecting and updating the gateway TOML configuration.

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::{ArgGroup, Args, Subcommand};
use miette::{IntoDiagnostic, Result, WrapErr};
use tempfile::NamedTempFile;
use toml_edit::{Array, DocumentMut, Item, Table, value};

use crate::{config_file, defaults};

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Detect the compute driver available in the current environment.
    DetectDriver,
    /// Update selected fields in the gateway TOML configuration.
    Set(SetArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("setting")
        .required(true)
        .multiple(true)
        .args(["compute_driver", "gateway_bind_address"])
))]
struct SetArgs {
    /// Select one compute driver, or use `auto` to remove an existing pin.
    #[arg(long, value_name = "DRIVER")]
    compute_driver: Option<String>,

    /// Set the gateway listener socket address.
    #[arg(long = "bind-address", value_name = "IP:PORT")]
    gateway_bind_address: Option<SocketAddr>,
}

pub fn run(args: ConfigArgs, explicit_path: Option<PathBuf>) -> Result<()> {
    match args.command {
        ConfigCommand::DetectDriver => {
            println!(
                "{}",
                detected_driver_name(openshell_core::config::detect_driver())
            );
        }
        ConfigCommand::Set(settings) => {
            let path = explicit_path.map_or_else(defaults::default_gateway_config_path, Ok)?;
            set(&path, &settings)?;
            println!("updated gateway configuration: {}", path.display());
            println!("Restart the gateway service for changes to take effect.");
        }
    }
    Ok(())
}

fn detected_driver_name(driver: Option<openshell_core::ComputeDriverKind>) -> &'static str {
    driver.map_or("none", openshell_core::ComputeDriverKind::as_str)
}

fn set(path: &Path, settings: &SetArgs) -> Result<()> {
    let original = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(err)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read gateway config '{}'", path.display()));
        }
    };

    let mut document = if original.trim().is_empty() {
        DocumentMut::new()
    } else {
        original
            .parse::<DocumentMut>()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to parse gateway config '{}'", path.display()))?
    };

    let openshell = ensure_table(document.as_table_mut(), "openshell")?;
    if !openshell.contains_key("version") {
        openshell.insert("version", value(i64::from(config_file::SCHEMA_VERSION)));
    }
    let gateway = ensure_table(openshell, "gateway")?;

    if let Some(driver) = settings.compute_driver.as_deref() {
        if driver.eq_ignore_ascii_case("auto") {
            gateway.remove("compute_drivers");
        } else {
            let driver = openshell_core::config::normalize_compute_driver_name(driver)
                .map_err(|err| miette::miette!("{err}"))?;
            let mut drivers = Array::new();
            drivers.push(driver);
            gateway.insert("compute_drivers", value(drivers));
        }
    }
    if let Some(bind_address) = settings.gateway_bind_address {
        gateway.insert("bind_address", value(bind_address.to_string()));
    }

    let rendered = document.to_string();
    config_file::parse(&rendered, path).map_err(|err| miette::miette!("{err}"))?;
    write_atomically(path, rendered.as_bytes())
}

fn ensure_table<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table> {
    if !parent.contains_key(key) {
        parent.insert(key, Item::Table(Table::new()));
    }
    parent
        .get_mut(key)
        .and_then(Item::as_table_mut)
        .ok_or_else(|| miette::miette!("gateway config key '{key}' must be a TOML table"))
}

fn write_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        miette::miette!(
            "gateway config path '{}' has no parent directory",
            path.display()
        )
    })?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create config directory '{}'", parent.display()))?;

    let permissions = fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    let mut temp = NamedTempFile::new_in(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create temporary file in '{}'", parent.display()))?;
    temp.write_all(contents)
        .into_diagnostic()
        .wrap_err("failed to write gateway configuration")?;
    temp.as_file()
        .sync_all()
        .into_diagnostic()
        .wrap_err("failed to sync gateway configuration")?;
    if let Some(permissions) = permissions {
        temp.as_file()
            .set_permissions(permissions)
            .into_diagnostic()
            .wrap_err("failed to preserve gateway config permissions")?;
    }
    temp.persist(path)
        .map_err(|err| err.error)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to replace gateway config '{}'", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(driver: Option<&str>, bind_address: Option<&str>) -> SetArgs {
        SetArgs {
            compute_driver: driver.map(str::to_string),
            gateway_bind_address: bind_address.map(|value| value.parse().unwrap()),
        }
    }

    #[test]
    fn detect_driver_output_is_machine_readable() {
        assert_eq!(
            detected_driver_name(Some(openshell_core::ComputeDriverKind::Podman)),
            "podman"
        );
        assert_eq!(
            detected_driver_name(Some(openshell_core::ComputeDriverKind::Docker)),
            "docker"
        );
        assert_eq!(detected_driver_name(None), "none");
    }

    #[test]
    fn set_creates_config_with_driver_and_bind_address() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("openshell/gateway.toml");

        set(&path, &settings(Some("podman"), Some("0.0.0.0:17670"))).unwrap();

        let loaded = config_file::load(&path).unwrap();
        assert_eq!(loaded.openshell.version, Some(config_file::SCHEMA_VERSION));
        assert_eq!(
            loaded.openshell.gateway.compute_drivers,
            Some(vec!["podman".to_string()])
        );
        assert_eq!(
            loaded.openshell.gateway.bind_address,
            Some("0.0.0.0:17670".parse().unwrap())
        );
    }

    #[test]
    fn set_preserves_comments_and_unrelated_settings() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        fs::write(
            &path,
            "# keep this comment\n[openshell]\nversion = 1\n\n[openshell.gateway]\nlog_level = \"debug\"\ncompute_drivers = [\"docker\"]\n",
        )
        .unwrap();

        set(&path, &settings(Some("podman"), None)).unwrap();

        let updated = fs::read_to_string(&path).unwrap();
        assert!(updated.contains("# keep this comment"));
        assert!(updated.contains("log_level = \"debug\""));
        let loaded = config_file::load(&path).unwrap();
        assert_eq!(
            loaded.openshell.gateway.compute_drivers,
            Some(vec!["podman".to_string()])
        );
    }

    #[test]
    fn auto_removes_driver_without_changing_bind_address() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        fs::write(
            &path,
            "[openshell]\nversion = 1\n\n[openshell.gateway]\nbind_address = \"0.0.0.0:17670\"\ncompute_drivers = [\"podman\"]\n",
        )
        .unwrap();

        set(&path, &settings(Some("auto"), None)).unwrap();

        let loaded = config_file::load(&path).unwrap();
        assert_eq!(loaded.openshell.gateway.compute_drivers, None);
        assert_eq!(
            loaded.openshell.gateway.bind_address,
            Some("0.0.0.0:17670".parse().unwrap())
        );
    }

    #[test]
    fn invalid_existing_config_is_not_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        let original = "[openshell\ninvalid";
        fs::write(&path, original).unwrap();

        let error = set(&path, &settings(Some("docker"), None)).unwrap_err();

        assert!(error.to_string().contains("failed to parse gateway config"));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn schema_validation_failure_is_not_written() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        let original = "[openshell]\nversion = 999\n";
        fs::write(&path, original).unwrap();

        let error = set(&path, &settings(Some("docker"), None)).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("unsupported gateway config version")
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn invalid_driver_name_is_not_written() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        let original = "[openshell]\nversion = 1\n";
        fs::write(&path, original).unwrap();

        let error = set(&path, &settings(Some("bad/name"), None)).unwrap_err();

        assert!(error.to_string().contains("invalid compute driver name"));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }
}
