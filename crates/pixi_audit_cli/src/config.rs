//! Workspace manifest discovery and `[tool.pixi-audit]` configuration.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use miette::{Context, IntoDiagnostic, miette};
use pixi_audit::SeverityBand;
use serde::Deserialize;

/// Persistent audit configuration from `[tool.pixi-audit]`.
#[derive(Debug, Default, PartialEq)]
pub struct AuditConfig {
    pub ignore: Vec<String>,
    pub ignore_until_fixed: Vec<String>,
    pub severity: Option<SeverityBand>,
}

/// The `[tool.pixi-audit]` table as written. Keys this tool does not know
/// are collected rather than rejected, so a newer config still loads under
/// an older binary, with a warning.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
struct RawConfig {
    ignore: Vec<String>,
    ignore_until_fixed: Vec<String>,
    severity: Option<String>,
    #[serde(flatten)]
    unknown: BTreeMap<String, toml::Value>,
}

/// Reads and parses `path` as TOML, naming the file in either error.
fn read_toml(path: &Path) -> miette::Result<toml::Value> {
    let content = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read '{}'", path.display()))?;
    toml::from_str(&content)
        .into_diagnostic()
        .wrap_err_with(|| format!("'{}' is not valid TOML", path.display()))
}

/// The workspace manifest in `dir`: `pixi.toml`, or `pyproject.toml` that
/// contains a `[tool.pixi]` table.
///
/// A `pyproject.toml` that exists but cannot be read or parsed as TOML is
/// an error naming the file — silently skipping it as "not a manifest"
/// could let discovery walk past the intended workspace to an ancestor,
/// or drop an explicit lockfile's sibling config. A `pyproject.toml`
/// that parses fine but has no `[tool.pixi]` table is `Ok(None)`.
pub fn find_manifest_in(dir: &Path) -> miette::Result<Option<PathBuf>> {
    let pixi = dir.join("pixi.toml");
    if pixi.is_file() {
        return Ok(Some(pixi));
    }
    let pyproject = dir.join("pyproject.toml");
    if pyproject.is_file() {
        let value = read_toml(&pyproject)?;
        if value.get("tool").and_then(|t| t.get("pixi")).is_some() {
            return Ok(Some(pyproject));
        }
    }
    Ok(None)
}

/// Walks up from `start` to the first directory containing a workspace
/// manifest and returns the manifest path.
pub fn discover_workspace(start: &Path) -> miette::Result<Option<PathBuf>> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        if let Some(manifest) = find_manifest_in(current)? {
            return Ok(Some(manifest));
        }
        dir = current.parent();
    }
    Ok(None)
}

/// Parses `[tool.pixi-audit]` from `manifest`. A missing table is an empty
/// config; a present-but-invalid table is an error — a security tool must
/// not silently drop configured suppressions. Unknown keys warn on stderr.
pub fn load_config(manifest: &Path) -> miette::Result<AuditConfig> {
    let value = read_toml(manifest)?;
    let Some(table) = value.get("tool").and_then(|t| t.get("pixi-audit")) else {
        return Ok(AuditConfig::default());
    };
    let raw: RawConfig = table
        .clone()
        .try_into()
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "invalid [tool.pixi-audit] table in '{}'",
                manifest.display()
            )
        })?;

    for key in raw.unknown.keys() {
        eprintln!(
            "warning: unrecognized key '{key}' in [tool.pixi-audit] of '{}'",
            manifest.display()
        );
    }

    let severity = raw
        .severity
        .as_deref()
        .map(parse_band)
        .transpose()
        .map_err(|err| {
            miette!(
                "invalid severity in [tool.pixi-audit] of '{}': {err}",
                manifest.display()
            )
        })?;

    Ok(AuditConfig {
        ignore: raw.ignore,
        ignore_until_fixed: raw.ignore_until_fixed,
        severity,
    })
}

/// Parses a severity threshold. Shared by clap's value parser and the
/// config file, so both accept exactly the same values.
pub fn parse_band(s: &str) -> Result<SeverityBand, String> {
    match s.parse::<SeverityBand>() {
        // "unknown" is a valid band but never a threshold: it must always
        // fail the audit, so it cannot be opted into.
        Ok(SeverityBand::Unknown) | Err(_) => Err(format!(
            "'{s}' is not a severity band (expected low, medium, high, or critical)"
        )),
        Ok(band) => Ok(band),
    }
}

#[cfg(test)]
mod tests;
