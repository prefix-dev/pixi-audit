//! Workspace manifest discovery and `[tool.pixi-audit]` configuration.

use std::path::{Path, PathBuf};

use miette::{Context, IntoDiagnostic, miette};
use pixi_audit::SeverityBand;

/// Persistent audit configuration from `[tool.pixi-audit]`.
#[derive(Debug, Default, PartialEq)]
pub struct AuditConfig {
    pub ignore: Vec<String>,
    pub ignore_until_fixed: Vec<String>,
    pub severity: Option<SeverityBand>,
}

const KNOWN_KEYS: &[&str] = &["ignore", "ignore-until-fixed", "severity"];

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
        let content = std::fs::read_to_string(&pyproject)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read '{}'", pyproject.display()))?;
        let value: toml::Value = toml::from_str(&content)
            .into_diagnostic()
            .wrap_err_with(|| format!("'{}' is not valid TOML", pyproject.display()))?;
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
    let content = std::fs::read_to_string(manifest)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read '{}'", manifest.display()))?;
    let value: toml::Value = toml::from_str(&content)
        .into_diagnostic()
        .wrap_err_with(|| format!("'{}' is not valid TOML", manifest.display()))?;

    let Some(table) = value.get("tool").and_then(|t| t.get("pixi-audit")) else {
        return Ok(AuditConfig::default());
    };
    let table = table.as_table().ok_or_else(|| {
        miette!(
            "[tool.pixi-audit] in '{}' must be a table",
            manifest.display()
        )
    })?;

    for key in table.keys() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            eprintln!(
                "warning: unrecognized key '{key}' in [tool.pixi-audit] of '{}'",
                manifest.display()
            );
        }
    }

    let string_list = |key: &str| -> miette::Result<Vec<String>> {
        match table.get(key) {
            None => Ok(Vec::new()),
            Some(value) => value
                .as_array()
                .and_then(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().map(str::to_string))
                        .collect::<Option<Vec<_>>>()
                })
                .ok_or_else(|| {
                    miette!(
                        "'{key}' in [tool.pixi-audit] of '{}' must be an array of strings",
                        manifest.display()
                    )
                }),
        }
    };

    let severity = match table.get("severity") {
        None => None,
        Some(value) => {
            let text = value.as_str().ok_or_else(|| {
                miette!(
                    "'severity' in [tool.pixi-audit] of '{}' must be a string",
                    manifest.display()
                )
            })?;
            Some(parse_band(text).map_err(|err| {
                miette!(
                    "invalid severity in [tool.pixi-audit] of '{}': {err}",
                    manifest.display()
                )
            })?)
        }
    };

    Ok(AuditConfig {
        ignore: string_list("ignore")?,
        ignore_until_fixed: string_list("ignore-until-fixed")?,
        severity,
    })
}

/// Parses a severity band name. Shared by clap's value parser and the
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
