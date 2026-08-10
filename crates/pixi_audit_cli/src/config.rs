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
    match s {
        "low" => Ok(SeverityBand::Low),
        "medium" => Ok(SeverityBand::Medium),
        "high" => Ok(SeverityBand::High),
        "critical" => Ok(SeverityBand::Critical),
        other => Err(format!(
            "'{other}' is not a severity band (expected low, medium, high, or critical)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn parses_full_table_from_pixi_toml() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write(
            dir.path(),
            "pixi.toml",
            r#"
[workspace]
name = "demo"

[tool.pixi-audit]
ignore = ["CVE-1"]
ignore-until-fixed = ["CVE-2"]
severity = "high"
"#,
        );
        let config = load_config(&manifest).unwrap();
        assert_eq!(config.ignore, vec!["CVE-1"]);
        assert_eq!(config.ignore_until_fixed, vec!["CVE-2"]);
        assert_eq!(config.severity, Some(SeverityBand::High));
    }

    #[test]
    fn accepts_toml_1_1_multiline_inline_tables() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write(
            dir.path(),
            "pixi.toml",
            r#"
[workspace]
name = "demo"

[tasks]
insta-review = {
    cmd = "cargo insta review",
    depends-on = ["test"],
}

[tool.pixi-audit]
severity = "high"
"#,
        );
        let config = load_config(&manifest).unwrap();
        assert_eq!(config.severity, Some(SeverityBand::High));
    }

    #[test]
    fn missing_table_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write(dir.path(), "pixi.toml", "[workspace]\nname = \"demo\"\n");
        let config = load_config(&manifest).unwrap();
        assert!(config.ignore.is_empty());
        assert!(config.ignore_until_fixed.is_empty());
        assert_eq!(config.severity, None);
    }

    #[test]
    fn invalid_severity_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write(
            dir.path(),
            "pixi.toml",
            "[tool.pixi-audit]\nseverity = \"severe\"\n",
        );
        assert!(load_config(&manifest).is_err());
    }

    #[test]
    fn wrong_type_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write(
            dir.path(),
            "pixi.toml",
            "[tool.pixi-audit]\nignore = \"CVE-1\"\n",
        );
        assert!(load_config(&manifest).is_err());
    }

    #[test]
    fn unparsable_toml_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write(dir.path(), "pixi.toml", "not toml [");
        assert!(load_config(&manifest).is_err());
    }

    #[test]
    fn pyproject_with_tool_pixi_is_a_manifest() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "pyproject.toml",
            "[tool.pixi]\n[tool.pixi-audit]\nignore = [\"CVE-9\"]\n",
        );
        let manifest = find_manifest_in(dir.path()).unwrap().unwrap();
        assert!(manifest.ends_with("pyproject.toml"));
        assert_eq!(load_config(&manifest).unwrap().ignore, vec!["CVE-9"]);
    }

    #[test]
    fn pyproject_without_tool_pixi_is_not_a_manifest() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "pyproject.toml", "[project]\nname = \"x\"\n");
        assert_eq!(find_manifest_in(dir.path()).unwrap(), None);
    }

    #[test]
    fn unparsable_pyproject_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "pyproject.toml", "not toml [");
        assert!(find_manifest_in(dir.path()).is_err());
    }

    #[test]
    fn pixi_toml_wins_over_pyproject() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "pixi.toml", "[workspace]\n");
        write(dir.path(), "pyproject.toml", "[tool.pixi]\n");
        assert!(
            find_manifest_in(dir.path())
                .unwrap()
                .unwrap()
                .ends_with("pixi.toml")
        );
    }

    #[test]
    fn pixi_toml_wins_over_pyproject_even_if_pyproject_is_unparsable() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "pixi.toml", "[workspace]\n");
        write(dir.path(), "pyproject.toml", "not toml [");
        assert!(
            find_manifest_in(dir.path())
                .unwrap()
                .unwrap()
                .ends_with("pixi.toml")
        );
    }

    #[test]
    fn discovery_walks_up_to_the_workspace_root() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "pixi.toml", "[workspace]\n");
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let manifest = discover_workspace(&nested).unwrap().unwrap();
        assert!(manifest.ends_with("pixi.toml"));
        assert_eq!(manifest.parent().unwrap(), dir.path());
    }

    #[test]
    fn discovery_fails_outside_any_workspace() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(discover_workspace(dir.path()).unwrap(), None);
    }

    #[test]
    fn discovery_errors_on_unparsable_pyproject_along_the_way() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "pyproject.toml", "not toml [");
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        assert!(discover_workspace(&nested).is_err());
    }

    #[test]
    fn parse_band_accepts_the_four_bands_only() {
        assert_eq!(parse_band("low").unwrap(), SeverityBand::Low);
        assert_eq!(parse_band("medium").unwrap(), SeverityBand::Medium);
        assert_eq!(parse_band("high").unwrap(), SeverityBand::High);
        assert_eq!(parse_band("critical").unwrap(), SeverityBand::Critical);
        assert!(parse_band("unknown").is_err());
        assert!(parse_band("HIGH").is_err());
    }
}
