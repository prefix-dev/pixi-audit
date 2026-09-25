//! Workspace manifest discovery and `[tool.pixi-audit]` configuration.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use jiff::civil::Date;
use miette::{Context, IntoDiagnostic, miette};
use pixi_audit::{IgnoreScope, PackageIgnore, SeverityBand};
use serde::Deserialize;

/// Persistent audit configuration from `[tool.pixi-audit]`, with expired
/// ignore rules already dropped.
#[derive(Debug, Default, PartialEq)]
pub struct AuditConfig {
    /// Ids from `ignore` that name no package.
    pub ignore: Vec<String>,
    /// Ids from `ignore-until-fixed` that name no package.
    pub ignore_until_fixed: Vec<String>,
    /// Entries of either list that name a package.
    pub package_rules: Vec<PackageIgnore>,
    /// Suppress every finding without a known fix until one is published.
    pub ignore_unfixed: bool,
    pub severity: Option<SeverityBand>,
}

/// The `[tool.pixi-audit]` table as written. Keys this tool does not know
/// are collected rather than rejected, so a newer config still loads under
/// an older binary, with a warning.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
struct RawConfig {
    ignore: Vec<IgnoreEntry>,
    ignore_until_fixed: Vec<IgnoreEntry>,
    ignore_unfixed: bool,
    severity: Option<String>,
    #[serde(flatten)]
    unknown: BTreeMap<String, toml::Value>,
}

/// One entry of an ignore list as written: a bare id, or a table naming
/// an id and/or a package, with why it is ignored and, optionally, until
/// when.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum IgnoreEntry {
    Id(String),
    Rule(IgnoreRule),
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreRule {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(flatten)]
    pub scope: IgnoreScope,
    #[serde(default)]
    pub reason: Option<String>,
    /// The last day the rule applies, as a TOML date or a `YYYY-MM-DD`
    /// string. Validated when the config is resolved.
    #[serde(default)]
    pub until: Option<toml::Value>,
}

/// What an ignore-list entry suppresses, with its expiry resolved.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ResolvedIgnore {
    pub id: Option<String>,
    pub scope: IgnoreScope,
}

impl std::fmt::Display for ResolvedIgnore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.id, &self.scope.package) {
            (Some(id), Some(package)) => write!(f, "'{id}' in package '{package}'"),
            (Some(id), None) => write!(f, "'{id}'"),
            (None, Some(package)) => write!(f, "package '{package}'"),
            (None, None) => f.write_str("(empty rule)"),
        }
    }
}

impl IgnoreEntry {
    /// What the entry suppresses. An entry naming neither an id nor a
    /// package would suppress everything, so it is rejected.
    fn resolved(&self) -> Result<ResolvedIgnore, String> {
        match self {
            IgnoreEntry::Id(id) => Ok(ResolvedIgnore {
                id: Some(id.clone()),
                scope: IgnoreScope::default(),
            }),
            IgnoreEntry::Rule(IgnoreRule {
                id: None,
                scope: IgnoreScope { package: None, .. },
                ..
            }) => Err("an ignore rule needs an 'id' or a 'package'".to_string()),
            IgnoreEntry::Rule(rule) => Ok(ResolvedIgnore {
                id: rule.id.clone(),
                scope: rule.scope.clone(),
            }),
        }
    }

    /// The rule's expiry, if it has one.
    fn until(&self) -> Result<Option<Date>, String> {
        let IgnoreEntry::Rule(IgnoreRule {
            until: Some(until), ..
        }) = self
        else {
            return Ok(None);
        };
        let text = match until {
            toml::Value::Datetime(datetime) => datetime.to_string(),
            toml::Value::String(text) => text.clone(),
            other => return Err(format!("'{other}' is not a date")),
        };
        text.trim()
            .parse::<Date>()
            .map(Some)
            .map_err(|err| format!("'{text}' is not a date (expected YYYY-MM-DD): {err}"))
    }
}

/// An ignore rule whose expiry has passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredIgnore {
    pub rule: ResolvedIgnore,
    pub until: Date,
}

/// Splits `entries` into the rules that still apply on `today` and the
/// rules that expired. A rule applies through its `until` day inclusive.
pub fn effective_ignores(
    entries: &[IgnoreEntry],
    today: Date,
) -> Result<(Vec<ResolvedIgnore>, Vec<ExpiredIgnore>), String> {
    let mut active = Vec::new();
    let mut expired = Vec::new();
    for entry in entries {
        let rule = entry.resolved()?;
        rule.scope.validate()?;
        match entry.until()? {
            Some(until) if until < today => expired.push(ExpiredIgnore { rule, until }),
            Some(_) | None => active.push(rule),
        }
    }
    Ok((active, expired))
}

/// Today's date in UTC, the reference for ignore rule expiry.
pub fn today() -> Date {
    jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .date()
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
    let mut value = read_toml(manifest)?;
    let table = value
        .get_mut("tool")
        .and_then(toml::Value::as_table_mut)
        .and_then(|tool| tool.remove("pixi-audit"));
    let Some(table) = table else {
        return Ok(AuditConfig::default());
    };
    let raw: RawConfig = table.try_into().into_diagnostic().wrap_err_with(|| {
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

    let today = today();
    let mut config = AuditConfig {
        severity,
        ignore_unfixed: raw.ignore_unfixed,
        ..AuditConfig::default()
    };
    for (key, entries, until_fixed) in [
        ("ignore", &raw.ignore, false),
        ("ignore-until-fixed", &raw.ignore_until_fixed, true),
    ] {
        let (active, expired) = effective_ignores(entries, today).map_err(|err| {
            miette!(
                "invalid '{key}' entry in [tool.pixi-audit] of '{}': {err}",
                manifest.display()
            )
        })?;
        for expired in expired {
            eprintln!(
                "warning: ignore rule {} in [tool.pixi-audit] of '{}' expired on {} and no longer applies",
                expired.rule,
                manifest.display(),
                expired.until
            );
        }
        for rule in active {
            match rule {
                ResolvedIgnore {
                    id: Some(id),
                    scope,
                } if scope.is_empty() => {
                    if until_fixed {
                        config.ignore_until_fixed.push(id);
                    } else {
                        config.ignore.push(id);
                    }
                }
                ResolvedIgnore { id, scope } => config.package_rules.push(PackageIgnore {
                    id,
                    scope,
                    until_fixed,
                }),
            }
        }
    }
    Ok(config)
}

/// Parses a severity threshold. Shared by clap's value parser and the
/// config file, so both accept exactly the same values.
pub fn parse_band(s: &str) -> Result<SeverityBand, String> {
    match s.parse::<SeverityBand>() {
        // "unknown" is a valid band but never a threshold: it must always
        // fail the audit, so it cannot be opted into.
        Ok(SeverityBand::Unknown) | Err(_) => {
            let expected: Vec<&str> = SeverityBand::ALL
                .iter()
                .filter(|band| **band != SeverityBand::Unknown)
                .map(|band| band.name())
                .collect();
            Err(format!(
                "'{s}' is not a severity band (expected one of {})",
                expected.join(", ")
            ))
        }
        Ok(band) => Ok(band),
    }
}

#[cfg(test)]
mod tests;
