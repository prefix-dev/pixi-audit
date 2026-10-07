//! `[tool.pixi-audit]` configuration.

use std::collections::BTreeMap;
use std::path::Path;

use jiff::civil::Date;
use miette::{Context, IntoDiagnostic, miette};
use pixi_audit::{IgnoreRule, IgnoreScope, SeverityBand};
use serde::{Deserialize, Serialize, de::IntoDeserializer};
use toml_edit::Item;

use crate::workspace::Manifest;

/// Persistent audit configuration from `[tool.pixi-audit]`, with expired
/// ignore rules already dropped.
#[derive(Debug, Default, PartialEq)]
pub struct AuditConfig {
    /// Active rules from both ignore lists, in their original spelling.
    pub rules: Vec<IgnoreRule>,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IgnoreEntry {
    Id(String),
    Rule(IgnoreTable),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreTable {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(flatten)]
    pub scope: IgnoreScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The last day the rule applies, as a TOML date or a `YYYY-MM-DD`
    /// string. Validated when the config is resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<toml::Value>,
}

impl IgnoreEntry {
    /// What the entry suppresses. An entry naming neither an id nor a
    /// package would suppress everything, so it is rejected.
    pub fn resolved(&self, until_fixed: bool) -> Result<IgnoreRule, String> {
        match self {
            IgnoreEntry::Id(id) => Ok(IgnoreRule::from_id(id.clone(), until_fixed)),
            IgnoreEntry::Rule(IgnoreTable {
                id: None,
                scope: IgnoreScope { package: None, .. },
                ..
            }) => Err("an ignore rule needs an 'id' or a 'package'".to_string()),
            IgnoreEntry::Rule(rule) => {
                IgnoreRule::new(rule.id.clone(), rule.scope.clone(), until_fixed)
                    .map_err(|error| error.to_string())
            }
        }
    }

    /// The rule's expiry, if it has one.
    fn until(&self) -> Result<Option<Date>, String> {
        let IgnoreEntry::Rule(IgnoreTable {
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
    pub rule: IgnoreRule,
    pub until: Date,
}

/// Splits `entries` into the rules that still apply on `today` and the
/// rules that expired. A rule applies through its `until` day inclusive.
pub fn effective_ignores(
    entries: &[IgnoreEntry],
    today: Date,
    until_fixed: bool,
) -> Result<(Vec<IgnoreRule>, Vec<ExpiredIgnore>), String> {
    let mut active = Vec::new();
    let mut expired = Vec::new();
    for entry in entries {
        let rule = entry.resolved(until_fixed)?;
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

/// Parses `[tool.pixi-audit]` from `manifest`. A missing table is an empty
/// config; a present-but-invalid table is an error — a security tool must
/// not silently drop configured suppressions. Unknown keys warn on stderr.
pub fn load_config(manifest: &Path) -> miette::Result<AuditConfig> {
    let mut manifest = Manifest::load(manifest)?;
    let table = manifest
        .document
        .get_mut("tool")
        .and_then(Item::as_table_like_mut)
        .and_then(|tool| tool.remove("pixi-audit"));
    let Some(table) = table else {
        return Ok(AuditConfig::default());
    };
    let table = table.into_value().expect("parsed TOML items have a value");
    let raw = RawConfig::deserialize(table.into_deserializer())
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "invalid [tool.pixi-audit] table in '{}'",
                manifest.path.display()
            )
        })?;

    for key in raw.unknown.keys() {
        eprintln!(
            "warning: unrecognized key '{key}' in [tool.pixi-audit] of '{}'",
            manifest.path.display()
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
                manifest.path.display()
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
        let (active, expired) = effective_ignores(entries, today, until_fixed).map_err(|err| {
            miette!(
                "invalid '{key}' entry in [tool.pixi-audit] of '{}': {err}",
                manifest.path.display()
            )
        })?;
        for expired in expired {
            eprintln!(
                "warning: ignore rule {} in [tool.pixi-audit] of '{}' expired on {} and no longer applies",
                expired.rule,
                manifest.path.display(),
                expired.until
            );
        }
        config.rules.extend(active);
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
