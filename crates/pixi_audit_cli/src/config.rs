//! `[tool.pixi-audit]` configuration.

use std::path::Path;

use jiff::civil::Date;
use miette::{Context, IntoDiagnostic, miette};
use pixi_audit::{
    IgnoreRule, SeverityBand,
    config::{AuditConfig as ManifestConfig, effective_ignores},
};
use serde::{Deserialize, de::IntoDeserializer};
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
    let raw = ManifestConfig::deserialize(table.into_deserializer())
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
    for (list, entries) in raw.ignore_lists() {
        let key = list.key();
        let until_fixed = list.until_fixed();
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
