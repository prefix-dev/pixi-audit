//! Reusable `[tool.pixi-audit]` configuration and ignore-rule schema.

use std::collections::BTreeMap;

use jiff::civil::Date;
use serde::{Deserialize, Serialize};

use crate::{IgnoreRule, IgnoreScope};

/// The `[tool.pixi-audit]` table as written. Keys this tool does not know
/// are collected rather than rejected, so a newer config still loads under
/// an older binary, with a warning.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct AuditConfig {
    pub ignore: Vec<IgnoreEntry>,
    pub ignore_until_fixed: Vec<IgnoreEntry>,
    pub ignore_unfixed: bool,
    pub severity: Option<String>,
    #[serde(flatten)]
    pub unknown: BTreeMap<String, toml::Value>,
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

/// The two ignore lists of `[tool.pixi-audit]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreList {
    Always,
    UntilFixed,
}

impl IgnoreList {
    pub fn key(self) -> &'static str {
        match self {
            Self::Always => "ignore",
            Self::UntilFixed => "ignore-until-fixed",
        }
    }

    pub fn until_fixed(self) -> bool {
        matches!(self, Self::UntilFixed)
    }
}

impl AuditConfig {
    /// Ignore lists in manifest order, with their suppression policy.
    pub fn ignore_lists(&self) -> [(IgnoreList, &[IgnoreEntry]); 2] {
        [
            (IgnoreList::Always, &self.ignore),
            (IgnoreList::UntilFixed, &self.ignore_until_fixed),
        ]
    }
}

#[cfg(test)]
mod tests;
