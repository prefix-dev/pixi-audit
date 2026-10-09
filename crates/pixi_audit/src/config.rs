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
    pub fail_on: Option<String>,
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
    #[serde(
        default,
        rename = "expired-at",
        skip_serializing_if = "Option::is_none"
    )]
    pub expired_at: Option<toml::Value>,
}

impl IgnoreEntry {
    /// What the entry ignores. An entry naming neither an id nor a
    /// package would ignore everything, so it is rejected.
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
    fn expired_at(&self) -> Result<Option<Date>, String> {
        let IgnoreEntry::Rule(IgnoreTable {
            expired_at: Some(expired_at),
            ..
        }) = self
        else {
            return Ok(None);
        };
        let text = match expired_at {
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
    pub expired_at: Date,
}

/// Splits `entries` into the rules that still apply on `today` and the
/// rules that expired. A rule applies through its `expired-at` day inclusive.
pub fn effective_ignores(
    entries: &[IgnoreEntry],
    today: Date,
    until_fixed: bool,
) -> Result<(Vec<IgnoreRule>, Vec<ExpiredIgnore>), String> {
    let mut active = Vec::new();
    let mut expired = Vec::new();
    for entry in entries {
        let rule = entry.resolved(until_fixed)?;
        match entry.expired_at()? {
            Some(expired_at) if expired_at < today => {
                expired.push(ExpiredIgnore { rule, expired_at })
            }
            Some(_) | None => active.push(rule),
        }
    }
    Ok((active, expired))
}

/// The two ignore lists of `[tool.pixi-audit]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreList {
    Permanent,
    UntilFixed,
}

impl IgnoreList {
    pub fn key(self) -> &'static str {
        match self {
            Self::Permanent => "ignore",
            Self::UntilFixed => "ignore-until-fixed",
        }
    }

    pub fn until_fixed(self) -> bool {
        matches!(self, Self::UntilFixed)
    }
}

impl AuditConfig {
    /// Ignore lists in manifest order, with their ignore mode.
    pub fn ignore_lists(&self) -> [(IgnoreList, &[IgnoreEntry]); 2] {
        [
            (IgnoreList::Permanent, &self.ignore),
            (IgnoreList::UntilFixed, &self.ignore_until_fixed),
        ]
    }
}

#[cfg(test)]
mod tests;
