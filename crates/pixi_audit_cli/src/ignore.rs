//! `pixi audit ignore`: records ignore rules in the workspace manifest's
//! `[tool.pixi-audit]` table, so a suppression lives next to the code it
//! covers instead of in a CI script.

use std::path::PathBuf;

use clap::Args;
use jiff::civil::Date;
use miette::{Context, IntoDiagnostic, miette};
use pixi_audit::{
    IgnoreRule, IgnoreScope,
    config::{IgnoreEntry, IgnoreList, IgnoreTable},
};
use serde::{Deserialize, Serialize, de::IntoDeserializer};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

use crate::{
    config,
    workspace::{self, Manifest},
};

#[derive(Debug, Args)]
pub struct IgnoreArgs {
    /// Vulnerability ids or aliases to ignore. With --package, only in
    /// that package; without any id, --package ignores the whole package.
    #[arg(required_unless_present = "package", value_name = "ID")]
    pub ids: Vec<String>,

    /// Limit the rule to this package, or ignore every finding in it
    #[arg(long, value_name = "NAME")]
    pub package: Option<String>,
    /// Match findings from this ecosystem (conda-forge or PyPI)
    #[arg(long, value_name = "ECOSYSTEM")]
    pub ecosystem: Option<String>,

    /// Match only this installed version
    #[arg(long, value_name = "VERSION")]
    pub version: Option<String>,

    /// Match installed versions no newer than this one
    #[arg(long, value_name = "VERSION")]
    pub max_affected_version: Option<String>,

    /// Ignore only while no fixed release is known
    #[arg(long)]
    pub until_fixed: bool,

    /// Why the finding is ignored; recorded next to the id
    #[arg(long, value_name = "TEXT")]
    pub reason: Option<String>,

    /// Last day the rule applies (YYYY-MM-DD). After it the audit reports
    /// the finding again and warns about the expired rule.
    #[arg(long, value_name = "DATE", value_parser = parse_date)]
    pub until: Option<Date>,

    /// Manifest to edit. Discovered from the current directory when
    /// omitted.
    #[arg(long, value_name = "PATH")]
    pub manifest: Option<PathBuf>,
}

fn parse_date(text: &str) -> Result<Date, String> {
    text.parse::<Date>()
        .map_err(|err| format!("'{text}' is not a date (expected YYYY-MM-DD): {err}"))
}

pub fn run(args: IgnoreArgs) -> miette::Result<()> {
    if let Some(until) = args.until
        && until < config::today()
    {
        return Err(miette!("--until {until} is in the past"));
    }
    let mut manifest = match args.manifest {
        Some(path) => Manifest::load(&path)?,
        None => {
            let cwd = std::env::current_dir()
                .into_diagnostic()
                .wrap_err("cannot determine the current directory")?;
            let path = workspace::discover_workspace(&cwd)?.ok_or_else(|| {
                miette!("no pixi workspace found; pass --manifest or run inside a pixi workspace")
            })?;
            Manifest::load(&path)?
        }
    };

    let list = if args.until_fixed {
        IgnoreList::UntilFixed
    } else {
        IgnoreList::Always
    };
    let scope = IgnoreScope {
        package: args.package,
        ecosystem: args.ecosystem,
        version: args.version,
        max_affected_version: args.max_affected_version,
    };
    let outcome = add_rules(
        &mut manifest.document,
        list,
        &args.ids,
        &scope,
        args.reason.as_deref(),
        args.until,
    )?;
    if !outcome.added.is_empty() {
        manifest.save()?;
    }

    for rule in &outcome.added {
        eprintln!(
            "Ignoring {rule}{} in '{}'",
            match list {
                IgnoreList::Always => "",
                IgnoreList::UntilFixed => " until a fix is released",
            },
            manifest.path.display()
        );
    }
    for rule in &outcome.existing {
        eprintln!(
            "note: {rule} is already listed under '{}' in [tool.pixi-audit] of '{}'",
            list.key(),
            manifest.path.display()
        );
    }
    Ok(())
}

/// Which rules a call recorded and which were already listed, as labels
/// such as `CVE-1`, `package 'x'`, or `CVE-1 in package 'x'`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub added: Vec<String>,
    pub existing: Vec<String>,
}

/// What one rule suppresses, with identifiers lowercased for comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleKey {
    id: Option<String>,
    scope: IgnoreScope,
}

impl RuleKey {
    fn new(id: Option<&str>, scope: &IgnoreScope) -> Self {
        Self {
            id: id.map(str::to_lowercase),
            scope: IgnoreScope {
                package: scope.package.as_deref().map(str::to_lowercase),
                ecosystem: scope.ecosystem.as_deref().map(str::to_lowercase),
                ..scope.clone()
            },
        }
    }
}

/// Appends a rule for each of `ids` to `list` in `document`, or one rule
/// for the whole scoped package when no id is given, creating the
/// `[tool.pixi-audit]` table and the list as needed. Rules already listed,
/// with case-insensitive identifiers and exact version strings, are left
/// alone and reported as existing.
/// Formatting and comments elsewhere in the document are untouched.
pub fn add_rules(
    document: &mut DocumentMut,
    list: IgnoreList,
    ids: &[String],
    scope: &IgnoreScope,
    reason: Option<&str>,
    until: Option<Date>,
) -> miette::Result<Outcome> {
    scope.validate().map_err(|error| miette!("{error}"))?;
    if ids.is_empty() && scope.package.is_none() {
        return Err(miette!("an ignore rule needs an id or a package"));
    }
    let table = audit_table(document)?;
    let item = table
        .entry(list.key())
        .or_insert_with(|| Item::Value(Value::Array(Array::new())));
    let array = item
        .as_array_mut()
        .ok_or_else(|| miette!("'{}' in [tool.pixi-audit] is not an array", list.key()))?;
    let existing_keys: Vec<RuleKey> = array.iter().filter_map(entry_key).collect();

    let targets: Vec<Option<&str>> = if ids.is_empty() {
        vec![None]
    } else {
        ids.iter().map(|id| Some(id.as_str())).collect()
    };
    let mut outcome = Outcome::default();
    let mut added_keys: Vec<RuleKey> = Vec::new();
    for id in targets {
        let key = RuleKey::new(id, scope);
        let rule = IgnoreRule::new(id.map(str::to_string), scope.clone(), list.until_fixed())
            .map_err(|error| miette!("{error}"))?;
        let label = rule.to_string();
        let listed = existing_keys.contains(&key);
        if listed || added_keys.contains(&key) {
            outcome.existing.push(label);
            continue;
        }
        array.push(rule_value(id, scope, reason, until)?);
        added_keys.push(key);
        outcome.added.push(label);
    }
    Ok(outcome)
}

/// The `[tool.pixi-audit]` table, created when missing. `tool` is kept
/// implicit so a new file gains a `[tool.pixi-audit]` header rather than
/// an empty `[tool]` one.
fn audit_table(document: &mut DocumentMut) -> miette::Result<&mut Table> {
    let tool = document.entry("tool").or_insert_with(|| {
        let mut table = Table::new();
        table.set_implicit(true);
        Item::Table(table)
    });
    let tool = tool
        .as_table_mut()
        .ok_or_else(|| miette!("'tool' in the manifest is not a table"))?;
    tool.entry("pixi-audit")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| miette!("[tool.pixi-audit] in the manifest is not a table"))
}

/// What an ignore list entry suppresses, for both the bare and table
/// forms. Entries of another shape are skipped here; the config loader
/// reports them.
fn entry_key(entry: &Value) -> Option<RuleKey> {
    let entry = IgnoreEntry::deserialize(entry.clone().into_deserializer()).ok()?;
    let rule = entry.resolved(false).ok()?;
    Some(RuleKey::new(rule.id(), rule.scope()))
}

/// A bare id when there is nothing else to record, otherwise an inline
/// table with the package, the reason, and a pixi-compatible quoted expiry.
fn rule_value(
    id: Option<&str>,
    scope: &IgnoreScope,
    reason: Option<&str>,
    until: Option<Date>,
) -> miette::Result<Value> {
    let entry = if let Some(id) = id
        && scope.is_empty()
        && reason.is_none()
        && until.is_none()
    {
        IgnoreEntry::Id(id.to_string())
    } else {
        IgnoreEntry::Rule(IgnoreTable {
            id: id.map(str::to_string),
            scope: scope.clone(),
            reason: reason.map(str::to_string),
            until: until.map(|until| toml::Value::String(until.to_string())),
        })
    };
    entry
        .serialize(toml_edit::ser::ValueSerializer::new())
        .into_diagnostic()
        .wrap_err("failed to serialize ignore rule")
}

#[cfg(test)]
mod tests;
