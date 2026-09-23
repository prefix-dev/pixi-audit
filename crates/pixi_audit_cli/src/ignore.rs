//! `pixi audit ignore`: records ignore rules in the workspace manifest's
//! `[tool.pixi-audit]` table, so a suppression lives next to the code it
//! covers instead of in a CI script.

use std::path::PathBuf;

use clap::Args;
use jiff::civil::Date;
use miette::{Context, IntoDiagnostic, miette};
use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, Value};

use crate::config;

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
    let manifest = match args.manifest {
        Some(path) => path,
        None => {
            let cwd = std::env::current_dir()
                .into_diagnostic()
                .wrap_err("cannot determine the current directory")?;
            config::discover_workspace(&cwd)?.ok_or_else(|| {
                miette!("no pixi workspace found; pass --manifest or run inside a pixi workspace")
            })?
        }
    };

    let content = std::fs::read_to_string(&manifest)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read manifest '{}'", manifest.display()))?;
    let mut document = content
        .parse::<DocumentMut>()
        .into_diagnostic()
        .wrap_err_with(|| format!("'{}' is not valid TOML", manifest.display()))?;

    let list = if args.until_fixed {
        IgnoreList::UntilFixed
    } else {
        IgnoreList::Always
    };
    let outcome = add_rules(
        &mut document,
        list,
        &args.ids,
        args.package.as_deref(),
        IgnoreScope {
            ecosystem: args.ecosystem.as_deref(),
            version: args.version.as_deref(),
            max_affected_version: args.max_affected_version.as_deref(),
        },
        args.reason.as_deref(),
        args.until,
    )?;
    if !outcome.added.is_empty() {
        std::fs::write(&manifest, document.to_string())
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to update manifest '{}'", manifest.display()))?;
    }

    for rule in &outcome.added {
        eprintln!(
            "Ignoring {rule}{} in '{}'",
            match list {
                IgnoreList::Always => "",
                IgnoreList::UntilFixed => " until a fix is released",
            },
            manifest.display()
        );
    }
    for rule in &outcome.existing {
        eprintln!(
            "note: {rule} is already listed under '{}' in [tool.pixi-audit] of '{}'",
            list.key(),
            manifest.display()
        );
    }
    Ok(())
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
            IgnoreList::Always => "ignore",
            IgnoreList::UntilFixed => "ignore-until-fixed",
        }
    }
}

/// Which rules a call recorded and which were already listed, as labels
/// such as `CVE-1`, `package 'x'`, or `CVE-1 in package 'x'`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub added: Vec<String>,
    pub existing: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct IgnoreScope<'a> {
    pub ecosystem: Option<&'a str>,
    pub version: Option<&'a str>,
    pub max_affected_version: Option<&'a str>,
}

/// What one rule suppresses, lowercased for comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleKey {
    id: Option<String>,
    package: Option<String>,
    ecosystem: Option<String>,
    version: Option<String>,
    max_affected_version: Option<String>,
}

impl RuleKey {
    fn new(id: Option<&str>, package: Option<&str>, scope: IgnoreScope<'_>) -> Self {
        Self {
            id: id.map(str::to_lowercase),
            package: package.map(str::to_lowercase),
            ecosystem: scope.ecosystem.map(str::to_lowercase),
            version: scope.version.map(str::to_string),
            max_affected_version: scope.max_affected_version.map(str::to_string),
        }
    }
}

/// Appends a rule for each of `ids` to `list` in `document`, or one rule
/// for the whole `package` when no id is given, creating the
/// `[tool.pixi-audit]` table and the list as needed. Rules already listed,
/// compared case-insensitively, are left alone and reported as existing.
/// Formatting and comments elsewhere in the document are untouched.
pub fn add_rules(
    document: &mut DocumentMut,
    list: IgnoreList,
    ids: &[String],
    package: Option<&str>,
    scope: IgnoreScope<'_>,
    reason: Option<&str>,
    until: Option<Date>,
) -> miette::Result<Outcome> {
    config::validate_scope(&config::ResolvedIgnore {
        id: ids.first().cloned(),
        package: package.map(str::to_string),
        ecosystem: scope.ecosystem.map(str::to_string),
        version: scope.version.map(str::to_string),
        max_affected_version: scope.max_affected_version.map(str::to_string),
    })
    .map_err(|error| miette!("{error}"))?;
    let table = audit_table(document)?;
    let item = table
        .entry(list.key())
        .or_insert_with(|| Item::Value(Value::Array(Array::new())));
    let array = item
        .as_array_mut()
        .ok_or_else(|| miette!("'{}' in [tool.pixi-audit] is not an array", list.key()))?;

    let targets: Vec<Option<&str>> = if ids.is_empty() {
        vec![None]
    } else {
        ids.iter().map(|id| Some(id.as_str())).collect()
    };
    let mut outcome = Outcome::default();
    let mut added_keys: Vec<RuleKey> = Vec::new();
    for id in targets {
        let key = RuleKey::new(id, package, scope);
        let label = match (id, package) {
            (Some(id), Some(package)) => format!("{id} in package '{package}'"),
            (Some(id), None) => id.to_string(),
            (None, Some(package)) => format!("package '{package}'"),
            (None, None) => return Err(miette!("an ignore rule needs an id or a package")),
        };
        let listed = array
            .iter()
            .filter_map(entry_key)
            .any(|existing| existing == key);
        if listed || added_keys.contains(&key) {
            outcome.existing.push(label);
            continue;
        }
        array.push(rule_value(id, package, scope, reason, until));
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
    match entry {
        Value::String(id) => Some(RuleKey::new(Some(id.value()), None, IgnoreScope::default())),
        Value::InlineTable(rule) => Some(RuleKey::new(
            rule.get("id").and_then(Value::as_str),
            rule.get("package").and_then(Value::as_str),
            IgnoreScope {
                ecosystem: rule.get("ecosystem").and_then(Value::as_str),
                version: rule.get("version").and_then(Value::as_str),
                max_affected_version: rule.get("max-affected-version").and_then(Value::as_str),
            },
        )),
        Value::Integer(_)
        | Value::Float(_)
        | Value::Boolean(_)
        | Value::Datetime(_)
        | Value::Array(_) => None,
    }
}

/// A bare id when there is nothing else to record, otherwise an inline
/// table with the package, the reason, and a pixi-compatible quoted expiry.
fn rule_value(
    id: Option<&str>,
    package: Option<&str>,
    scope: IgnoreScope<'_>,
    reason: Option<&str>,
    until: Option<Date>,
) -> Value {
    if let (Some(id), None, None, None, None, None, None) = (
        id,
        package,
        scope.ecosystem,
        scope.version,
        scope.max_affected_version,
        reason,
        until,
    ) {
        return Value::from(id);
    }
    let mut rule = InlineTable::new();
    if let Some(id) = id {
        rule.insert("id", Value::from(id));
    }
    if let Some(package) = package {
        rule.insert("package", Value::from(package));
    }
    if let Some(ecosystem) = scope.ecosystem {
        rule.insert("ecosystem", Value::from(ecosystem));
    }
    if let Some(version) = scope.version {
        rule.insert("version", Value::from(version));
    }
    if let Some(version) = scope.max_affected_version {
        rule.insert("max-affected-version", Value::from(version));
    }
    if let Some(reason) = reason {
        rule.insert("reason", Value::from(reason));
    }
    if let Some(until) = until {
        rule.insert("until", Value::from(until.to_string()));
    }
    Value::InlineTable(rule)
}

#[cfg(test)]
mod tests;
