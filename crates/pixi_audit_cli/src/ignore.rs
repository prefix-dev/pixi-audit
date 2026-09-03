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
    /// Vulnerability ids or aliases to ignore
    #[arg(required = true, value_name = "ID")]
    pub ids: Vec<String>,

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
        args.reason.as_deref(),
        args.until,
    )?;
    if !outcome.added.is_empty() {
        std::fs::write(&manifest, document.to_string())
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to update manifest '{}'", manifest.display()))?;
    }

    for id in &outcome.added {
        eprintln!(
            "Ignoring {id}{} in '{}'",
            match list {
                IgnoreList::Always => "",
                IgnoreList::UntilFixed => " until a fix is released",
            },
            manifest.display()
        );
    }
    for id in &outcome.existing {
        eprintln!(
            "note: '{id}' is already listed under '{}' in [tool.pixi-audit] of '{}'",
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

/// Which ids a call recorded and which were already listed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub added: Vec<String>,
    pub existing: Vec<String>,
}

/// Appends a rule for each of `ids` to `list` in `document`, creating the
/// `[tool.pixi-audit]` table and the list as needed. Ids already listed,
/// compared case-insensitively, are left alone and reported as existing.
/// Formatting and comments elsewhere in the document are untouched.
pub fn add_rules(
    document: &mut DocumentMut,
    list: IgnoreList,
    ids: &[String],
    reason: Option<&str>,
    until: Option<Date>,
) -> miette::Result<Outcome> {
    let table = audit_table(document)?;
    let item = table
        .entry(list.key())
        .or_insert_with(|| Item::Value(Value::Array(Array::new())));
    let array = item
        .as_array_mut()
        .ok_or_else(|| miette!("'{}' in [tool.pixi-audit] is not an array", list.key()))?;

    let mut outcome = Outcome::default();
    for id in ids {
        let listed = array
            .iter()
            .filter_map(entry_id)
            .any(|existing| existing.eq_ignore_ascii_case(id));
        if listed
            || outcome
                .added
                .iter()
                .any(|added| added.eq_ignore_ascii_case(id))
        {
            outcome.existing.push(id.clone());
            continue;
        }
        array.push(rule_value(id, reason, until));
        outcome.added.push(id.clone());
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

/// The id an ignore list entry names, for both the bare and table forms.
fn entry_id(entry: &Value) -> Option<&str> {
    match entry {
        Value::String(id) => Some(id.value()),
        Value::InlineTable(rule) => rule.get("id").and_then(Value::as_str),
        Value::Integer(_)
        | Value::Float(_)
        | Value::Boolean(_)
        | Value::Datetime(_)
        | Value::Array(_) => None,
    }
}

/// A bare id when there is nothing else to record, otherwise an inline
/// table with the reason and the expiry as a TOML date.
fn rule_value(id: &str, reason: Option<&str>, until: Option<Date>) -> Value {
    if reason.is_none() && until.is_none() {
        return Value::from(id);
    }
    let mut rule = InlineTable::new();
    rule.insert("id", Value::from(id));
    if let Some(reason) = reason {
        rule.insert("reason", Value::from(reason));
    }
    if let Some(until) = until {
        rule.insert("until", Value::from(toml_date(until)));
    }
    Value::InlineTable(rule)
}

fn toml_date(date: Date) -> toml_edit::Datetime {
    toml_edit::Datetime {
        date: Some(toml_edit::Date {
            year: date.year().unsigned_abs(),
            month: date.month().unsigned_abs(),
            day: date.day().unsigned_abs(),
        }),
        time: None,
        offset: None,
    }
}

#[cfg(test)]
mod tests;
