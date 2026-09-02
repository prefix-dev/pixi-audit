//! The default report: a grype-style status block, then a `pixi list`-style
//! table with one row per finding, rendered with iocraft.

use std::io::{self, Write};

use iocraft::prelude::*;
use pixi_audit::{AuditReport, Finding, SeverityBand, UncheckedPackage};
use supports_hyperlinks::Stream;

pub mod field;
mod grid;

pub use field::{DEFAULT_FIELDS, Field};
use field::{RowContext, environments_cell, name_cell, severity_color};
use grid::{Cell, grid};

/// What the output stream can show.
#[derive(Debug, Clone, Copy, Default)]
pub struct OutputStyle {
    /// Emit ANSI colors and bold text.
    pub color: bool,
    /// Wrap advisory IDs in OSC 8 hyperlinks to their advisory page.
    pub hyperlinks: bool,
}

impl OutputStyle {
    /// Detects what stdout supports. Colors follow the `console` crate's
    /// rules, so `NO_COLOR` disables them and `CLICOLOR_FORCE=1` turns them
    /// on for CI logs that render ANSI. Hyperlinks additionally require a
    /// terminal known to render OSC 8.
    pub fn detect_stdout() -> Self {
        let color = console::colors_enabled();
        Self {
            color,
            hyperlinks: color && supports_hyperlinks::on(Stream::Stdout),
        }
    }
}

/// Which columns the findings tables show, and in what order the rows come.
#[derive(Debug, Clone)]
pub struct TableLayout {
    pub fields: Vec<Field>,
    pub sort_by: Field,
}

impl Default for TableLayout {
    fn default() -> Self {
        Self {
            fields: DEFAULT_FIELDS.to_vec(),
            sort_by: Field::Severity,
        }
    }
}

/// Renders the report and writes it to `out`. The table is always laid out
/// at its natural width, never clipped to the terminal: a narrow terminal
/// soft-wraps long rows, which loses alignment but never information.
pub fn write_table(
    report: &AuditReport,
    lockfile: &str,
    style: OutputStyle,
    layout: &TableLayout,
    out: impl Write,
) -> io::Result<()> {
    let canvas = build(report, lockfile, style, layout).render(None);
    if style.color {
        canvas.write_ansi(out)
    } else {
        canvas.write(out)
    }
}

/// Renders the report as unstyled text at natural width, for tests.
#[cfg(test)]
pub fn render_table(report: &AuditReport, lockfile: &str, layout: &TableLayout) -> String {
    build(report, lockfile, OutputStyle::default(), layout).to_string()
}

fn build(
    report: &AuditReport,
    lockfile: &str,
    style: OutputStyle,
    layout: &TableLayout,
) -> Element<'static, View> {
    let sections: Vec<AnyElement<'static>> = [
        Some(status_block(report, lockfile).into_any()),
        findings_table(&report.vulnerabilities, style, layout).map(|e| e.into_any()),
        ignored_table(&report.ignored, style, layout).map(|e| e.into_any()),
        unchecked_table(&report.unchecked, style).map(|e| e.into_any()),
        Some(summary_line(report).into_any()),
    ]
    .into_iter()
    .flatten()
    .collect();

    element! {
        View(flex_direction: FlexDirection::Column, gap: 1, padding_left: 1) {
            #(sections)
        }
    }
}

// ---------------------------------------------------------------------------
// Status block, modelled on grype's progress summary:
//
//  ✔ Audited pixi.lock                 [312 packages audited]
//  ✔ Scanned for vulnerabilities       [4 vulnerability matches]
//    ├── by severity: 1 critical, 2 high, 1 medium, 0 low, 0 unknown
//    └── by status:   3 fixed, 1 not-fixed, 1 ignored
// ---------------------------------------------------------------------------

const LABEL_WIDTH: usize = 35;

fn status_block(report: &AuditReport, lockfile: &str) -> Element<'static, View> {
    let summary = &report.summary;
    let packages = format!(
        "[{} packages audited{}]",
        summary.audited,
        if summary.unchecked > 0 {
            format!(", {} unchecked", summary.unchecked)
        } else {
            String::new()
        }
    );
    let matches = match summary.vulnerable {
        0 => "[no vulnerability matches]".to_string(),
        1 => "[1 vulnerability match]".to_string(),
        n => format!("[{n} vulnerability matches]"),
    };

    let by_severity = severity_counts(&report.vulnerabilities);
    let fixed = report
        .vulnerabilities
        .iter()
        .filter(|f| !f.fixed_versions.is_empty())
        .count();
    let not_fixed = report.vulnerabilities.len() - fixed;

    element! {
        View(flex_direction: FlexDirection::Column) {
            #(status_line(format!("Audited {lockfile}"), packages))
            #(status_line("Scanned for vulnerabilities", matches))
            View {
                Text(content: "  ├── by severity: ", color: Color::DarkGrey)
                #(by_severity)
            }
            View {
                Text(content: "  └── by status:   ", color: Color::DarkGrey)
                Text(content: format!("{fixed} fixed, "))
                Text(content: format!("{not_fixed} not-fixed, "))
                Text(content: format!("{} ignored", summary.ignored))
            }
        }
    }
}

/// `✔ <label>   [detail]`, with the detail column aligned across lines
/// unless a label (such as a long lock file path) is wider than the column.
fn status_line(label: impl Into<String>, detail: String) -> Option<Element<'static, View>> {
    let label = label.into();
    Some(element! {
        View(gap: 1) {
            View(min_width: LABEL_WIDTH as u32) {
                Text(content: "✔ ", color: Color::Green)
                Text(content: label, wrap: TextWrap::NoWrap)
            }
            Text(content: detail, color: Color::DarkGrey, wrap: TextWrap::NoWrap)
        }
    })
}

/// `1 critical, 2 high, ...` with each non-zero count in its band's color.
fn severity_counts(findings: &[Finding]) -> Vec<Element<'static, Text>> {
    let bands = SeverityBand::ALL.iter().rev();
    let last = SeverityBand::ALL.len() - 1;
    bands
        .enumerate()
        .map(|(i, band)| {
            let count = findings.iter().filter(|f| f.severity == *band).count();
            let separator = if i == last { "" } else { ", " };
            let color = if count == 0 {
                Some(Color::DarkGrey)
            } else {
                severity_color(*band)
            };
            element! {
                Text(content: format!("{count} {}{separator}", band.name()), color: color)
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// Lays `findings` out under `fields`, sorted by `layout.sort_by`.
fn findings_grid(
    findings: &[Finding],
    fields: &[Field],
    style: OutputStyle,
    layout: &TableLayout,
) -> Element<'static, View> {
    let headers: Vec<&'static str> = fields.iter().map(|field| field.header()).collect();
    let mut rows = Vec::with_capacity(findings.len());
    let mut previous: Option<&Finding> = None;
    for finding in field::sorted(findings, layout.sort_by) {
        let context = RowContext {
            repeated_package: previous.is_some_and(|p| same_package(p, finding)),
            hyperlinks: style.hyperlinks,
            color: style.color,
        };
        rows.push(
            fields
                .iter()
                .map(|field| field.cell(finding, context))
                .collect(),
        );
        previous = Some(finding);
    }
    grid(&headers, rows)
}

fn same_package(a: &Finding, b: &Finding) -> bool {
    a.package == b.package && a.version == b.version && a.ecosystem == b.ecosystem
}

fn findings_table(
    findings: &[Finding],
    style: OutputStyle,
    layout: &TableLayout,
) -> Option<Element<'static, View>> {
    if findings.is_empty() {
        return None;
    }
    Some(findings_grid(findings, &layout.fields, style, layout))
}

/// Ignored findings under the same columns, plus why each one is ignored.
fn ignored_table(
    ignored: &[Finding],
    style: OutputStyle,
    layout: &TableLayout,
) -> Option<Element<'static, View>> {
    if ignored.is_empty() {
        return None;
    }
    let mut fields = layout.fields.clone();
    if !fields.contains(&Field::Ignored) {
        fields.push(Field::Ignored);
    }
    Some(section(
        format!("Ignored ({})", ignored.len()),
        findings_grid(ignored, &fields, style, layout),
    ))
}

fn unchecked_table(
    unchecked: &[UncheckedPackage],
    style: OutputStyle,
) -> Option<Element<'static, View>> {
    if unchecked.is_empty() {
        return None;
    }
    let context = RowContext {
        color: style.color,
        ..Default::default()
    };
    let rows = unchecked
        .iter()
        .map(|package| {
            vec![
                name_cell(&package.ecosystem, &package.package.to_string(), context),
                Cell::new(package.version.clone().unwrap_or_else(|| "?".to_string())),
                Cell::new(package.ecosystem.to_string()),
                environments_cell(&package.environments),
            ]
        })
        .collect();
    Some(section(
        format!(
            "Unchecked ({}) — no vulnerability database for these sources",
            unchecked.len()
        ),
        grid(&["Name", "Version", "Source", "Environments"], rows),
    ))
}

fn section(title: String, body: Element<'static, View>) -> Element<'static, View> {
    element! {
        View(flex_direction: FlexDirection::Column) {
            View(margin_bottom: 1) {
                Text(content: title, weight: Weight::Bold)
            }
            #(Some(body))
        }
    }
}

fn summary_line(report: &AuditReport) -> Element<'static, View> {
    let summary = &report.summary;
    let details = format!(
        " ({} audited, {} ignored, {} unchecked)",
        summary.audited, summary.ignored, summary.unchecked
    );
    if summary.vulnerable == 0 {
        return element! {
            View {
                Text(content: "✔ No vulnerabilities found", color: Color::Green, weight: Weight::Bold)
                Text(content: details, color: Color::DarkGrey)
            }
        };
    }
    let mut packages: Vec<(&str, &str)> = report
        .vulnerabilities
        .iter()
        .map(|f| (f.package.as_str(), f.version.as_str()))
        .collect();
    packages.sort_unstable();
    packages.dedup();
    let headline = format!(
        "✖ {} vulnerabilities in {} package(s)",
        summary.vulnerable,
        packages.len()
    );
    element! {
        View {
            Text(content: headline, color: Color::Red, weight: Weight::Bold)
            Text(content: details, color: Color::DarkGrey)
        }
    }
}

#[cfg(test)]
mod tests;
