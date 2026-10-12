//! The default report: a grype-style status block, then a `pixi list`-style
//! table with one row per vulnerability match, rendered with iocraft.

use std::io::{self, Write};

use iocraft::prelude::*;
use pixi_audit::{
    AuditPackage, AuditReport, FixAvailability, Match, MatchConfidence, SeverityRating,
};
use supports_hyperlinks::Stream;

use super::{
    EXPLAIN_HINT, EXPLANATION_TERM_PALETTE_INDEX, ExplanationSection, Guidance, GuidanceOptions,
};

pub mod column;
mod grid;

pub use column::{Column, DEFAULT_COLUMNS};
use column::{RowContext, environments_cell, kind_cell, name_cell, severity_color};
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

/// Which columns the vulnerability match tables show, and in what order the rows come.
#[derive(Debug, Clone)]
pub struct TableLayout {
    pub columns: Vec<Column>,
    pub sort_by: Column,
}

impl Default for TableLayout {
    fn default() -> Self {
        Self {
            columns: DEFAULT_COLUMNS.to_vec(),
            sort_by: Column::Risk,
        }
    }
}

/// Renders the report and writes it to `out`. The table is always laid out
/// at its natural width, never clipped to the terminal: a narrow terminal
/// soft-wraps long rows, which loses alignment but never information.
pub fn write_table(
    report: &AuditReport,
    lock_file: &str,
    style: OutputStyle,
    layout: &TableLayout,
    options: GuidanceOptions,
    out: impl Write,
) -> io::Result<()> {
    let canvas = build(report, lock_file, style, layout, options).render(None);
    if style.color {
        canvas.write_ansi(out)
    } else {
        canvas.write(out)
    }
}

/// Renders the report as unstyled text at natural width, for tests.
#[cfg(test)]
pub fn render_table(report: &AuditReport, lock_file: &str, layout: &TableLayout) -> String {
    build(
        report,
        lock_file,
        OutputStyle::default(),
        layout,
        GuidanceOptions::default(),
    )
    .to_string()
}

#[cfg(test)]
pub fn render_table_explained(
    report: &AuditReport,
    lock_file: &str,
    layout: &TableLayout,
) -> String {
    build(
        report,
        lock_file,
        OutputStyle::default(),
        layout,
        GuidanceOptions {
            explain: true,
            ..Default::default()
        },
    )
    .to_string()
}

#[cfg(test)]
pub fn render_table_after_fix(
    report: &AuditReport,
    lock_file: &str,
    layout: &TableLayout,
) -> String {
    build(
        report,
        lock_file,
        OutputStyle::default(),
        layout,
        GuidanceOptions {
            fix_attempted: true,
            ..Default::default()
        },
    )
    .to_string()
}

fn build(
    report: &AuditReport,
    lock_file: &str,
    style: OutputStyle,
    layout: &TableLayout,
    options: GuidanceOptions,
) -> Element<'static, View> {
    let guidance = Guidance::for_report(report);
    let assessment = guidance.assessment_lines();
    let next_steps = guidance.next_step_lines(options.fix_attempted, options.manifest_available);
    let explanation = options
        .explain
        .then(|| guidance.explanation_sections(report));
    let sections: Vec<AnyElement<'static>> = [
        not_audited_table(&report.not_audited, style).map(|e| e.into_any()),
        Some(status_block(report, lock_file).into_any()),
        matches_table(&report.matches, style, layout).map(|e| e.into_any()),
        ignored_table(&report.ignored, style, layout).map(|e| e.into_any()),
        Some(summary_line(report).into_any()),
        guidance_section("Overview", assessment).map(|e| e.into_any()),
        guidance_section("Recommendations", next_steps).map(|e| e.into_any()),
        (!options.explain)
            .then(|| element! { Text(content: EXPLAIN_HINT, weight: Weight::Light) }.into_any()),
        explanation
            .and_then(explanation_section)
            .map(|e| e.into_any()),
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
//    └── by status:   3 fixed, 1 not-fixed, 1 ignored, 1 unbounded
//
// The status line ends with the weak matches, each count only when it is
// not zero: `unbounded` advisories name the product without version
// bounds, `unevaluated` ones were never checked against the versions.
// ---------------------------------------------------------------------------

const LABEL_WIDTH: usize = 35;

fn status_block(report: &AuditReport, lock_file: &str) -> Element<'static, View> {
    let summary = &report.summary;
    let packages = format!(
        "[{} packages audited{}]",
        summary.audited,
        if summary.not_audited > 0 {
            format!(", {} not audited", summary.not_audited)
        } else {
            String::new()
        }
    );
    let matches = match summary.vulnerable {
        0 => "[no vulnerability matches]".to_string(),
        1 => "[1 vulnerability match]".to_string(),
        n => format!("[{n} vulnerability matches]"),
    };

    let by_severity = severity_counts(&report.matches);
    let fixed = report
        .matches
        .iter()
        .filter(|f| f.fix_availability() == FixAvailability::Available)
        .count();
    let not_fixed = report.matches.len() - fixed;
    let weak_matches = weak_confidence_counts(&report.matches);

    element! {
        View(flex_direction: FlexDirection::Column) {
            #(status_line(format!("Audited {lock_file}"), packages))
            #(status_line("Scanned for vulnerabilities", matches))
            View {
                Text(content: "  ├── by severity: ", weight: Weight::Light)
                #(by_severity)
            }
            View {
                Text(content: format!("  └── by status:   {fixed} fixed, {not_fixed} not-fixed, {} ignored{weak_matches}", summary.ignored), weight: Weight::Light)
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
            Text(content: detail, weight: Weight::Light, wrap: TextWrap::NoWrap)
        }
    })
}

/// `, 1 unbounded, 2 unevaluated`: the matches basilisk could not pin to
/// versions, listed only when there are any.
fn weak_confidence_counts(matches: &[Match]) -> String {
    [
        MatchConfidence::VersionUnbounded,
        MatchConfidence::Unevaluated,
    ]
    .into_iter()
    .filter_map(|confidence| {
        let count = matches
            .iter()
            .filter(|m| m.match_confidence == confidence)
            .count();
        (count > 0).then(|| {
            format!(
                ", {count} {}",
                column::confidence_label(confidence).unwrap_or_default()
            )
        })
    })
    .collect()
}

/// `1 critical, 2 high, ...` with each non-zero count in its rating's color.
/// The whole line is dim, like the rest of the status tree.
fn severity_counts(matches: &[Match]) -> Vec<Element<'static, Text>> {
    let ratings = SeverityRating::ALL.iter().rev();
    let last = SeverityRating::ALL.len() - 1;
    ratings
        .enumerate()
        .map(|(i, rating)| {
            let count = matches.iter().filter(|m| m.severity == *rating).count();
            let separator = if i == last { "" } else { ", " };
            let color = if count == 0 {
                None
            } else {
                severity_color(*rating)
            };
            element! {
                Text(content: format!("{count} {}{separator}", rating.name()), color: color, weight: Weight::Light)
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// Lays `matches` out under `columns`, sorted by `layout.sort_by`.
fn matches_grid(
    matches: &[Match],
    columns: &[Column],
    style: OutputStyle,
    layout: &TableLayout,
) -> Element<'static, View> {
    let headers: Vec<&'static str> = columns.iter().flat_map(|column| column.headers()).collect();
    let mut rows = Vec::with_capacity(matches.len());
    let mut previous: Option<&Match> = None;
    for vuln_match in column::sorted(matches, layout.sort_by) {
        let context = RowContext {
            repeated_package: previous.is_some_and(|p| p.package == vuln_match.package),
            hyperlinks: style.hyperlinks,
            color: style.color,
            confidence_column: columns.contains(&Column::Confidence),
        };
        rows.push(
            columns
                .iter()
                .flat_map(|column| column.cells(vuln_match, context))
                .collect(),
        );
        previous = Some(vuln_match);
    }
    grid(&headers, rows)
}

fn matches_table(
    matches: &[Match],
    style: OutputStyle,
    layout: &TableLayout,
) -> Option<Element<'static, View>> {
    if matches.is_empty() {
        return None;
    }
    Some(matches_grid(matches, &layout.columns, style, layout))
}

/// Ignored vulnerability matches under the same columns, plus why each one is ignored.
fn ignored_table(
    ignored: &[Match],
    style: OutputStyle,
    layout: &TableLayout,
) -> Option<Element<'static, View>> {
    if ignored.is_empty() {
        return None;
    }
    let mut columns = layout.columns.clone();
    if !columns.contains(&Column::Ignored) {
        columns.push(Column::Ignored);
    }
    Some(section(
        format!("Ignored ({})", ignored.len()),
        matches_grid(ignored, &columns, style, layout),
    ))
}

fn not_audited_table(
    not_audited: &[AuditPackage],
    style: OutputStyle,
) -> Option<Element<'static, View>> {
    if not_audited.is_empty() {
        return None;
    }
    let context = RowContext {
        color: style.color,
        ..Default::default()
    };
    let rows = not_audited
        .iter()
        .map(|package| {
            vec![
                kind_cell(&package.ecosystem, context),
                name_cell(package.name.as_str(), context),
                Cell::new(package.version.clone().unwrap_or_else(|| "?".to_string())),
                Cell::new(package.ecosystem.to_string()),
                environments_cell(&package.environments),
            ]
        })
        .collect();
    Some(section(
        format!(
            "Not audited ({}) — no vulnerability database for these sources",
            not_audited.len()
        ),
        grid(&["", "Name", "Version", "Source", "Environments"], rows),
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

fn guidance_section(title: &'static str, lines: Vec<String>) -> Option<Element<'static, View>> {
    if lines.is_empty() {
        return None;
    }
    let lines: Vec<Element<'static, Text>> = lines
        .into_iter()
        .map(|line| element! { Text(content: format!("  • {line}")) })
        .collect();
    Some(element! {
        View(flex_direction: FlexDirection::Column) {
            Text(content: title, weight: Weight::Bold)
            #(lines)
        }
    })
}

fn explanation_section(sections: Vec<ExplanationSection>) -> Option<Element<'static, View>> {
    if sections.is_empty() {
        return None;
    }
    let sections: Vec<Element<'static, View>> = sections
        .into_iter()
        .map(|section| {
            let width = section.label_width();
            let lines: Vec<Element<'static, View>> = section
                .entries
                .into_iter()
                .map(|entry| {
                    let label = format!(
                        "    {:indent$}{:<width$}",
                        "",
                        entry.label,
                        indent = entry.indent
                    );
                    element! {
                        View {
                            Text(content: label, color: Color::AnsiValue(EXPLANATION_TERM_PALETTE_INDEX), weight: Weight::Bold)
                            Text(content: entry.text)
                        }
                    }
                })
                .collect();
            element! {
                View(flex_direction: FlexDirection::Column) {
                    Text(content: format!("  {}", section.title), weight: Weight::Bold)
                    #(lines)
                }
            }
        })
        .collect();
    Some(element! {
        View(flex_direction: FlexDirection::Column, gap: 1) {
            Text(content: "Definitions", weight: Weight::Bold)
            #(sections)
        }
    })
}

fn summary_line(report: &AuditReport) -> Element<'static, View> {
    let summary = &report.summary;
    let details = format!(
        " ({} audited, {} ignored, {} not audited)",
        summary.audited, summary.ignored, summary.not_audited
    );
    if summary.vulnerable == 0 {
        return element! {
            View {
                Text(content: "✔ No vulnerabilities found", color: Color::Green, weight: Weight::Bold)
                Text(content: details, weight: Weight::Light)
            }
        };
    }
    let mut packages: Vec<(&str, &str)> = report
        .matches
        .iter()
        .map(|f| (f.package.name.as_str(), f.package.version.as_str()))
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
            Text(content: details, weight: Weight::Light)
        }
    }
}

#[cfg(test)]
mod tests;
