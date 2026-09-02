//! The columns a finding can be shown in. Each field knows its header, how
//! to render a finding into a cell, and how two findings order under it, so
//! `--fields` and `--sort-by` are the same enum.

use std::cmp::Ordering;

use clap::ValueEnum;
use iocraft::prelude::{Color, Weight};
use pixi_audit::{Finding, IgnoreReason, MatchApplicability, PackageEcosystem, SeverityBand};

use super::grid::{Cell, Span};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Field {
    Name,
    Version,
    #[clap(name = "fixed-in")]
    FixedIn,
    Kind,
    Source,
    Vulnerability,
    Severity,
    Environments,
    Aliases,
    Summary,
    Url,
    /// Why a finding sits in the ignored section; empty elsewhere.
    Ignored,
    /// How confidently basilisk matched the advisory to the package.
    Match,
}

/// Columns shown when `--fields` is not given, in this order. The package
/// kind is not a column by default: like `pixi lock`, the name carries a
/// `C`/`P` marker. Neither is the source: only conda-forge and PyPI are
/// ever queried, so for a finding the marker already says which it is.
/// Nor is the match: most matches are evaluated, so the Vulnerability
/// column flags the ones that are not.
pub const DEFAULT_FIELDS: [Field; 6] = [
    Field::Name,
    Field::Version,
    Field::FixedIn,
    Field::Vulnerability,
    Field::Severity,
    Field::Environments,
];

/// Per-row context a cell may depend on beyond the finding itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct RowContext {
    /// The previous row is the same locked package, so identifying columns
    /// are dimmed to make the grouping visible without dropping data.
    pub repeated_package: bool,
    /// Wrap advisory IDs in hyperlinks.
    pub hyperlinks: bool,
    /// Colors are shown, so the kind marker can be a single colored letter
    /// instead of a word.
    pub color: bool,
    /// The Match column is shown, so the Vulnerability cell need not flag
    /// weak matches itself.
    pub match_column: bool,
}

impl Field {
    pub fn header(self) -> &'static str {
        match self {
            Field::Name => "Name",
            Field::Version => "Version",
            Field::FixedIn => "Fixed in",
            Field::Kind => "Kind",
            Field::Source => "Source",
            Field::Vulnerability => "Vulnerability",
            Field::Severity => "Severity",
            Field::Environments => "Environments",
            Field::Aliases => "Aliases",
            Field::Summary => "Summary",
            Field::Url => "URL",
            Field::Ignored => "Ignored",
            Field::Match => "Match",
        }
    }

    pub fn cell(self, finding: &Finding, context: RowContext) -> Cell {
        let dim_if_repeated = context.repeated_package.then_some(Color::DarkGrey);
        match self {
            Field::Name => name_cell(&finding.ecosystem, &finding.package.to_string(), context),
            Field::Version => Cell::new(finding.version.clone()).color(dim_if_repeated),
            Field::FixedIn => fixed_in(finding),
            Field::Kind => {
                let (name, color) = kind(&finding.ecosystem);
                Cell::new(name).color(color)
            }
            Field::Source => Cell::new(finding.ecosystem.to_string()),
            Field::Vulnerability => {
                let url = finding.url.clone().filter(|_| context.hyperlinks);
                let cell = Cell::new(finding.id.clone()).hyperlink(url);
                match weak_match_label(finding.applicability) {
                    Some(label) if !context.match_column => {
                        cell.then(Span::new(format!(" ({label})")).color(Color::DarkGrey))
                    }
                    _ => cell,
                }
            }
            Field::Severity => severity(finding.severity),
            Field::Environments => environments_cell(&finding.environments),
            Field::Aliases => Cell::new(finding.aliases.join(", ")),
            Field::Summary => Cell::new(finding.summary.clone().unwrap_or_default()),
            Field::Url => Cell::new(finding.url.clone().unwrap_or_default()),
            Field::Ignored => match finding.ignore_reason {
                Some(IgnoreReason::UntilFixed) => {
                    Cell::new("until a fix is released").color(Color::DarkGrey)
                }
                Some(IgnoreReason::Always) => Cell::new("always").color(Color::DarkGrey),
                None => Cell::empty(),
            },
            Field::Match => match match_label(finding.applicability) {
                Some(label) => Cell::new(label)
                    .color(weak_match_label(finding.applicability).map(|_| Color::DarkGrey)),
                None => Cell::empty(),
            },
        }
    }

    /// The order two findings take when the table is sorted by this field.
    /// Severity sorts most severe first; everything else ascends. Ties keep
    /// their existing order, so sorting is stable over the report's own
    /// severity ordering.
    pub fn compare(self, a: &Finding, b: &Finding) -> Ordering {
        match self {
            // By spelling, not by `PackageName`'s ecosystem-first derive.
            Field::Name => (a.package.as_str(), &a.version).cmp(&(b.package.as_str(), &b.version)),
            Field::Version => a.version.cmp(&b.version),
            // Fixed versions first, ordered by version; unfixed last.
            Field::FixedIn => match (a.fixed_versions.first(), b.fixed_versions.first()) {
                (Some(x), Some(y)) => x.cmp(y),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            },
            Field::Kind => kind(&a.ecosystem).0.cmp(kind(&b.ecosystem).0),
            Field::Source => a.ecosystem.cmp(&b.ecosystem),
            Field::Vulnerability => a.id.cmp(&b.id),
            Field::Severity => b.severity.cmp(&a.severity),
            Field::Environments => a.environments.cmp(&b.environments),
            Field::Aliases => a.aliases.cmp(&b.aliases),
            Field::Summary => a.summary.cmp(&b.summary),
            Field::Url => a.url.cmp(&b.url),
            Field::Ignored => a.ignore_reason.is_some().cmp(&b.ignore_reason.is_some()),
            // Most confident first; unspecified last.
            Field::Match => b.applicability.cmp(&a.applicability),
        }
    }
}

/// Findings in `sort_by` order, ties keeping the report's order.
pub fn sorted(findings: &[Finding], sort_by: Field) -> Vec<&Finding> {
    let mut rows: Vec<&Finding> = findings.iter().collect();
    rows.sort_by(|a, b| sort_by.compare(a, b));
    rows
}

/// The package kind the way `pixi list` shows it: green `conda`, blue `pypi`.
fn kind(ecosystem: &PackageEcosystem) -> (&'static str, Color) {
    match ecosystem {
        PackageEcosystem::Pypi => ("pypi", Color::Blue),
        PackageEcosystem::CondaForge | PackageEcosystem::Other(_) => ("conda", Color::Green),
    }
}

/// The kind marker `pixi lock` puts before a package name: a bold green
/// `C` or blue `P` when colors show, `(conda)` or `(pypi)` otherwise.
pub fn kind_marker(ecosystem: &PackageEcosystem, color: bool) -> Span {
    let (name, tint) = kind(ecosystem);
    if color {
        let letter = name[..1].to_ascii_uppercase();
        Span::new(letter).color(tint).weight(Weight::Bold)
    } else {
        Span::new(format!("({name})"))
    }
}

/// `<marker> <name>`, the name dimmed when the row repeats the package above.
pub fn name_cell(ecosystem: &PackageEcosystem, name: &str, context: RowContext) -> Cell {
    let dim_if_repeated = context.repeated_package.then_some(Color::DarkGrey);
    Cell::from(kind_marker(ecosystem, context.color))
        .then(Span::new(format!(" {name}")).color(dim_if_repeated))
}

/// Environment names in the color pixi uses for them.
pub fn environments_cell(environments: &[String]) -> Cell {
    Cell::new(environments.join(", ")).color(Color::Magenta)
}

/// Fixed versions in the package's own ecosystem, or a dim note naming
/// where else a fix exists. Blank when nothing does.
fn fixed_in(finding: &Finding) -> Cell {
    if !finding.fixed_versions.is_empty() {
        Cell::new(finding.fixed_versions.join(", ")).color(Color::Green)
    } else if !finding.upstream_fixes.is_empty() {
        let labels: Vec<String> = finding
            .upstream_fixes
            .iter()
            .map(crate::render::upstream_fix_label)
            .collect();
        Cell::new(labels.join(", ")).color(Color::DarkGrey)
    } else {
        Cell::empty()
    }
}

fn severity(band: SeverityBand) -> Cell {
    let mut name = band.name().to_string();
    if let Some(first) = name.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    let weight = match band {
        SeverityBand::Critical => Weight::Bold,
        _ => Weight::Normal,
    };
    Cell::new(name).color(severity_color(band)).weight(weight)
}

/// The color a severity band carries wherever it is shown.
pub fn severity_color(band: SeverityBand) -> Option<Color> {
    match band {
        SeverityBand::Critical | SeverityBand::High => Some(Color::Red),
        SeverityBand::Medium => Some(Color::Yellow),
        SeverityBand::Low => None,
        SeverityBand::Unknown => Some(Color::DarkGrey),
    }
}

/// The applicability as the Match column shows it; `None` when basilisk
/// recorded none.
pub fn match_label(applicability: MatchApplicability) -> Option<&'static str> {
    match applicability {
        MatchApplicability::Evaluated => Some("evaluated"),
        MatchApplicability::Unevaluated => Some("unevaluated"),
        MatchApplicability::VersionUnbounded => Some("unbounded"),
        MatchApplicability::Unspecified => None,
    }
}

/// The label of a match worth flagging next to the advisory: one basilisk
/// could not evaluate, or one with no version bounds at all.
pub fn weak_match_label(applicability: MatchApplicability) -> Option<&'static str> {
    match applicability {
        MatchApplicability::Unevaluated | MatchApplicability::VersionUnbounded => {
            match_label(applicability)
        }
        MatchApplicability::Evaluated | MatchApplicability::Unspecified => None,
    }
}
