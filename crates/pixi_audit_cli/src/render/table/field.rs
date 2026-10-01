//! The columns a finding can be shown in. Each field knows its header, how
//! to render a finding into a cell, and how two findings order under it, so
//! `--fields` and `--sort-by` are the same enum.

use std::cmp::Ordering;

use clap::ValueEnum;
use iocraft::prelude::{Color, Weight};
use pixi_audit::{
    Finding, FixStatus, IgnoreReason, MatchApplicability, PackageEcosystem, SeverityBand,
    SortStrategy,
};

use super::grid::{Cell, Span};
use crate::render::{epss_label, kev_label, risk_label};

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
    /// EPSS exploit probability and percentile.
    Epss,
    /// The 0-100 risk score.
    Risk,
    /// `kev` for findings in CISA's KEV catalog, `kev, ransomware` when
    /// used in ransomware campaigns; empty otherwise. The risk column
    /// already marks these, so this is mostly a sort key.
    Kev,
    Environments,
    Aliases,
    Summary,
    Url,
    /// Why a finding sits in the ignored section; empty elsewhere.
    Ignored,
    /// How the advisory's version data matched the package.
    Match,
}

/// Columns shown when `--fields` is not given, in this order. The package
/// kind is not a column by default: like `pixi lock`, a `C`/`P` marker
/// precedes the name. Neither is the source: only conda-forge and PyPI are
/// ever queried, so for a finding the marker already says which it is.
/// Nor is the match: most matches are evaluated, so the Vulnerability
/// column flags the ones that are not.
pub const DEFAULT_FIELDS: [Field; 8] = [
    Field::Name,
    Field::Version,
    Field::FixedIn,
    Field::Vulnerability,
    Field::Severity,
    Field::Epss,
    Field::Risk,
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

impl RowContext {
    /// The weight of an identifying cell: dim when the row repeats the
    /// package above, otherwise `normal`.
    fn identity_weight(self, normal: Weight) -> Weight {
        if self.repeated_package {
            Weight::Light
        } else {
            normal
        }
    }
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
            Field::Epss => "EPSS",
            Field::Risk => "Risk",
            Field::Kev => "KEV",
            Field::Environments => "Environments",
            Field::Aliases => "Aliases",
            Field::Summary => "Summary",
            Field::Url => "URL",
            Field::Ignored => "Ignored",
            Field::Match => "Match",
        }
    }

    /// The header of each grid column this field occupies. The name field
    /// spans two: the kind marker and the name itself, so names line up
    /// whatever the marker's width.
    pub fn headers(self) -> Vec<&'static str> {
        match self {
            Field::Name => vec!["", "Name"],
            other => vec![other.header()],
        }
    }

    /// One cell per column of [`Field::headers`].
    pub fn cells(self, finding: &Finding, context: RowContext) -> Vec<Cell> {
        match self {
            Field::Name => vec![
                kind_cell(&finding.package.ecosystem, context),
                name_cell(&finding.package.name.to_string(), context),
            ],
            other => vec![other.cell(finding, context)],
        }
    }

    pub fn cell(self, finding: &Finding, context: RowContext) -> Cell {
        match self {
            Field::Name => name_cell(&finding.package.name.to_string(), context),
            Field::Version => Cell::new(finding.package.version.clone())
                .weight(context.identity_weight(Weight::Normal)),
            Field::FixedIn => fixed_in(finding),
            Field::Kind => {
                let (name, color) = kind(&finding.package.ecosystem);
                Cell::new(name).color(color)
            }
            Field::Source => Cell::new(finding.package.ecosystem.to_string()),
            Field::Vulnerability => {
                let url = finding.url.clone().filter(|_| context.hyperlinks);
                let cell = Cell::new(finding.id.clone()).hyperlink(url);
                match weak_match_label(finding.applicability) {
                    Some(label) if !context.match_column => {
                        cell.then(Span::new(format!(" ({label})")).weight(Weight::Light))
                    }
                    _ => cell,
                }
            }
            Field::Severity => severity(finding.severity),
            Field::Epss => epss_label(&finding.epss).map_or_else(Cell::empty, Cell::new),
            Field::Risk => risk_cell(finding),
            Field::Kev => kev_label(&finding.known_exploited).map_or_else(Cell::empty, |label| {
                Cell::new(label).color(KEV_COLOR).weight(Weight::Bold)
            }),
            Field::Environments => environments_cell(&finding.environments),
            Field::Aliases => Cell::new(finding.aliases.join(", ")),
            Field::Summary => Cell::new(finding.summary.clone().unwrap_or_default()),
            Field::Url => Cell::new(finding.url.clone().unwrap_or_default()),
            Field::Ignored => match finding.ignore_reason {
                Some(IgnoreReason::UntilFixed) => {
                    Cell::new("until a fix is released").weight(Weight::Light)
                }
                Some(IgnoreReason::Always) => Cell::new("always").weight(Weight::Light),
                None => Cell::empty(),
            },
            Field::Match => match match_label(finding.applicability) {
                Some(label) => {
                    let cell = Cell::new(label);
                    if weak_match_label(finding.applicability).is_some() {
                        cell.weight(Weight::Light)
                    } else {
                        cell
                    }
                }
                None => Cell::empty(),
            },
        }
    }

    /// The order two findings take when the table is sorted by this field.
    /// Risk, severity, EPSS, and KEV sort highest first and break ties the
    /// way the report's [`SortStrategy`] does; everything else ascends,
    /// ties keeping their existing order.
    pub fn compare(self, a: &Finding, b: &Finding) -> Ordering {
        match self {
            // By spelling, not by `PackageName`'s ecosystem-first derive.
            Field::Name => (a.package.name.as_str(), &a.package.version)
                .cmp(&(b.package.name.as_str(), &b.package.version)),
            Field::Version => a.package.version.cmp(&b.package.version),
            // Fixed versions first, ordered by version; unfixed last.
            Field::FixedIn => match (a.fixed_versions.first(), b.fixed_versions.first()) {
                (Some(x), Some(y)) => x.cmp(y),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            },
            Field::Kind => kind(&a.package.ecosystem)
                .0
                .cmp(kind(&b.package.ecosystem).0),
            Field::Source => a.package.ecosystem.cmp(&b.package.ecosystem),
            Field::Vulnerability => a.id.cmp(&b.id),
            Field::Severity => SortStrategy::Severity.compare(a, b),
            Field::Epss => SortStrategy::Epss.compare(a, b),
            Field::Risk => SortStrategy::Risk.compare(a, b),
            Field::Kev => SortStrategy::Kev.compare(a, b),
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

/// The kind marker `pixi lock` puts before a package name, in a column of
/// its own: a bold green `C` or blue `P` when colors show, `(conda)` or
/// `(pypi)` otherwise. Dimmed like the name when the row repeats the
/// package above.
pub fn kind_cell(ecosystem: &PackageEcosystem, context: RowContext) -> Cell {
    let (name, tint) = kind(ecosystem);
    let span = if context.color {
        let letter = name[..1].to_ascii_uppercase();
        Span::new(letter)
            .color(tint)
            .weight(context.identity_weight(Weight::Bold))
    } else {
        Span::new(format!("({name})")).weight(context.identity_weight(Weight::Normal))
    };
    Cell::from(span)
}

/// The package name, dimmed when the row repeats the package above.
pub fn name_cell(name: &str, context: RowContext) -> Cell {
    Cell::new(name).weight(context.identity_weight(Weight::Normal))
}

/// Environment names in the color pixi uses for them.
pub fn environments_cell(environments: &[String]) -> Cell {
    Cell::new(environments.join(", ")).color(Color::Magenta)
}

/// Fixed versions in the package's own ecosystem, or a dim note naming
/// where else a fix exists. Blank when nothing does.
fn fixed_in(finding: &Finding) -> Cell {
    match finding.fix_status() {
        FixStatus::Available => Cell::new(finding.fixed_versions.join(", ")).color(Color::Green),
        FixStatus::UpstreamOnly => {
            let labels: Vec<String> = finding
                .upstream_fixes
                .iter()
                .map(crate::render::upstream_fix_label)
                .collect();
            Cell::new(labels.join(", ")).weight(Weight::Light)
        }
        FixStatus::Unfixed => Cell::empty(),
    }
}

/// The risk score, with grype's `(kev)` marker after it for findings in
/// the catalog. Blank without threat data.
fn risk_cell(finding: &Finding) -> Cell {
    let Some(risk) = risk_label(finding.risk) else {
        return Cell::empty();
    };
    let cell = Cell::new(risk);
    match kev_label(&finding.known_exploited) {
        Some(kev) => cell.then(
            Span::new(format!(" ({kev})"))
                .color(KEV_COLOR)
                .weight(Weight::Bold),
        ),
        None => cell,
    }
}

fn severity(band: SeverityBand) -> Cell {
    let mut name = band.name().to_string();
    if let Some(first) = name.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    Cell::new(name)
        .color(severity_color(band))
        .weight(severity_weight(band))
}

/// The color a severity band carries wherever it is shown: grype's
/// palette, as 256-color indexes so it reads the same on any terminal
/// theme.
pub fn severity_color(band: SeverityBand) -> Option<Color> {
    Some(Color::AnsiValue(severity_palette_index(band)))
}

/// The 256-color palette index behind [`severity_color`], for renderers
/// that do not go through iocraft.
pub fn severity_palette_index(band: SeverityBand) -> u8 {
    match band {
        SeverityBand::Critical => 198, // bright pink
        SeverityBand::High => 203,     // salmon
        SeverityBand::Medium => 178,   // gold
        SeverityBand::Low => 36,       // teal
        SeverityBand::Unknown => 12,   // light blue
    }
}

/// The applicability as the Match column shows it; `None` when no
/// applicability metadata was recorded.
pub fn match_label(applicability: MatchApplicability) -> Option<&'static str> {
    match applicability {
        MatchApplicability::Evaluated => Some("affects version"),
        MatchApplicability::Unevaluated => Some("version not checked"),
        MatchApplicability::VersionUnbounded => Some("no version limits"),
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

/// The weight a severity band carries wherever it is shown: critical
/// stands out.
pub fn severity_weight(band: SeverityBand) -> Weight {
    match band {
        SeverityBand::Critical => Weight::Bold,
        SeverityBand::High | SeverityBand::Medium | SeverityBand::Low | SeverityBand::Unknown => {
            Weight::Normal
        }
    }
}

/// The 256-color palette index of the KEV marker: grype's bright pink,
/// shared with critical.
pub const KEV_PALETTE_INDEX: u8 = 198;

/// The color of the KEV marker.
pub const KEV_COLOR: Color = Color::AnsiValue(KEV_PALETTE_INDEX);
