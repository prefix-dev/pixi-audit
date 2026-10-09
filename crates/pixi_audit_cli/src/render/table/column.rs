//! The columns a vulnerability match can be shown in. Each column knows its
//! header, how to render a vulnerability match into a cell, and how two
//! vulnerability matches order under it, so `--columns` and `--sort-by` are
//! the same enum.

use std::cmp::Ordering;

use clap::ValueEnum;
use iocraft::prelude::{Color, Weight};
use pixi_audit::{
    FixAvailability, IgnoreMode, Match, MatchConfidence, PackageEcosystem, SeverityRating, SortKey,
};

use super::grid::{Cell, Span};
use crate::render::{epss_label, kev_label, risk_label};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Column {
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
    /// `kev` for vulnerability matches in CISA's KEV catalog, `kev, ransomware` when
    /// used in ransomware campaigns; empty otherwise. The risk column
    /// already marks these, so this is mostly a sort key.
    Kev,
    Environments,
    Aliases,
    Summary,
    Url,
    /// Why a vulnerability match sits in the ignored section; empty elsewhere.
    Ignored,
    /// How the advisory's version data matched the package.
    Confidence,
}

/// Columns shown when `--columns` is not given, in this order. The package
/// kind is not a column by default: like `pixi lock`, a `C`/`P` marker
/// precedes the name. Neither is the source: only conda-forge and PyPI are
/// ever queried, so for a vulnerability match the marker already says which it is.
/// Nor is the confidence: most matches are evaluated, so the Vulnerability
/// column flags the ones that are not.
pub const DEFAULT_COLUMNS: [Column; 8] = [
    Column::Name,
    Column::Version,
    Column::FixedIn,
    Column::Vulnerability,
    Column::Severity,
    Column::Epss,
    Column::Risk,
    Column::Environments,
];

/// Per-row context a cell may depend on beyond the vulnerability match itself.
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
    /// The Confidence column is shown, so the Vulnerability cell need not flag
    /// weak matches itself.
    pub confidence_column: bool,
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

impl Column {
    pub fn header(self) -> &'static str {
        match self {
            Column::Name => "Name",
            Column::Version => "Version",
            Column::FixedIn => "Fixed in",
            Column::Kind => "Kind",
            Column::Source => "Source",
            Column::Vulnerability => "Vulnerability",
            Column::Severity => "Severity",
            Column::Epss => "EPSS",
            Column::Risk => "Risk",
            Column::Kev => "KEV",
            Column::Environments => "Environments",
            Column::Aliases => "Aliases",
            Column::Summary => "Summary",
            Column::Url => "URL",
            Column::Ignored => "Ignored",
            Column::Confidence => "Confidence",
        }
    }

    /// The header of each grid column this column occupies. The name column
    /// spans two: the kind marker and the name itself, so names line up
    /// whatever the marker's width.
    pub fn headers(self) -> Vec<&'static str> {
        match self {
            Column::Name => vec!["", "Name"],
            other => vec![other.header()],
        }
    }

    /// One cell per column of [`Column::headers`].
    pub fn cells(self, vuln_match: &Match, context: RowContext) -> Vec<Cell> {
        match self {
            Column::Name => vec![
                kind_cell(&vuln_match.package.ecosystem, context),
                name_cell(&vuln_match.package.name.to_string(), context),
            ],
            other => vec![other.cell(vuln_match, context)],
        }
    }

    pub fn cell(self, vuln_match: &Match, context: RowContext) -> Cell {
        match self {
            Column::Name => name_cell(&vuln_match.package.name.to_string(), context),
            Column::Version => Cell::new(vuln_match.package.version.clone())
                .weight(context.identity_weight(Weight::Normal)),
            Column::FixedIn => fixed_in(vuln_match),
            Column::Kind => {
                let (name, color) = kind(&vuln_match.package.ecosystem);
                Cell::new(name).color(color)
            }
            Column::Source => Cell::new(vuln_match.package.ecosystem.to_string()),
            Column::Vulnerability => {
                let url = vuln_match.url.clone().filter(|_| context.hyperlinks);
                let cell = Cell::new(vuln_match.id.clone()).hyperlink(url);
                match weak_confidence_label(vuln_match.match_confidence) {
                    Some(label) if !context.confidence_column => {
                        cell.then(Span::new(format!(" ({label})")).weight(Weight::Light))
                    }
                    _ => cell,
                }
            }
            Column::Severity => severity(vuln_match.severity),
            Column::Epss => epss_label(&vuln_match.epss).map_or_else(Cell::empty, Cell::new),
            Column::Risk => risk_cell(vuln_match),
            Column::Kev => kev_label(&vuln_match.kev).map_or_else(Cell::empty, |label| {
                Cell::new(label).color(KEV_COLOR).weight(Weight::Bold)
            }),
            Column::Environments => environments_cell(&vuln_match.environments),
            Column::Aliases => Cell::new(vuln_match.aliases.join(", ")),
            Column::Summary => Cell::new(vuln_match.summary.clone().unwrap_or_default()),
            Column::Url => Cell::new(vuln_match.url.clone().unwrap_or_default()),
            Column::Ignored => match vuln_match.ignore_mode {
                Some(IgnoreMode::UntilFixed) => {
                    Cell::new("until a fix is released").weight(Weight::Light)
                }
                Some(IgnoreMode::Permanent) => Cell::new("permanent").weight(Weight::Light),
                None => Cell::empty(),
            },
            Column::Confidence => match confidence_label(vuln_match.match_confidence) {
                Some(label) => {
                    let cell = Cell::new(label);
                    if weak_confidence_label(vuln_match.match_confidence).is_some() {
                        cell.weight(Weight::Light)
                    } else {
                        cell
                    }
                }
                None => Cell::empty(),
            },
        }
    }

    /// The order two vulnerability matches take when the table is sorted by this column.
    /// Risk, severity, EPSS, and KEV sort highest first and break ties the
    /// way the report's [`SortKey`] does; everything else ascends,
    /// ties keeping their existing order.
    pub fn compare(self, a: &Match, b: &Match) -> Ordering {
        match self {
            // By spelling, not by `PackageName`'s ecosystem-first derive.
            Column::Name => (a.package.name.as_str(), &a.package.version)
                .cmp(&(b.package.name.as_str(), &b.package.version)),
            Column::Version => a.package.version.cmp(&b.package.version),
            // Fixed versions first, ordered by version; no fix last.
            Column::FixedIn => match (a.fixed_versions.first(), b.fixed_versions.first()) {
                (Some(x), Some(y)) => x.cmp(y),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            },
            Column::Kind => kind(&a.package.ecosystem)
                .0
                .cmp(kind(&b.package.ecosystem).0),
            Column::Source => a.package.ecosystem.cmp(&b.package.ecosystem),
            Column::Vulnerability => a.id.cmp(&b.id),
            Column::Severity => SortKey::Severity.compare(a, b),
            Column::Epss => SortKey::Epss.compare(a, b),
            Column::Risk => SortKey::Risk.compare(a, b),
            Column::Kev => SortKey::Kev.compare(a, b),
            Column::Environments => a.environments.cmp(&b.environments),
            Column::Aliases => a.aliases.cmp(&b.aliases),
            Column::Summary => a.summary.cmp(&b.summary),
            Column::Url => a.url.cmp(&b.url),
            Column::Ignored => a.ignore_mode.is_some().cmp(&b.ignore_mode.is_some()),
            // Most confident first; unspecified last.
            Column::Confidence => b.match_confidence.cmp(&a.match_confidence),
        }
    }
}

/// Vulnerability matches in `sort_by` order, ties keeping the report's order.
pub fn sorted(matches: &[Match], sort_by: Column) -> Vec<&Match> {
    let mut rows: Vec<&Match> = matches.iter().collect();
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
fn fixed_in(vuln_match: &Match) -> Cell {
    match vuln_match.fix_availability() {
        FixAvailability::Available => {
            Cell::new(vuln_match.fixed_versions.join(", ")).color(Color::Green)
        }
        FixAvailability::ElsewhereOnly => {
            Cell::new(crate::render::fix_elsewhere_labels(vuln_match).join(", "))
                .weight(Weight::Light)
        }
        FixAvailability::None => Cell::empty(),
    }
}

/// The risk score, with grype's `(kev)` marker after it for vulnerability matches in
/// the catalog. Blank without threat data.
fn risk_cell(vuln_match: &Match) -> Cell {
    let Some(risk) = risk_label(vuln_match.risk) else {
        return Cell::empty();
    };
    let cell = Cell::new(risk);
    match kev_label(&vuln_match.kev) {
        Some(kev) => cell.then(
            Span::new(format!(" ({kev})"))
                .color(KEV_COLOR)
                .weight(Weight::Bold),
        ),
        None => cell,
    }
}

fn severity(rating: SeverityRating) -> Cell {
    let mut name = rating.name().to_string();
    if let Some(first) = name.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    Cell::new(name)
        .color(severity_color(rating))
        .weight(severity_weight(rating))
}

/// The color a severity rating carries wherever it is shown: grype's
/// palette, as 256-color indexes so it reads the same on any terminal
/// theme.
pub fn severity_color(rating: SeverityRating) -> Option<Color> {
    Some(Color::AnsiValue(severity_palette_index(rating)))
}

/// The 256-color palette index behind [`severity_color`], for renderers
/// that do not go through iocraft.
pub fn severity_palette_index(rating: SeverityRating) -> u8 {
    match rating {
        SeverityRating::Critical => 198, // bright pink
        SeverityRating::High => 203,     // salmon
        SeverityRating::Medium => 178,   // gold
        SeverityRating::Low => 36,       // teal
        SeverityRating::Unknown => 12,   // light blue
    }
}

/// The match confidence as the Confidence column shows it; `None` when no
/// confidence metadata was recorded.
pub fn confidence_label(confidence: MatchConfidence) -> Option<&'static str> {
    match confidence {
        MatchConfidence::Evaluated => Some("affects version"),
        MatchConfidence::Unevaluated => Some("version not checked"),
        MatchConfidence::VersionUnbounded => Some("no version limits"),
        MatchConfidence::Unspecified => None,
    }
}

/// The label of a match worth flagging next to the advisory: one basilisk
/// could not evaluate, or one with no version bounds at all.
pub fn weak_confidence_label(confidence: MatchConfidence) -> Option<&'static str> {
    match confidence {
        MatchConfidence::Unevaluated | MatchConfidence::VersionUnbounded => {
            confidence_label(confidence)
        }
        MatchConfidence::Evaluated | MatchConfidence::Unspecified => None,
    }
}

/// The weight a severity rating carries wherever it is shown: critical
/// stands out.
pub fn severity_weight(rating: SeverityRating) -> Weight {
    match rating {
        SeverityRating::Critical => Weight::Bold,
        SeverityRating::High
        | SeverityRating::Medium
        | SeverityRating::Low
        | SeverityRating::Unknown => Weight::Normal,
    }
}

/// The 256-color palette index of the KEV marker: grype's bright pink,
/// shared with critical.
pub const KEV_PALETTE_INDEX: u8 = 198;

/// The color of the KEV marker.
pub const KEV_COLOR: Color = Color::AnsiValue(KEV_PALETTE_INDEX);
