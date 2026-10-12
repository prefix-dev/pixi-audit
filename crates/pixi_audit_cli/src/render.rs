use std::collections::BTreeSet;
use std::fmt::Write as _;

use console::style;
use iocraft::prelude::Weight;
use pixi_audit::{
    AuditReport, CondaForgeBuild, EpssScore, FixAvailability, IgnoreMode, KevEntry, Match,
    MatchConfidence, OtherEcosystemFix, PackageEcosystem, PackageId, RansomwareCampaignUse,
    RiskScore, SeverityRating, ThreatSourceStatus, UpstreamRelease,
};
use supports_hyperlinks::Stream;

/// How [`render_human`] adapts its output to the terminal it is written to.
#[derive(Debug, Clone, Copy)]
pub struct RenderOptions {
    /// Wrap each advisory ID in an OSC 8 hyperlink instead of printing its URL
    /// on a separate line.
    pub hyperlinks: bool,
    /// Whether this report is the result of a completed `--fix` attempt.
    pub fix_attempted: bool,
    /// Whether `--fix` can edit a manifest beside the audited lock file.
    pub manifest_available: bool,
    /// Whether to explain report terminology after the recommended actions.
    pub explain: bool,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            hyperlinks: false,
            fix_attempted: false,
            manifest_available: true,
            explain: false,
        }
    }
}

impl RenderOptions {
    /// Detect what stdout supports. Hyperlinks require color to be enabled as
    /// well, so `NO_COLOR` and piped output stay plain text.
    pub fn detect_stdout() -> Self {
        Self {
            hyperlinks: console::colors_enabled() && supports_hyperlinks::on(Stream::Stdout),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuidanceOptions {
    pub fix_attempted: bool,
    pub manifest_available: bool,
    pub explain: bool,
}

impl Default for GuidanceOptions {
    fn default() -> Self {
        Self {
            fix_attempted: false,
            manifest_available: true,
            explain: false,
        }
    }
}

impl From<RenderOptions> for GuidanceOptions {
    fn from(options: RenderOptions) -> Self {
        Self {
            fix_attempted: options.fix_attempted,
            manifest_available: options.manifest_available,
            explain: options.explain,
        }
    }
}

pub fn render_human(report: &AuditReport, options: RenderOptions) -> String {
    let mut out = String::new();
    if !report.not_audited.is_empty() {
        writeln!(
            out,
            "{} package(s) could not be audited:",
            report.not_audited.len()
        )
        .unwrap();
        for package in &report.not_audited {
            writeln!(
                out,
                "  {} {} ({}) — {}",
                package.name,
                package.version.as_deref().unwrap_or("?"),
                package.ecosystem,
                package.environments.join(", ")
            )
            .unwrap();
        }
        out.push('\n');
    }

    let columns = ThreatColumns::for_report(report);
    for group in grouped(&report.matches) {
        writeln!(out, "{}", group.header).unwrap();
        for vuln_match in group.members {
            let id = match_id(vuln_match, options);
            let severity = severity_cell(vuln_match.severity)
                .map(|cell| format!("  {cell}"))
                .unwrap_or_default();
            writeln!(
                out,
                "  {id}{severity}{}{}{}",
                columns.cells(vuln_match),
                fix_note(vuln_match),
                confidence_note(vuln_match)
                    .map(|note| format!("  {}", style(note).dim()))
                    .unwrap_or_default()
            )
            .unwrap();
            if let Some(url) = &vuln_match.url
                && !options.hyperlinks
            {
                writeln!(out, "  {}", style(url).dim()).unwrap();
            }
        }
        out.push('\n');
    }

    if !report.ignored.is_empty() {
        writeln!(
            out,
            "Ignored {} vulnerability match(es):",
            report.ignored.len()
        )
        .unwrap();
        for vuln_match in &report.ignored {
            let marker = match vuln_match.ignore_mode {
                Some(IgnoreMode::UntilFixed) => " — until a fix is released",
                Some(IgnoreMode::Permanent) | None => "",
            };
            writeln!(
                out,
                "  {} ({} {}){marker}",
                vuln_match.id, vuln_match.package.name, vuln_match.package.version
            )
            .unwrap();
        }
        out.push('\n');
    }

    let summary = &report.summary;
    if summary.vulnerable > 0 {
        let packages: BTreeSet<&PackageId> = report.matches.iter().map(|f| &f.package).collect();
        writeln!(
            out,
            "{} vulnerabilities in {} package(s) ({} audited, {} ignored, {} not audited)",
            style(summary.vulnerable).red().bold(),
            packages.len(),
            summary.audited,
            summary.ignored,
            summary.not_audited
        )
        .unwrap();
    } else {
        writeln!(
            out,
            "{} ({} audited, {} ignored, {} not audited)",
            style("No vulnerabilities found").green(),
            summary.audited,
            summary.ignored,
            summary.not_audited
        )
        .unwrap();
    }
    render_guidance(&mut out, report, options.into());
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KevSummary {
    Loaded(usize),
    Unavailable,
    NotChecked,
}

pub(crate) const EXPLAIN_HINT: &str = "Add `--explain` for scoring and report definitions.";
pub(crate) const EXPLANATION_TERM_PALETTE_INDEX: u8 = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExplanationEntry {
    pub(crate) label: &'static str,
    pub(crate) text: &'static str,
    pub(crate) indent: usize,
}

impl ExplanationEntry {
    const fn new(label: &'static str, text: &'static str) -> Self {
        Self {
            label,
            text,
            indent: 0,
        }
    }

    const fn child(label: &'static str, text: &'static str) -> Self {
        Self {
            label,
            text,
            indent: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExplanationSection {
    pub(crate) title: &'static str,
    pub(crate) entries: Vec<ExplanationEntry>,
}

impl ExplanationSection {
    pub(crate) fn label_width(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| entry.label.len())
            .max()
            .unwrap_or(0)
            + 2
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Guidance {
    highest_risk: Option<String>,
    kev: KevSummary,
    severe: usize,
    fixable_matches: usize,
    audited_packages_with_fixes: usize,
    update_targets: usize,
    elsewhere_only: usize,
    no_fix: usize,
    ignored: usize,
    not_audited: usize,
    total: usize,
}

impl Guidance {
    pub(crate) fn for_report(report: &AuditReport) -> Self {
        let matches = &report.matches;
        let highest_risk = matches
            .iter()
            .map(|vuln_match| vuln_match.risk)
            .max()
            .and_then(risk_label);
        let kev_cves = matches
            .iter()
            .flat_map(|vuln_match| &vuln_match.kev)
            .map(|entry| entry.cve.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        let kev = match &report.threat_data.kev {
            ThreatSourceStatus::Loaded { .. } => KevSummary::Loaded(kev_cves),
            ThreatSourceStatus::Failed { .. } => KevSummary::Unavailable,
            ThreatSourceStatus::Disabled => KevSummary::NotChecked,
        };
        let severe = matches
            .iter()
            .filter(|vuln_match| {
                matches!(
                    vuln_match.severity,
                    SeverityRating::Critical | SeverityRating::High
                )
            })
            .count();
        let fix_count = |status: FixAvailability| {
            matches
                .iter()
                .filter(|m| m.fix_availability() == status)
                .count()
        };
        let fixable_matches = fix_count(FixAvailability::Available);
        let audited_packages_with_fixes = matches
            .iter()
            .filter(|vuln_match| vuln_match.fix_availability() == FixAvailability::Available)
            .map(|vuln_match| &vuln_match.package)
            .collect::<BTreeSet<_>>()
            .len();
        let elsewhere_only = fix_count(FixAvailability::ElsewhereOnly);
        let no_fix = fix_count(FixAvailability::None);

        Self {
            highest_risk,
            kev,
            severe,
            fixable_matches,
            audited_packages_with_fixes,
            update_targets: report.fixable_package_names().len(),
            elsewhere_only,
            no_fix,
            ignored: report.ignored.len(),
            not_audited: report.not_audited.len(),
            total: matches.len(),
        }
    }

    pub(crate) fn assessment_lines(&self) -> Vec<String> {
        if self.total == 0 {
            return Vec::new();
        }
        let highest_risk = self
            .highest_risk
            .as_deref()
            .map(|score| format!("{score} / 100"))
            .unwrap_or_else(|| "n/a".to_string());
        let kev = match self.kev {
            KevSummary::Loaded(0) => "0 CVEs".to_string(),
            KevSummary::Loaded(number) => format!(
                "{} — exploitation confirmed in the wild",
                count(number, "CVE", "CVEs")
            ),
            KevSummary::Unavailable => "n/a — CISA KEV catalog unavailable".to_string(),
            KevSummary::NotChecked => "n/a — CISA KEV catalog not checked".to_string(),
        };
        vec![
            assessment_line("Highest risk score:", highest_risk),
            assessment_line("CISA KEV matches:", kev),
            assessment_line(
                "Critical/high vulnerability matches:",
                self.severe.to_string(),
            ),
            assessment_line(
                "Fix available in audited ecosystem:",
                format!(
                    "{} of {} across {}",
                    self.fixable_matches,
                    count(self.total, "vulnerability", "vulnerabilities"),
                    count(
                        self.audited_packages_with_fixes,
                        "audited package",
                        "audited packages"
                    )
                ),
            ),
            assessment_line(
                "Fix only elsewhere:",
                count(self.elsewhere_only, "vulnerability", "vulnerabilities"),
            ),
            assessment_line(
                "No known fix:",
                count(self.no_fix, "vulnerability", "vulnerabilities"),
            ),
        ]
    }

    pub(crate) fn next_step_lines(
        &self,
        fix_attempted: bool,
        manifest_available: bool,
    ) -> Vec<String> {
        let mut lines = Vec::new();
        if self.total == 0 {
            if self.ignored == 0 && self.not_audited == 0 {
                lines.push("None. No vulnerabilities were found in audited packages.".to_string());
                return lines;
            }
            lines.push("No active vulnerabilities were found in audited packages.".to_string());
            if self.ignored > 0 {
                lines.push(format!(
                    "Review {} periodically.",
                    count(
                        self.ignored,
                        "ignored vulnerability match",
                        "ignored vulnerability matches"
                    )
                ));
            }
        } else {
            if let KevSummary::Loaded(number) = self.kev
                && number > 0
            {
                lines.push(format!(
                    "Prioritize {} because exploitation has been confirmed in the wild.",
                    count(number, "CISA KEV match", "CISA KEV matches")
                ));
            }
            if self.fixable_matches > 0 {
                if fix_attempted {
                    let (fix, verb) = if self.fixable_matches == 1 {
                        ("a fix", "remains")
                    } else {
                        ("fixes", "remain")
                    };
                    lines.push(format!(
                        "`--fix` completed, but {} with {fix} in the audited ecosystem {verb}. Review dependency constraints and pixi's solver output.",
                        count(self.fixable_matches, "vulnerability", "vulnerabilities")
                    ));
                } else if manifest_available {
                    lines.push(format!(
                        "Re-run this audit with `--fix` to ask pixi to update {}. Fixed releases in the audited ecosystem are available for {}.",
                        count(self.update_targets, "package name", "package names"),
                        count(self.fixable_matches, "vulnerability", "vulnerabilities")
                    ));
                } else {
                    lines.push(format!(
                        "Fixed releases in the audited ecosystem are available for {} across {}, but `--fix` requires a `pixi.toml` or `pyproject.toml` next to the audited lock file. Run the same audit with `--fix` from the workspace that owns this lock file.",
                        count(self.fixable_matches, "vulnerability", "vulnerabilities"),
                        count(
                            self.audited_packages_with_fixes,
                            "audited package",
                            "audited packages"
                        )
                    ));
                }
            }
            if self.elsewhere_only > 0 {
                let (fix, pronoun) = if self.elsewhere_only == 1 {
                    ("a fix", "it")
                } else {
                    ("fixes", "them")
                };
                lines.push(format!(
                    "{} {} {fix} only elsewhere. `--fix` cannot install {pronoun}. Wait for an ecosystem build or change dependency source.",
                    count(
                        self.elsewhere_only,
                        "vulnerability",
                        "vulnerabilities"
                    ),
                    if self.elsewhere_only == 1 { "has" } else { "have" }
                ));
            }
            if self.no_fix > 0 {
                lines.push(format!(
                    "{} {} no known fix. Remove, replace, or mitigate the affected dependencies. Use `pixi audit ignore <ID> --until-fixed` only after accepting the risk.",
                    count(self.no_fix, "vulnerability", "vulnerabilities"),
                    if self.no_fix == 1 { "has" } else { "have" }
                ));
            }
        }
        if self.not_audited > 0 {
            lines.push(if self.not_audited == 1 {
                "Review 1 package that was not audited. Its source is not covered by the configured vulnerability databases.".to_string()
            } else {
                format!(
                    "Review {} packages that were not audited. Their sources are not covered by the configured vulnerability databases.",
                    self.not_audited
                )
            });
        }
        lines
    }

    pub(crate) fn explanation_sections(&self, report: &AuditReport) -> Vec<ExplanationSection> {
        let mut sections = vec![ExplanationSection {
            title: "Counts",
            entries: vec![
                ExplanationEntry::new("Package", "One locked name, version, and source."),
                ExplanationEntry::new("Vulnerability match", "One advisory affecting a package."),
                ExplanationEntry::new(
                    "CVE IDs",
                    "Standard vulnerability IDs. One vulnerability match can reference several.",
                ),
            ],
        }];

        if self.total > 0 {
            let mut threat = vec![
                ExplanationEntry::new("EPSS", "Estimated chance of exploitation within 30 days."),
                ExplanationEntry::new(
                    "Percentile",
                    "Rank among scored CVEs. 90th is higher than 90% of them.",
                ),
                ExplanationEntry::new("KEV", "CISA confirms exploitation in the wild."),
                ExplanationEntry::new(
                    "Boost",
                    "KEV adds 5%. Known ransomware use raises this to 10%.",
                ),
            ];
            if report
                .matches
                .iter()
                .any(|vuln_match| !vuln_match.kev.is_empty())
            {
                threat.push(ExplanationEntry::new(
                    "Markers",
                    "`kev, ransomware` means CISA records known ransomware use. `kev` alone means CISA does not mark that use as Known.",
                ));
            }
            sections.push(ExplanationSection {
                title: "Threat data",
                entries: threat,
            });

            sections.push(ExplanationSection {
                title: "Risk",
                entries: vec![
                    ExplanationEntry::new(
                        "Risk",
                        "A 0–100 score for ordering individual vulnerability matches.",
                    ),
                    ExplanationEntry::child(
                        "Formula",
                        "min(threat × severity × boost, 1) × 100.",
                    ),
                    ExplanationEntry::new(
                        "Threat",
                        "1.0 for any KEV match. Otherwise the highest EPSS probability, or 0 without data.",
                    ),
                    ExplanationEntry::new(
                        "Severity",
                        "Critical .90, high .75, medium/unknown .50, low .30. Averaged equally with CVSS when available.",
                    ),
                ],
            });

            sections.push(ExplanationSection {
                title: "Fixes",
                entries: vec![
                    ExplanationEntry::new(
                        "Fix available",
                        "A fixed release exists for the audited package source. The `Fixed in` column lists it.",
                    ),
                    ExplanationEntry::new(
                        "Fix only elsewhere",
                        "A fix exists elsewhere. `--fix` cannot install it.",
                    ),
                    ExplanationEntry::new(
                        "No known fix",
                        "Audit sources list no fixed release. Mitigation may still be possible.",
                    ),
                    ExplanationEntry::new(
                        "`--fix`",
                        "Raises matching direct constraints, runs `pixi update`, and audits again. A listed fix does not guarantee selection.",
                    ),
                ],
            });
        }

        let mut coverage = Vec::new();
        if self.ignored > 0 {
            coverage.push(ExplanationEntry::new(
                "Ignored",
                "Excluded from active totals and the failure decision. The package is not patched.",
            ));
        }
        if self.not_audited > 0 {
            coverage.push(ExplanationEntry::new(
                "Not audited",
                "The package source lacks vulnerability database coverage. Safety is unknown.",
            ));
        }

        let matches = report.matches.iter().chain(report.ignored.iter());
        let (version_unbounded, unevaluated) = matches.fold((false, false), |state, vuln_match| {
            (
                state.0 || vuln_match.match_confidence == MatchConfidence::VersionUnbounded,
                state.1 || vuln_match.match_confidence == MatchConfidence::Unevaluated,
            )
        });
        if version_unbounded {
            coverage.push(ExplanationEntry::new(
                "No version limits",
                "The advisory has no usable version bounds, so every version matches.",
            ));
        }
        if unevaluated {
            coverage.push(ExplanationEntry::new(
                "Version not checked",
                "The source lacks enough version data to decide whether this version is affected.",
            ));
        }
        if !coverage.is_empty() {
            sections.push(ExplanationSection {
                title: "Ignored and not audited",
                entries: coverage,
            });
        }

        sections
    }
}

fn assessment_line(label: &str, value: String) -> String {
    format!("{label:<39}{value}")
}

fn count(number: usize, singular: &str, plural: &str) -> String {
    format!("{number} {}", if number == 1 { singular } else { plural })
}

fn render_guidance(out: &mut String, report: &AuditReport, options: GuidanceOptions) {
    let guidance = Guidance::for_report(report);
    let assessment = guidance.assessment_lines();
    if !assessment.is_empty() {
        writeln!(out, "\n{}", style("Overview").bold()).unwrap();
        for line in assessment {
            writeln!(out, "  • {line}").unwrap();
        }
    }
    writeln!(out, "\n{}", style("Recommendations").bold()).unwrap();
    for line in guidance.next_step_lines(options.fix_attempted, options.manifest_available) {
        writeln!(out, "  • {line}").unwrap();
    }
    if options.explain {
        writeln!(out, "\n{}", style("Definitions").bold()).unwrap();
        for section in guidance.explanation_sections(report) {
            let width = section.label_width();
            writeln!(out, "\n  {}", style(section.title).bold()).unwrap();
            for entry in section.entries {
                let label = format!(
                    "{:indent$}{:<width$}",
                    "",
                    entry.label,
                    indent = entry.indent
                );
                write!(
                    out,
                    "    {}",
                    style(label).color256(EXPLANATION_TERM_PALETTE_INDEX).bold()
                )
                .unwrap();
                writeln!(out, "{}", entry.text).unwrap();
            }
        }
    } else {
        writeln!(out, "\n{}", style(EXPLAIN_HINT).dim()).unwrap();
    }
}

/// The vulnerability matches for one locked package, under a shared header.
struct Group<'a> {
    key: &'a PackageId,
    header: String,
    members: Vec<&'a Match>,
}

/// Groups vulnerability matches by package in first-appearance order, which keeps the
/// most severe packages first since the report is sorted by severity.
fn grouped(matches: &[Match]) -> Vec<Group<'_>> {
    let mut groups: Vec<Group<'_>> = Vec::new();
    for vuln_match in matches {
        let key = &vuln_match.package;
        match groups.iter_mut().find(|group| group.key == key) {
            Some(group) => group.members.push(vuln_match),
            None => groups.push(Group {
                key,
                header: format!(
                    "{} {} ({}) — {}",
                    style(&vuln_match.package.name).bold(),
                    vuln_match.package.version,
                    vuln_match.package.ecosystem,
                    vuln_match.environments.join(", ")
                ),
                members: vec![vuln_match],
            }),
        }
    }
    groups
}

/// The advisory ID, wrapped in an OSC 8 hyperlink to its advisory page when
/// the terminal renders those.
fn match_id(vuln_match: &Match, options: RenderOptions) -> String {
    match (&vuln_match.url, options.hyperlinks) {
        (Some(url), true) => format!("\x1b]8;;{url}\x1b\\{}\x1b]8;;\x1b\\", vuln_match.id),
        (Some(_), false) | (None, _) => vuln_match.id.clone(),
    }
}

/// A fixed-width severity label in the table's palette, or `None` for
/// unknown severity, which the grouped report leaves blank rather than
/// shouting "UNKNOWN".
fn severity_cell(rating: SeverityRating) -> Option<String> {
    if rating == SeverityRating::Unknown {
        return None;
    }
    let text = format!("{:<8}", rating.name().to_uppercase());
    let mut styled = style(text).color256(table::column::severity_palette_index(rating));
    if table::column::severity_weight(rating) == Weight::Bold {
        styled = styled.bold();
    }
    Some(styled.to_string())
}

/// Which threat-data cells a report's sources justify. Risk is shown when
/// any source is configured, EPSS only when the EPSS source is. KEV
/// entries are marked on the risk cell.
#[derive(Clone, Copy)]
struct ThreatColumns {
    risk: bool,
    epss: bool,
}

impl ThreatColumns {
    fn for_report(report: &AuditReport) -> Self {
        let configured = |status: &ThreatSourceStatus| match status {
            ThreatSourceStatus::Disabled => false,
            ThreatSourceStatus::Loaded { .. } | ThreatSourceStatus::Failed { .. } => true,
        };
        let epss = configured(&report.threat_data.epss);
        Self {
            risk: epss || configured(&report.threat_data.kev),
            epss,
        }
    }

    fn cells(self, vuln_match: &Match) -> String {
        let mut cells = String::new();
        if self.risk {
            let label = risk_label(vuln_match.risk).unwrap_or_else(|| "n/a".to_string());
            cells.push_str(&format!("  risk {label:>5}"));
            if let Some(kev) = kev_label(&vuln_match.kev) {
                cells.push_str(&format!(
                    " {}",
                    style(format!("({kev})"))
                        .color256(table::column::KEV_PALETTE_INDEX)
                        .bold()
                ));
            }
        }
        if self.epss {
            let label = epss_label(&vuln_match.epss).unwrap_or_else(|| "n/a".to_string());
            cells.push_str(&format!("  epss {label}"));
        }
        cells
    }
}

/// The risk score with one decimal, `< 0.1` below that, or `None` when
/// there is no threat data behind it.
pub fn risk_label(risk: RiskScore) -> Option<String> {
    let value = risk.value();
    if value == 0.0 {
        None
    } else if value < 0.1 {
        Some("< 0.1".to_string())
    } else {
        Some(format!("{value:.1}"))
    }
}

/// The percentile rank followed by exploit probability, such as
/// `99th · 90.8%`, or `None` without an EPSS record.
pub fn epss_label(epss: &[EpssScore]) -> Option<String> {
    let score = highest_epss(epss)?;
    let probability = score.epss * 100.0;
    let percentile = ordinal((score.percentile * 100.0).floor() as u32);
    if probability < 0.1 {
        Some(format!("{percentile} · < 0.1%"))
    } else {
        Some(format!("{percentile} · {probability:.1}%"))
    }
}

/// EPSS probability followed by percentile for established machine-oriented
/// renderers whose text is kept stable.
pub fn epss_probability_first_label(epss: &[EpssScore]) -> Option<String> {
    let score = highest_epss(epss)?;
    let probability = score.epss * 100.0;
    let percentile = ordinal((score.percentile * 100.0).floor() as u32);
    if probability < 0.1 {
        Some(format!("< 0.1% ({percentile})"))
    } else {
        Some(format!("{probability:.1}% ({percentile})"))
    }
}

fn highest_epss(epss: &[EpssScore]) -> Option<&EpssScore> {
    epss.iter()
        .max_by(|left, right| left.epss.total_cmp(&right.epss))
}

fn ordinal(number: u32) -> String {
    let suffix = match (number % 100, number % 10) {
        (11..=13, _) => "th",
        (_, 1) => "st",
        (_, 2) => "nd",
        (_, 3) => "rd",
        _ => "th",
    };
    format!("{number}{suffix}")
}

/// `kev`, or `kev, ransomware` when any entry reports ransomware use;
/// `None` for vulnerability matches outside the catalog.
pub fn kev_label(entries: &[KevEntry]) -> Option<&'static str> {
    if entries.is_empty() {
        return None;
    }
    let ransomware = entries
        .iter()
        .any(|entry| entry.known_ransomware_campaign_use == RansomwareCampaignUse::Known);
    Some(if ransomware { "kev, ransomware" } else { "kev" })
}

fn fix_note(vuln_match: &Match) -> String {
    match vuln_match.fix_availability() {
        FixAvailability::Available => {
            format!("  fixed in: {}", vuln_match.fixed_versions.join(", "))
        }
        FixAvailability::ElsewhereOnly => format!(
            "  fix released elsewhere: {}",
            describe_fixes_elsewhere(vuln_match)
        ),
        FixAvailability::None => "  no known fixed version".to_string(),
    }
}

/// Describe the advisory's version match in human-readable output.
pub fn confidence_note(vuln_match: &Match) -> Option<&'static str> {
    match vuln_match.match_confidence {
        MatchConfidence::VersionUnbounded => Some("confidence: no version limits"),
        MatchConfidence::Unevaluated => Some("confidence: version not checked"),
        MatchConfidence::Evaluated => Some("confidence: affects version"),
        MatchConfidence::Unspecified
            if vuln_match.package.ecosystem == PackageEcosystem::CondaForge =>
        {
            Some("match details unavailable")
        }
        MatchConfidence::Unspecified => None,
    }
}

/// Every fix outside the audited ecosystem spelled out, `; `-separated:
/// other-ecosystem fixes first, then upstream releases.
pub fn describe_fixes_elsewhere(vuln_match: &Match) -> String {
    vuln_match
        .other_ecosystem_fixes
        .iter()
        .map(describe_other_ecosystem_fix)
        .chain(
            vuln_match
                .upstream_releases
                .iter()
                .map(describe_upstream_release),
        )
        .collect::<Vec<_>>()
        .join("; ")
}

/// An other-ecosystem fix in a sentence: `3.2.0 on PyPI`.
pub fn describe_other_ecosystem_fix(fix: &OtherEcosystemFix) -> String {
    format!("{} on {}", fix.version, fix.ecosystem)
}

/// An upstream release in a sentence, with what basilisk knows about a
/// conda-forge build of it.
pub fn describe_upstream_release(release: &UpstreamRelease) -> String {
    match release.conda_forge_build {
        CondaForgeBuild::Missing => {
            format!(
                "{} released upstream, no conda-forge build",
                release.version
            )
        }
        CondaForgeBuild::Unknown => format!(
            "{} released upstream, conda-forge build unconfirmed",
            release.version
        ),
        CondaForgeBuild::Available => format!("{} released upstream", release.version),
    }
}

/// Every fix outside the audited ecosystem as a short table label:
/// `PyPI: 3.2.0`, `upstream: 2.8.2`, or `upstream: 2.8.2 (unconfirmed)`
/// when basilisk could not tell whether conda-forge has a build.
pub fn fix_elsewhere_labels(vuln_match: &Match) -> Vec<String> {
    vuln_match
        .other_ecosystem_fixes
        .iter()
        .map(other_ecosystem_fix_label)
        .chain(
            vuln_match
                .upstream_releases
                .iter()
                .map(upstream_release_label),
        )
        .collect()
}

/// An other-ecosystem fix as a short table label: `PyPI: 3.2.0`.
pub fn other_ecosystem_fix_label(fix: &OtherEcosystemFix) -> String {
    format!("{}: {}", fix.ecosystem, fix.version)
}

/// An upstream release as a short table label: `upstream: 2.8.2`, with
/// `(unconfirmed)` when basilisk could not tell whether conda-forge has a
/// build.
pub fn upstream_release_label(release: &UpstreamRelease) -> String {
    match release.conda_forge_build {
        CondaForgeBuild::Unknown => format!("upstream: {} (unconfirmed)", release.version),
        CondaForgeBuild::Missing | CondaForgeBuild::Available => {
            format!("upstream: {}", release.version)
        }
    }
}

/// Where a vulnerability match's fix stands, as a sentence fragment:
/// `fixed in 3.1.1`, `fix released elsewhere: ...`, or
/// `no known fixed version`.
pub fn fix_summary(vuln_match: &Match) -> String {
    match vuln_match.fix_availability() {
        FixAvailability::Available => {
            format!("fixed in {}", vuln_match.fixed_versions.join(", "))
        }
        FixAvailability::ElsewhereOnly => format!(
            "fix released elsewhere: {}",
            describe_fixes_elsewhere(vuln_match)
        ),
        FixAvailability::None => "no known fixed version".to_string(),
    }
}

pub mod sarif;
pub mod table;

#[cfg(test)]
mod tests;
