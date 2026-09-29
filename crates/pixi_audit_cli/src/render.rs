use std::collections::BTreeSet;
use std::fmt::Write as _;

use console::style;
use iocraft::prelude::Weight;
use pixi_audit::{
    AuditReport, CondaPublication, EpssScore, Finding, FixStatus, IgnoreReason, KnownExploited,
    MatchApplicability, PackageEcosystem, PackageId, RansomwareCampaignUse, RiskScore,
    SeverityBand, ThreatSourceStatus, UpstreamFix, UpstreamOrigin,
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
    if !report.unchecked.is_empty() {
        writeln!(
            out,
            "{} package(s) could not be checked:",
            report.unchecked.len()
        )
        .unwrap();
        for package in &report.unchecked {
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
    for group in grouped(&report.vulnerabilities) {
        writeln!(out, "{}", group.header).unwrap();
        for finding in group.members {
            let id = finding_id(finding, options);
            let severity = severity_cell(finding.severity)
                .map(|cell| format!("  {cell}"))
                .unwrap_or_default();
            writeln!(
                out,
                "  {id}{severity}{}{}{}",
                columns.cells(finding),
                fix_note(finding),
                match_note(finding)
                    .map(|note| format!("  {}", style(note).dim()))
                    .unwrap_or_default()
            )
            .unwrap();
            if let Some(url) = &finding.url
                && !options.hyperlinks
            {
                writeln!(out, "  {}", style(url).dim()).unwrap();
            }
        }
        out.push('\n');
    }

    if !report.ignored.is_empty() {
        writeln!(out, "Ignored {} finding(s):", report.ignored.len()).unwrap();
        for finding in &report.ignored {
            let marker = match finding.ignore_reason {
                Some(IgnoreReason::UntilFixed) => " — until a fix is released",
                Some(IgnoreReason::Always) | None => "",
            };
            writeln!(
                out,
                "  {} ({} {}){marker}",
                finding.id, finding.package.name, finding.package.version
            )
            .unwrap();
        }
        out.push('\n');
    }

    let summary = &report.summary;
    if summary.vulnerable > 0 {
        let packages: BTreeSet<&PackageId> =
            report.vulnerabilities.iter().map(|f| &f.package).collect();
        writeln!(
            out,
            "{} vulnerabilities in {} package(s) ({} audited, {} ignored, {} unchecked)",
            style(summary.vulnerable).red().bold(),
            packages.len(),
            summary.audited,
            summary.ignored,
            summary.unchecked
        )
        .unwrap();
    } else {
        writeln!(
            out,
            "{} ({} audited, {} ignored, {} unchecked)",
            style("No vulnerabilities found").green(),
            summary.audited,
            summary.ignored,
            summary.unchecked
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
    fixable_findings: usize,
    audited_packages_with_fixes: usize,
    update_targets: usize,
    upstream_only: usize,
    unfixed: usize,
    ignored: usize,
    unchecked: usize,
    total: usize,
}

impl Guidance {
    pub(crate) fn for_report(report: &AuditReport) -> Self {
        let findings = &report.vulnerabilities;
        let highest_risk = findings
            .iter()
            .map(|finding| finding.risk)
            .max()
            .and_then(risk_label);
        let known_exploited = findings
            .iter()
            .flat_map(|finding| &finding.known_exploited)
            .map(|entry| entry.cve.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        let kev = match &report.threat_data.kev {
            ThreatSourceStatus::Loaded { .. } => KevSummary::Loaded(known_exploited),
            ThreatSourceStatus::Failed { .. } => KevSummary::Unavailable,
            ThreatSourceStatus::Disabled => KevSummary::NotChecked,
        };
        let severe = findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.severity,
                    SeverityBand::Critical | SeverityBand::High
                )
            })
            .count();
        let fix_count =
            |status: FixStatus| findings.iter().filter(|f| f.fix_status() == status).count();
        let fixable_findings = fix_count(FixStatus::Available);
        let audited_packages_with_fixes = findings
            .iter()
            .filter(|finding| finding.fix_status() == FixStatus::Available)
            .map(|finding| &finding.package)
            .collect::<BTreeSet<_>>()
            .len();
        let upstream_only = fix_count(FixStatus::UpstreamOnly);
        let unfixed = fix_count(FixStatus::Unfixed);

        Self {
            highest_risk,
            kev,
            severe,
            fixable_findings,
            audited_packages_with_fixes,
            update_targets: crate::fix::fixable_package_names(report).len(),
            upstream_only,
            unfixed,
            ignored: report.ignored.len(),
            unchecked: report.unchecked.len(),
            total: findings.len(),
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
            assessment_line("Highest finding prioritization score:", highest_risk),
            assessment_line("CISA KEV matches:", kev),
            assessment_line("Critical/high findings:", self.severe.to_string()),
            assessment_line(
                "Fix available in audited ecosystem:",
                format!(
                    "{} of {} across {}",
                    self.fixable_findings,
                    count(self.total, "vulnerability", "vulnerabilities"),
                    count(
                        self.audited_packages_with_fixes,
                        "audited package",
                        "audited packages"
                    )
                ),
            ),
            assessment_line(
                "Fix only upstream:",
                count(self.upstream_only, "vulnerability", "vulnerabilities"),
            ),
            assessment_line(
                "No known fix:",
                count(self.unfixed, "vulnerability", "vulnerabilities"),
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
            if self.ignored == 0 && self.unchecked == 0 {
                lines.push("None. No vulnerabilities were found in checked packages.".to_string());
                return lines;
            }
            lines.push("No active vulnerabilities were found in checked packages.".to_string());
            if self.ignored > 0 {
                lines.push(format!(
                    "Review {} periodically.",
                    count(self.ignored, "ignored finding", "ignored findings")
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
            if self.fixable_findings > 0 {
                if fix_attempted {
                    let (fix, verb) = if self.fixable_findings == 1 {
                        ("a fix", "remains")
                    } else {
                        ("fixes", "remain")
                    };
                    lines.push(format!(
                        "`--fix` completed, but {} with {fix} in the audited ecosystem {verb}. Review dependency constraints and pixi's solver output.",
                        count(self.fixable_findings, "vulnerability", "vulnerabilities")
                    ));
                } else if manifest_available {
                    lines.push(format!(
                        "Re-run this audit with `--fix` to ask pixi to update {}. Fixed releases in the audited ecosystem are available for {}.",
                        count(self.update_targets, "package name", "package names"),
                        count(self.fixable_findings, "vulnerability", "vulnerabilities")
                    ));
                } else {
                    lines.push(format!(
                        "Fixed releases in the audited ecosystem are available for {} across {}, but `--fix` requires a `pixi.toml` or `pyproject.toml` next to the audited lock file. Run the same audit with `--fix` from the workspace that owns this lock file.",
                        count(self.fixable_findings, "vulnerability", "vulnerabilities"),
                        count(
                            self.audited_packages_with_fixes,
                            "audited package",
                            "audited packages"
                        )
                    ));
                }
            }
            if self.upstream_only > 0 {
                let (fix, pronoun) = if self.upstream_only == 1 {
                    ("a fix", "it")
                } else {
                    ("fixes", "them")
                };
                lines.push(format!(
                    "{} {} {fix} only upstream. `--fix` cannot install {pronoun}. Wait for an ecosystem build or change dependency source.",
                    count(
                        self.upstream_only,
                        "vulnerability",
                        "vulnerabilities"
                    ),
                    if self.upstream_only == 1 { "has" } else { "have" }
                ));
            }
            if self.unfixed > 0 {
                lines.push(format!(
                    "{} {} no known fix. Remove, replace, or mitigate the affected dependencies. Use `pixi audit ignore <ID> --until-fixed` only after accepting the risk.",
                    count(self.unfixed, "vulnerability", "vulnerabilities"),
                    if self.unfixed == 1 { "has" } else { "have" }
                ));
            }
        }
        if self.unchecked > 0 {
            lines.push(if self.unchecked == 1 {
                "Review 1 unchecked package. Its source is not covered by the configured vulnerability databases.".to_string()
            } else {
                format!(
                    "Review {} unchecked packages. Their sources are not covered by the configured vulnerability databases.",
                    self.unchecked
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
                ExplanationEntry::new("Finding", "One vulnerability record affecting a package."),
                ExplanationEntry::new(
                    "CVE IDs",
                    "Standard vulnerability IDs. One finding can reference several.",
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
                .vulnerabilities
                .iter()
                .any(|finding| !finding.known_exploited.is_empty())
            {
                threat.push(ExplanationEntry::new(
                    "Markers",
                    "`kev, ransomware` means CISA records known ransomware use. `kev` alone means CISA does not mark that use as Known.",
                ));
            }
            sections.push(ExplanationSection {
                title: "Threat signals",
                entries: threat,
            });

            sections.push(ExplanationSection {
                title: "Prioritization",
                entries: vec![
                    ExplanationEntry::new(
                        "Risk",
                        "A 0–100 score for ordering individual findings.",
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
                        "Ecosystem fix",
                        "A fixed release exists for the audited package source. The `Fixed in` column lists it.",
                    ),
                    ExplanationEntry::new(
                        "Fix only upstream",
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
        if self.unchecked > 0 {
            coverage.push(ExplanationEntry::new(
                "Unchecked",
                "The package source lacks vulnerability database coverage. Safety is unknown.",
            ));
        }

        let findings = report.vulnerabilities.iter().chain(report.ignored.iter());
        let (version_unbounded, unevaluated) = findings.fold((false, false), |state, finding| {
            (
                state.0 || finding.applicability == MatchApplicability::VersionUnbounded,
                state.1 || finding.applicability == MatchApplicability::Unevaluated,
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
                title: "Coverage",
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
        writeln!(out, "\n{}", style("Assessment").bold()).unwrap();
        for line in assessment {
            writeln!(out, "  • {line}").unwrap();
        }
    }
    writeln!(out, "\n{}", style("Next steps").bold()).unwrap();
    for line in guidance.next_step_lines(options.fix_attempted, options.manifest_available) {
        writeln!(out, "  • {line}").unwrap();
    }
    if options.explain {
        writeln!(out, "\n{}", style("How this report works").bold()).unwrap();
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

/// The findings for one locked package, under a shared header.
struct Group<'a> {
    key: &'a PackageId,
    header: String,
    members: Vec<&'a Finding>,
}

/// Groups findings by package in first-appearance order, which keeps the
/// most severe packages first since the report is sorted by severity.
fn grouped(findings: &[Finding]) -> Vec<Group<'_>> {
    let mut groups: Vec<Group<'_>> = Vec::new();
    for finding in findings {
        let key = &finding.package;
        match groups.iter_mut().find(|group| group.key == key) {
            Some(group) => group.members.push(finding),
            None => groups.push(Group {
                key,
                header: format!(
                    "{} {} ({}) — {}",
                    style(&finding.package.name).bold(),
                    finding.package.version,
                    finding.package.ecosystem,
                    finding.environments.join(", ")
                ),
                members: vec![finding],
            }),
        }
    }
    groups
}

/// The advisory ID, wrapped in an OSC 8 hyperlink to its advisory page when
/// the terminal renders those.
fn finding_id(finding: &Finding, options: RenderOptions) -> String {
    match (&finding.url, options.hyperlinks) {
        (Some(url), true) => format!("\x1b]8;;{url}\x1b\\{}\x1b]8;;\x1b\\", finding.id),
        (Some(_), false) | (None, _) => finding.id.clone(),
    }
}

/// A fixed-width severity label in the table's palette, or `None` for
/// unknown severity, which the grouped report leaves blank rather than
/// shouting "UNKNOWN".
fn severity_cell(band: SeverityBand) -> Option<String> {
    if band == SeverityBand::Unknown {
        return None;
    }
    let text = format!("{:<8}", band.name().to_uppercase());
    let mut styled = style(text).color256(table::field::severity_palette_index(band));
    if table::field::severity_weight(band) == Weight::Bold {
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

    fn cells(self, finding: &Finding) -> String {
        let mut cells = String::new();
        if self.risk {
            let label = risk_label(finding.risk).unwrap_or_else(|| "n/a".to_string());
            cells.push_str(&format!("  risk {label:>5}"));
            if let Some(kev) = kev_label(&finding.known_exploited) {
                cells.push_str(&format!(
                    " {}",
                    style(format!("({kev})"))
                        .color256(table::field::KEV_PALETTE_INDEX)
                        .bold()
                ));
            }
        }
        if self.epss {
            let label = epss_label(&finding.epss).unwrap_or_else(|| "n/a".to_string());
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
/// `None` for findings outside the catalog.
pub fn kev_label(entries: &[KnownExploited]) -> Option<&'static str> {
    if entries.is_empty() {
        return None;
    }
    let ransomware = entries
        .iter()
        .any(|entry| entry.known_ransomware_campaign_use == RansomwareCampaignUse::Known);
    Some(if ransomware { "kev, ransomware" } else { "kev" })
}

fn fix_note(finding: &Finding) -> String {
    match finding.fix_status() {
        FixStatus::Available => format!("  fixed in: {}", finding.fixed_versions.join(", ")),
        FixStatus::UpstreamOnly => format!(
            "  fix released elsewhere: {}",
            describe_upstream_fixes(finding)
        ),
        FixStatus::Unfixed => "  no known fixed version".to_string(),
    }
}

/// Describe the advisory's version match in human-readable output.
pub fn match_note(finding: &Finding) -> Option<&'static str> {
    match finding.applicability {
        MatchApplicability::VersionUnbounded => Some("match: no version limits"),
        MatchApplicability::Unevaluated => Some("match: version not checked"),
        MatchApplicability::Evaluated => Some("match: affects version"),
        MatchApplicability::Unspecified
            if finding.package.ecosystem == PackageEcosystem::CondaForge =>
        {
            Some("match details unavailable")
        }
        MatchApplicability::Unspecified => None,
    }
}

/// Every upstream fix of a finding spelled out, `; `-separated.
pub fn describe_upstream_fixes(finding: &Finding) -> String {
    finding
        .upstream_fixes
        .iter()
        .map(describe_upstream_fix)
        .collect::<Vec<_>>()
        .join("; ")
}

/// One upstream fix in a sentence: where it exists and what that means for
/// the audited package.
pub fn describe_upstream_fix(fix: &UpstreamFix) -> String {
    match &fix.origin {
        UpstreamOrigin::Ecosystem { ecosystem } => format!("{} on {ecosystem}", fix.version),
        UpstreamOrigin::Project { conda_publication } => match conda_publication {
            CondaPublication::NotPublished => {
                format!("{} released upstream, no conda-forge build", fix.version)
            }
            CondaPublication::Unknown => format!(
                "{} released upstream, conda-forge build unconfirmed",
                fix.version
            ),
            CondaPublication::Published => format!("{} released upstream", fix.version),
        },
    }
}

/// One upstream fix as a short table label: `PyPI: 3.2.0`,
/// `upstream: 2.8.2`, or `upstream: 2.8.2 (unconfirmed)` when basilisk
/// could not tell whether conda-forge has a build.
pub fn upstream_fix_label(fix: &UpstreamFix) -> String {
    match &fix.origin {
        UpstreamOrigin::Ecosystem { ecosystem } => format!("{ecosystem}: {}", fix.version),
        UpstreamOrigin::Project { conda_publication } => match conda_publication {
            CondaPublication::Unknown => format!("upstream: {} (unconfirmed)", fix.version),
            CondaPublication::NotPublished | CondaPublication::Published => {
                format!("upstream: {}", fix.version)
            }
        },
    }
}

/// Where a finding's fix stands, as a sentence fragment: `fixed in 3.1.1`,
/// `fix released elsewhere: ...`, or `no known fixed version`.
pub fn fix_summary(finding: &Finding) -> String {
    match finding.fix_status() {
        FixStatus::Available => format!("fixed in {}", finding.fixed_versions.join(", ")),
        FixStatus::UpstreamOnly => format!(
            "fix released elsewhere: {}",
            describe_upstream_fixes(finding)
        ),
        FixStatus::Unfixed => "no known fixed version".to_string(),
    }
}

pub mod sarif;
pub mod table;

#[cfg(test)]
mod tests;
