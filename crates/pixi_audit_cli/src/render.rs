use std::collections::BTreeSet;
use std::fmt::Write as _;

use console::style;
use iocraft::prelude::Weight;
use pixi_audit::{
    AuditReport, CondaPublication, EpssScore, Finding, IgnoreReason, KnownExploited,
    MatchApplicability, PackageEcosystem, PackageName, RansomwareCampaignUse, RiskScore,
    SeverityBand, ThreatSourceStatus, UpstreamFix, UpstreamOrigin,
};
use supports_hyperlinks::Stream;

/// How [`render_human`] adapts its output to the terminal it is written to.
#[derive(Debug, Clone, Copy, Default)]
pub struct RenderOptions {
    /// Wrap each advisory ID in an OSC 8 hyperlink instead of printing its URL
    /// on a separate line.
    pub hyperlinks: bool,
}

impl RenderOptions {
    /// Detect what stdout supports. Hyperlinks require color to be enabled as
    /// well, so `NO_COLOR` and piped output stay plain text.
    pub fn detect_stdout() -> Self {
        Self {
            hyperlinks: console::colors_enabled() && supports_hyperlinks::on(Stream::Stdout),
        }
    }
}

pub fn render_human(report: &AuditReport, options: RenderOptions) -> String {
    let mut out = String::new();

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
                finding.id, finding.package, finding.version
            )
            .unwrap();
        }
        out.push('\n');
    }

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
                package.package,
                package.version.as_deref().unwrap_or("?"),
                package.ecosystem,
                package.environments.join(", ")
            )
            .unwrap();
        }
        out.push('\n');
    }

    let summary = &report.summary;
    if summary.vulnerable > 0 {
        let packages: BTreeSet<PackageKey<'_>> =
            report.vulnerabilities.iter().map(package_key).collect();
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
    out
}

/// Identifies one locked package: the same name at a different version or
/// from a different ecosystem is a different package.
type PackageKey<'a> = (&'a PackageName, &'a str, &'a PackageEcosystem);

fn package_key(finding: &Finding) -> PackageKey<'_> {
    (
        &finding.package,
        finding.version.as_str(),
        &finding.ecosystem,
    )
}

/// The findings for one locked package, under a shared header.
struct Group<'a> {
    key: PackageKey<'a>,
    header: String,
    members: Vec<&'a Finding>,
}

/// Groups findings by package in first-appearance order, which keeps the
/// most severe packages first since the report is sorted by severity.
fn grouped(findings: &[Finding]) -> Vec<Group<'_>> {
    let mut groups: Vec<Group<'_>> = Vec::new();
    for finding in findings {
        let key = package_key(finding);
        match groups.iter_mut().find(|group| group.key == key) {
            Some(group) => group.members.push(finding),
            None => groups.push(Group {
                key,
                header: format!(
                    "{} {} ({}) — {}",
                    style(&finding.package).bold(),
                    finding.version,
                    finding.ecosystem,
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

/// The exploit probability as a percentage with its percentile rank, such
/// as `90.8% (99th)`, or `None` without an EPSS record.
pub fn epss_label(epss: &[EpssScore]) -> Option<String> {
    let score = epss.first()?;
    let probability = score.epss * 100.0;
    let percentile = ordinal((score.percentile * 100.0).floor() as u32);
    if probability < 0.1 {
        Some(format!("< 0.1% ({percentile})"))
    } else {
        Some(format!("{probability:.1}% ({percentile})"))
    }
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
    if !finding.fixed_versions.is_empty() {
        format!("  fixed in: {}", finding.fixed_versions.join(", "))
    } else if !finding.upstream_fixes.is_empty() {
        format!(
            "  fix released elsewhere: {}",
            describe_upstream_fixes(finding)
        )
    } else {
        "  no known fixed version".to_string()
    }
}

/// A note on how the advisory was matched, for matches that deserve a
/// second look; `None` when basilisk evaluated it or recorded nothing.
pub fn match_note(finding: &Finding) -> Option<&'static str> {
    match finding.applicability {
        MatchApplicability::VersionUnbounded => Some("match: version unbounded"),
        MatchApplicability::Unevaluated => Some("match: unevaluated"),
        MatchApplicability::Evaluated | MatchApplicability::Unspecified => None,
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
    if !finding.fixed_versions.is_empty() {
        format!("fixed in {}", finding.fixed_versions.join(", "))
    } else if !finding.upstream_fixes.is_empty() {
        format!(
            "fix released elsewhere: {}",
            describe_upstream_fixes(finding)
        )
    } else {
        "no known fixed version".to_string()
    }
}

pub mod sarif;
pub mod table;

#[cfg(test)]
mod tests;
