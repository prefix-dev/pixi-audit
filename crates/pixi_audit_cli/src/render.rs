use std::collections::BTreeSet;
use std::fmt::Write as _;

use console::style;
use pixi_audit::{
    AuditReport, CondaPublication, Finding, IgnoreReason, PackageEcosystem, PackageName,
    SeverityBand, UpstreamFix, UpstreamOrigin,
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

    for group in grouped(&report.vulnerabilities) {
        writeln!(out, "{}", group.header).unwrap();
        for finding in group.members {
            let id = finding_id(finding, options);
            let severity = severity_cell(finding.severity)
                .map(|cell| format!("  {cell}"))
                .unwrap_or_default();
            writeln!(out, "  {id}{severity}{}", fix_note(finding)).unwrap();
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

/// A fixed-width, colored severity label, or `None` for unknown severity,
/// which the human report leaves blank rather than shouting "UNKNOWN".
fn severity_cell(band: SeverityBand) -> Option<String> {
    let text = format!("{:<8}", band.name().to_uppercase());
    let styled = match band {
        SeverityBand::Critical | SeverityBand::High => style(text).red().bold(),
        SeverityBand::Medium => style(text).yellow(),
        SeverityBand::Low => style(text).dim(),
        SeverityBand::Unknown => return None,
    };
    Some(styled.to_string())
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

pub mod table;

#[cfg(test)]
mod tests;
