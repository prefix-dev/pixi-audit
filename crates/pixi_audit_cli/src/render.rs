use std::collections::BTreeSet;
use std::fmt::Write as _;

use console::style;
use pixi_audit::{AuditReport, Finding, IgnoreReason, PackageEcosystem, PackageName, SeverityBand};

pub fn render_human(report: &AuditReport) -> String {
    let mut out = String::new();

    for group in grouped(&report.vulnerabilities) {
        writeln!(out, "{}", group.header).unwrap();
        for finding in group.members {
            let severity = severity_cell(finding.severity)
                .map(|cell| format!("  {cell}"))
                .unwrap_or_default();
            writeln!(out, "  {}{severity}{}", finding.id, fix_note(finding)).unwrap();
            if let Some(url) = &finding.url {
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
    } else if !finding.upstream_fixed_versions.is_empty() {
        format!(
            "  fix released upstream: {}",
            finding.upstream_fixed_versions.join(", ")
        )
    } else {
        "  no known fixed version".to_string()
    }
}

#[cfg(test)]
mod tests;
