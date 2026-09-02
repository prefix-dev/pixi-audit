use std::fmt::Write as _;

use console::style;
use pixi_audit::{AuditReport, Finding, PackageEcosystem, SeverityBand};

pub fn render_human(report: &AuditReport) -> String {
    let mut out = String::new();

    for (header, findings) in grouped(&report.vulnerabilities) {
        writeln!(out, "{header}").unwrap();
        for finding in findings {
            if finding.severity == SeverityBand::Unknown {
                writeln!(out, "  {}{}", finding.id, fix_note(finding)).unwrap();
            } else {
                writeln!(
                    out,
                    "  {}  {}{}",
                    finding.id,
                    severity_cell(finding.severity),
                    fix_note(finding)
                )
                .unwrap();
            }
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
                Some(pixi_audit::IgnoreReason::UntilFixed) => " — until a fix is released",
                _ => "",
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
        let packages: std::collections::BTreeSet<(&str, &str, &PackageEcosystem)> = report
            .vulnerabilities
            .iter()
            .map(|finding| {
                (
                    finding.package.as_str(),
                    finding.version.as_str(),
                    &finding.ecosystem,
                )
            })
            .collect();
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

fn grouped(findings: &[Finding]) -> Vec<(String, Vec<&Finding>)> {
    type Group<'a> = (
        (&'a str, &'a str, &'a PackageEcosystem),
        String,
        Vec<&'a Finding>,
    );

    let mut groups: Vec<Group<'_>> = Vec::new();
    for finding in findings {
        let key = (
            finding.package.as_str(),
            finding.version.as_str(),
            &finding.ecosystem,
        );
        match groups.iter_mut().find(|(k, _, _)| *k == key) {
            Some((_, _, members)) => members.push(finding),
            None => {
                let header = format!(
                    "{} {} ({}) — {}",
                    style(&finding.package).bold(),
                    finding.version,
                    finding.ecosystem,
                    finding.environments.join(", ")
                );
                groups.push((key, header, vec![finding]));
            }
        }
    }
    groups
        .into_iter()
        .map(|(_, header, members)| (header, members))
        .collect()
}

fn severity_cell(band: SeverityBand) -> String {
    let text = format!("{:<8}", band.to_string().to_uppercase());
    let styled = match band {
        SeverityBand::Critical | SeverityBand::High => style(text).red().bold(),
        SeverityBand::Medium => style(text).yellow(),
        SeverityBand::Low => style(text).dim(),
        SeverityBand::Unknown => unreachable!("unknown severity is omitted from human output"),
    };
    styled.to_string()
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
