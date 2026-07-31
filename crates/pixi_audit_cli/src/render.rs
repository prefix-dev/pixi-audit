use std::fmt::Write as _;

use console::style;
use pixi_audit::{AuditReport, Finding, SeverityBand};

pub fn render_human(report: &AuditReport) -> String {
    let mut out = String::new();

    for (header, findings) in grouped(&report.vulnerabilities) {
        writeln!(out, "{header}").unwrap();
        for finding in findings {
            writeln!(
                out,
                "  {}  {}{}",
                finding.id,
                severity_cell(finding.severity),
                fix_note(finding)
            )
            .unwrap();
            if let Some(url) = &finding.url {
                writeln!(out, "  {}", style(url).dim()).unwrap();
            }
        }
        out.push('\n');
    }

    if !report.ignored.is_empty() {
        writeln!(out, "Ignored {} finding(s):", report.ignored.len()).unwrap();
        for finding in &report.ignored {
            writeln!(
                out,
                "  {} ({} {})",
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
        let packages: std::collections::BTreeSet<(&str, &str, &str)> = report
            .vulnerabilities
            .iter()
            .map(|finding| {
                (
                    finding.package.as_str(),
                    finding.version.as_str(),
                    finding.ecosystem.as_str(),
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
    type Group<'a> = ((&'a str, &'a str, &'a str), String, Vec<&'a Finding>);

    let mut groups: Vec<Group<'_>> = Vec::new();
    for finding in findings {
        let key = (
            finding.package.as_str(),
            finding.version.as_str(),
            finding.ecosystem.as_str(),
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
        SeverityBand::Low | SeverityBand::Unknown => style(text).dim(),
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
mod tests {
    use pixi_audit::{AuditReport, AuditSummary, Finding, SeverityBand, UncheckedPackage};

    use super::*;

    fn finding(package: &str, id: &str, severity: SeverityBand) -> Finding {
        Finding {
            package: package.to_string(),
            version: "3.1.0".to_string(),
            ecosystem: "conda-forge".to_string(),
            environments: vec!["default".to_string(), "prod".to_string()],
            id: id.to_string(),
            aliases: vec![],
            severity,
            fixed_versions: vec!["3.1.4".to_string()],
            upstream_fixed_versions: vec![],
            summary: None,
            url: Some(format!("https://osv.dev/{id}")),
        }
    }

    #[test]
    fn empty_report_renders_clean_summary() {
        let report = AuditReport {
            summary: AuditSummary {
                audited: 5,
                ..Default::default()
            },
            ..Default::default()
        };
        let text = render_human(&report);
        assert_eq!(
            text,
            "No vulnerabilities found (5 audited, 0 ignored, 0 unchecked)\n"
        );
    }

    #[test]
    fn findings_are_grouped_per_package_with_fix_and_url() {
        let mut second = finding("openssl", "CVE-2026-0002", SeverityBand::Medium);
        second.fixed_versions = vec![];
        second.upstream_fixed_versions = vec!["3.2.0".to_string()];
        second.url = None;
        let report = AuditReport {
            vulnerabilities: vec![
                finding("openssl", "CVE-2026-0001", SeverityBand::High),
                second,
            ],
            summary: AuditSummary {
                audited: 10,
                vulnerable: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        let text = render_human(&report);
        assert_eq!(
            text.matches("openssl 3.1.0 (conda-forge) — default, prod")
                .count(),
            1
        );
        assert!(text.contains("CVE-2026-0001  HIGH      fixed in: 3.1.4"));
        assert!(text.contains("https://osv.dev/CVE-2026-0001"));
        assert!(text.contains("CVE-2026-0002  MEDIUM    fix released upstream: 3.2.0"));
        assert!(
            text.contains("2 vulnerabilities in 1 package(s) (10 audited, 0 ignored, 0 unchecked)")
        );
    }

    #[test]
    fn findings_from_different_ecosystems_are_separate_packages() {
        let conda = finding("openssl", "CVE-2026-0001", SeverityBand::High);
        let mut pypi = finding("openssl", "CVE-2026-0002", SeverityBand::Medium);
        pypi.ecosystem = "PyPI".to_string();
        pypi.environments = vec!["docs".to_string()];
        let report = AuditReport {
            vulnerabilities: vec![conda, pypi],
            summary: AuditSummary {
                audited: 2,
                vulnerable: 2,
                ..Default::default()
            },
            ..Default::default()
        };

        let text = render_human(&report);
        assert!(text.contains("openssl 3.1.0 (conda-forge) — default, prod"));
        assert!(text.contains("openssl 3.1.0 (PyPI) — docs"));
        assert!(text.contains("2 vulnerabilities in 2 package(s)"));
    }

    #[test]
    fn finding_without_any_fix_says_so() {
        let mut f = finding("openssl", "CVE-2026-0003", SeverityBand::Unknown);
        f.fixed_versions = vec![];
        let report = AuditReport {
            vulnerabilities: vec![f],
            summary: AuditSummary {
                audited: 1,
                vulnerable: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let text = render_human(&report);
        assert!(text.contains("CVE-2026-0003  UNKNOWN   no known fixed version"));
    }

    #[test]
    fn ignored_and_unchecked_sections_render() {
        let report = AuditReport {
            ignored: vec![finding("openssl", "CVE-2026-0001", SeverityBand::High)],
            unchecked: vec![UncheckedPackage {
                package: "samtools".to_string(),
                version: Some("1.19".to_string()),
                ecosystem: "bioconda".to_string(),
                environments: vec!["default".to_string()],
            }],
            summary: AuditSummary {
                audited: 3,
                vulnerable: 0,
                ignored: 1,
                unchecked: 1,
            },
            ..Default::default()
        };
        let text = render_human(&report);
        assert!(text.contains("Ignored 1 finding(s):"));
        assert!(text.contains("  CVE-2026-0001 (openssl 3.1.0)"));
        assert!(text.contains("1 package(s) could not be checked:"));
        assert!(text.contains("  samtools 1.19 (bioconda) — default"));
        assert!(text.contains("No vulnerabilities found (3 audited, 1 ignored, 1 unchecked)"));
    }

    #[test]
    fn unchecked_package_without_version_renders_question_mark() {
        let report = AuditReport {
            unchecked: vec![UncheckedPackage {
                package: "mypkg".to_string(),
                version: None,
                ecosystem: "unknown".to_string(),
                environments: vec!["default".to_string()],
            }],
            summary: AuditSummary {
                unchecked: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(render_human(&report).contains("  mypkg ? (unknown) — default"));
    }
}
