//! GitHub Actions workflow commands. Written to stderr on a runner, they
//! surface every finding as an annotation on the job and on the pull
//! request's changed files, without touching the report on stdout.

use std::fmt::Write as _;

use pixi_audit::{AuditReport, Finding};

/// The annotation level, chosen by whether the audit fails the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warning,
}

impl Level {
    fn command(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warning => "warning",
        }
    }
}

/// Whether this process runs inside a GitHub Actions job.
pub fn on_github_actions() -> bool {
    std::env::var_os("GITHUB_ACTIONS").is_some_and(|value| value == "true")
}

/// One workflow command per vulnerability, each on its own line.
pub fn github_annotations(report: &AuditReport, level: Level) -> String {
    let mut out = String::new();
    for finding in &report.vulnerabilities {
        writeln!(
            out,
            "::{} title={}::{}",
            level.command(),
            escape_property(&format!(
                "{} in {} {}",
                finding.id, finding.package, finding.version
            )),
            escape_data(&message(finding))
        )
        .unwrap();
    }
    out
}

fn message(finding: &Finding) -> String {
    let fix = if !finding.fixed_versions.is_empty() {
        format!("fixed in {}", finding.fixed_versions.join(", "))
    } else if !finding.upstream_fixes.is_empty() {
        format!(
            "fix released elsewhere: {}",
            crate::render::describe_upstream_fixes(finding)
        )
    } else {
        "no known fixed version".to_string()
    };
    let mut text = format!(
        "{} severity, {fix} ({}; {})",
        finding.severity,
        finding.ecosystem,
        finding.environments.join(", ")
    );
    if let Some(summary) = &finding.summary {
        text.push_str(": ");
        text.push_str(summary);
    }
    if let Some(url) = &finding.url {
        text.push(' ');
        text.push_str(url);
    }
    text
}

/// Escapes a command's message per the runner's rules.
fn escape_data(text: &str) -> String {
    text.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Escapes a command's property value, which additionally cannot contain
/// the property delimiters.
fn escape_property(text: &str) -> String {
    escape_data(text).replace(':', "%3A").replace(',', "%2C")
}

#[cfg(test)]
mod tests {
    use pixi_audit::{AuditSummary, PackageEcosystem, PackageName, SeverityBand};

    use super::*;

    #[test]
    fn one_command_per_finding_with_escaped_title() {
        let report = AuditReport {
            vulnerabilities: vec![Finding {
                package: PackageName::conda("openssl").unwrap(),
                version: "3.1.0".to_string(),
                ecosystem: PackageEcosystem::CondaForge,
                environments: vec!["default".to_string()],
                id: "CVE-2026-1".to_string(),
                aliases: vec![],
                severity: SeverityBand::High,
                fixed_versions: vec!["3.1.1".to_string()],
                upstream_fixes: vec![],
                summary: Some("100% broken\nreally".to_string()),
                url: Some("https://osv.dev/CVE-2026-1".to_string()),
                ignore_reason: None,
            }],
            summary: AuditSummary {
                audited: 1,
                vulnerable: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            github_annotations(&report, Level::Error),
            "::error title=CVE-2026-1 in openssl 3.1.0::high severity, fixed in 3.1.1 \
             (conda-forge; default): 100%25 broken%0Areally https://osv.dev/CVE-2026-1\n"
        );
        assert!(github_annotations(&report, Level::Warning).starts_with("::warning "));
    }
}
