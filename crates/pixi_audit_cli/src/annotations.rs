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
pub fn github_annotations(report: &AuditReport, level_for: impl Fn(&Finding) -> Level) -> String {
    let mut out = String::new();
    for finding in &report.vulnerabilities {
        writeln!(
            out,
            "::{} title={}::{}",
            level_for(finding).command(),
            escape_property(&format!(
                "{} in {} {}",
                finding.id, finding.package.name, finding.package.version
            )),
            escape_data(&message(finding))
        )
        .unwrap();
    }
    out
}

fn message(finding: &Finding) -> String {
    let fix = crate::render::fix_summary(finding);
    let match_note = crate::render::match_note(finding)
        .map(|note| format!(", {note}"))
        .unwrap_or_default();
    let mut text = format!("{} severity", finding.severity);
    if let Some(risk) = crate::render::risk_label(finding.risk) {
        text.push_str(&format!(", risk {risk}"));
    }
    if !finding.known_exploited.is_empty() {
        text.push_str(", known exploited");
    }
    text.push_str(&format!(
        ", {fix}{match_note} ({}; {})",
        finding.package.ecosystem,
        finding.environments.join(", ")
    ));
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
    use pixi_audit::{
        AuditSummary, MatchApplicability, PackageEcosystem, PackageId, PackageName, SeverityBand,
    };

    use super::*;

    #[test]
    fn one_command_per_finding_with_escaped_title() {
        let report = AuditReport {
            vulnerabilities: vec![Finding {
                package: PackageId {
                    name: PackageName::conda("openssl").unwrap(),
                    version: "3.1.0".to_string(),
                    ecosystem: PackageEcosystem::CondaForge,
                },
                environments: vec!["default".to_string()],
                id: "CVE-2026-1".to_string(),
                aliases: vec![],
                severity: SeverityBand::High,
                cvss_base_score: None,
                fixed_versions: vec!["3.1.1".to_string()],
                upstream_fixes: vec![],
                applicability: MatchApplicability::Unspecified,
                matched_identity: None,
                summary: Some("100% broken\nreally".to_string()),
                url: Some("https://osv.dev/CVE-2026-1".to_string()),
                epss: vec![],
                known_exploited: vec![],
                risk: pixi_audit::RiskScore::NONE,
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
            github_annotations(&report, |_| Level::Error),
            "::error title=CVE-2026-1 in openssl 3.1.0::high severity, fixed in 3.1.1, \
             match details unavailable (conda-forge; default): 100%25 broken%0Areally https://osv.dev/CVE-2026-1\n"
        );
        assert!(github_annotations(&report, |_| Level::Warning).starts_with("::warning "));
    }

    #[test]
    fn weak_matches_are_noted_in_the_message() {
        let mut report = AuditReport {
            vulnerabilities: vec![Finding {
                package: PackageId {
                    name: PackageName::conda("libpq").unwrap(),
                    version: "16.0".to_string(),
                    ecosystem: PackageEcosystem::CondaForge,
                },
                environments: vec!["default".to_string()],
                id: "CVE-2022-25852".to_string(),
                aliases: vec![],
                severity: SeverityBand::High,
                cvss_base_score: None,
                fixed_versions: vec![],
                upstream_fixes: vec![],
                applicability: MatchApplicability::VersionUnbounded,
                matched_identity: None,
                summary: None,
                url: None,
                epss: vec![],
                known_exploited: vec![],
                risk: pixi_audit::RiskScore::NONE,
                ignore_reason: None,
            }],
            ..Default::default()
        };
        assert_eq!(
            github_annotations(&report, |_| Level::Warning),
            "::warning title=CVE-2022-25852 in libpq 16.0::high severity, no known fixed \
             version, match: no version limits (conda-forge; default)\n"
        );
        report.vulnerabilities[0].applicability = MatchApplicability::Unevaluated;
        assert!(
            github_annotations(&report, |_| Level::Warning)
                .contains(", match: version not checked (")
        );
    }

    #[test]
    fn risk_and_kev_are_mentioned_when_present() {
        let mut report = AuditReport::default();
        let mut finding = Finding {
            package: PackageId {
                name: PackageName::conda("openssl").unwrap(),
                version: "3.1.0".to_string(),
                ecosystem: PackageEcosystem::CondaForge,
            },
            environments: vec!["default".to_string()],
            id: "CVE-2026-1".to_string(),
            aliases: vec![],
            severity: SeverityBand::High,
            cvss_base_score: None,
            fixed_versions: vec![],
            upstream_fixes: vec![],
            applicability: MatchApplicability::Unspecified,
            matched_identity: None,
            summary: None,
            url: None,
            epss: vec![],
            known_exploited: vec![pixi_audit::KnownExploited {
                cve: "CVE-2026-1".to_string(),
                vendor_project: String::new(),
                product: String::new(),
                vulnerability_name: String::new(),
                date_added: String::new(),
                required_action: String::new(),
                due_date: String::new(),
                known_ransomware_campaign_use: pixi_audit::RansomwareCampaignUse::Unknown,
                notes: String::new(),
            }],
            risk: pixi_audit::RiskScore::NONE,
            ignore_reason: None,
        };
        finding.risk = pixi_audit::RiskScore::compute(
            finding.severity,
            None,
            &finding.epss,
            &finding.known_exploited,
        );
        report.vulnerabilities.push(finding);
        assert_eq!(
            github_annotations(&report, |_| Level::Error),
            "::error title=CVE-2026-1 in openssl 3.1.0::high severity, risk 78.8, known exploited, \
             no known fixed version, match details unavailable (conda-forge; default)\n"
        );
    }
}
