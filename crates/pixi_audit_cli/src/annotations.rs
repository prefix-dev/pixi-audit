//! GitHub Actions workflow commands. Written to stderr on a runner, they
//! surface every vulnerability match as an annotation on the job and on the pull
//! request's changed files, without touching the report on stdout.

use std::fmt::Write as _;

use pixi_audit::{AuditReport, Match};

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
pub fn github_annotations(report: &AuditReport, level_for: impl Fn(&Match) -> Level) -> String {
    let mut out = String::new();
    for vuln_match in &report.matches {
        writeln!(
            out,
            "::{} title={}::{}",
            level_for(vuln_match).command(),
            escape_property(&format!(
                "{} in {} {}",
                vuln_match.id, vuln_match.package.name, vuln_match.package.version
            )),
            escape_data(&message(vuln_match))
        )
        .unwrap();
    }
    out
}

fn message(vuln_match: &Match) -> String {
    let fix = crate::render::fix_summary(vuln_match);
    let confidence_note = crate::render::confidence_note(vuln_match)
        .map(|note| format!(", {note}"))
        .unwrap_or_default();
    let mut text = format!("{} severity", vuln_match.severity);
    if let Some(risk) = crate::render::risk_label(vuln_match.risk) {
        text.push_str(&format!(", risk {risk}"));
    }
    if !vuln_match.kev.is_empty() {
        text.push_str(", known exploited");
    }
    text.push_str(&format!(
        ", {fix}{confidence_note} ({}; {})",
        vuln_match.package.ecosystem,
        vuln_match.environments.join(", ")
    ));
    if let Some(summary) = &vuln_match.summary {
        text.push_str(": ");
        text.push_str(summary);
    }
    if let Some(url) = &vuln_match.url {
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
        AuditSummary, MatchConfidence, PackageEcosystem, PackageId, PackageName, SeverityRating,
    };

    use super::*;

    #[test]
    fn one_command_per_match_with_escaped_title() {
        let report = AuditReport {
            matches: vec![Match {
                package: PackageId {
                    name: PackageName::conda("openssl").unwrap(),
                    version: "3.1.0".to_string(),
                    ecosystem: PackageEcosystem::CondaForge,
                },
                environments: vec!["default".to_string()],
                id: "CVE-2026-1".to_string(),
                aliases: vec![],
                severity: SeverityRating::High,
                cvss_base_score: None,
                fixed_versions: vec!["3.1.1".to_string()],
                other_ecosystem_fixes: vec![],
                upstream_releases: vec![],
                match_confidence: MatchConfidence::Unspecified,
                matched_identity: None,
                summary: Some("100% broken\nreally".to_string()),
                url: Some("https://osv.dev/CVE-2026-1".to_string()),
                epss: vec![],
                kev: vec![],
                risk: pixi_audit::RiskScore::NONE,
                ignore_mode: None,
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
            matches: vec![Match {
                package: PackageId {
                    name: PackageName::conda("libpq").unwrap(),
                    version: "16.0".to_string(),
                    ecosystem: PackageEcosystem::CondaForge,
                },
                environments: vec!["default".to_string()],
                id: "CVE-2022-25852".to_string(),
                aliases: vec![],
                severity: SeverityRating::High,
                cvss_base_score: None,
                fixed_versions: vec![],
                other_ecosystem_fixes: vec![],
                upstream_releases: vec![],
                match_confidence: MatchConfidence::VersionUnbounded,
                matched_identity: None,
                summary: None,
                url: None,
                epss: vec![],
                kev: vec![],
                risk: pixi_audit::RiskScore::NONE,
                ignore_mode: None,
            }],
            ..Default::default()
        };
        assert_eq!(
            github_annotations(&report, |_| Level::Warning),
            "::warning title=CVE-2022-25852 in libpq 16.0::high severity, no known fixed \
             version, confidence: no version limits (conda-forge; default)\n"
        );
        report.matches[0].match_confidence = MatchConfidence::Unevaluated;
        assert!(
            github_annotations(&report, |_| Level::Warning)
                .contains(", confidence: version not checked (")
        );
    }

    #[test]
    fn risk_and_kev_are_mentioned_when_present() {
        let mut report = AuditReport::default();
        let mut vuln_match = Match {
            package: PackageId {
                name: PackageName::conda("openssl").unwrap(),
                version: "3.1.0".to_string(),
                ecosystem: PackageEcosystem::CondaForge,
            },
            environments: vec!["default".to_string()],
            id: "CVE-2026-1".to_string(),
            aliases: vec![],
            severity: SeverityRating::High,
            cvss_base_score: None,
            fixed_versions: vec![],
            other_ecosystem_fixes: vec![],
            upstream_releases: vec![],
            match_confidence: MatchConfidence::Unspecified,
            matched_identity: None,
            summary: None,
            url: None,
            epss: vec![],
            kev: vec![pixi_audit::KevEntry {
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
            ignore_mode: None,
        };
        vuln_match.risk = pixi_audit::RiskScore::compute(
            vuln_match.severity,
            None,
            &vuln_match.epss,
            &vuln_match.kev,
        );
        report.matches.push(vuln_match);
        assert_eq!(
            github_annotations(&report, |_| Level::Error),
            "::error title=CVE-2026-1 in openssl 3.1.0::high severity, risk 78.8, known exploited, \
             no known fixed version, match details unavailable (conda-forge; default)\n"
        );
    }
}
