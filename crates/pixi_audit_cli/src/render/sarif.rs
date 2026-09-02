//! SARIF 2.1.0 output, the format GitHub code scanning and similar tools
//! ingest. One rule per vulnerability and package, one result per finding,
//! located at the package's line in the lock file. Ignored findings are
//! results with a suppression, so dashboards can show them as dismissed
//! rather than losing them.

use std::collections::BTreeSet;
use std::path::Path;

use pixi_audit::{AuditReport, Finding, IgnoreReason, PackageEcosystem, SeverityBand};
use serde::Serialize;

use super::{epss_label, fix_summary, kev_label, risk_label};

/// The lock file a report was produced from: the path written into the
/// log, and the contents used to find each package's line.
pub struct LockfileSource<'a> {
    pub path: &'a Path,
    pub contents: &'a str,
}

/// A SARIF log with a single run.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Run {
    tool: Tool,
    invocations: Vec<Invocation>,
    results: Vec<SarifResult>,
}

/// The audit ran to completion; a failed audit never produces a log.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Invocation {
    execution_successful: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Tool {
    driver: Driver,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Driver {
    name: &'static str,
    version: &'static str,
    semantic_version: &'static str,
    information_uri: &'static str,
    rules: Vec<Rule>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Rule {
    id: String,
    name: String,
    short_description: Message,
    full_description: Message,
    #[serde(skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    help: MultiformatMessage,
    properties: RuleProperties,
}

/// The properties GitHub reads from a rule: `security-severity` drives the
/// alert's severity label, tags its category filter.
#[derive(Debug, Serialize)]
struct RuleProperties {
    #[serde(rename = "security-severity")]
    security_severity: String,
    tags: Vec<String>,
    purls: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Message {
    text: String,
}

#[derive(Debug, Serialize)]
struct MultiformatMessage {
    text: String,
    markdown: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    kind: &'static str,
    level: &'static str,
    message: Message,
    locations: Vec<Location>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    suppressions: Vec<Suppression>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Debug, Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: usize,
}

#[derive(Debug, Serialize)]
struct Suppression {
    kind: &'static str,
    justification: String,
}

impl SarifLog {
    pub fn from_report(report: &AuditReport, lockfile: &LockfileSource<'_>) -> Self {
        let findings = report.vulnerabilities.iter().chain(&report.ignored);
        let mut seen = BTreeSet::new();
        let rules = findings
            .clone()
            .filter(|finding| seen.insert(rule_id(finding)))
            .map(|finding| rule(finding, lockfile))
            .collect();
        let uri = artifact_uri(lockfile.path);
        let results = findings
            .map(|finding| result(finding, &uri, lockfile.contents))
            .collect();
        Self {
            schema: "https://json.schemastore.org/sarif-2.1.0.json",
            version: "2.1.0",
            runs: vec![Run {
                tool: Tool {
                    driver: Driver {
                        name: "pixi-audit",
                        version: env!("CARGO_PKG_VERSION"),
                        semantic_version: env!("CARGO_PKG_VERSION"),
                        information_uri: "https://github.com/prefix-dev/pixi_audit",
                        rules,
                    },
                },
                invocations: vec![Invocation {
                    execution_successful: true,
                }],
                results,
            }],
        }
    }
}

/// One rule per vulnerability and package, so dashboards group alerts the
/// way people fix them.
fn rule_id(finding: &Finding) -> String {
    format!("{}-{}", finding.id, finding.package)
}

fn rule(finding: &Finding, lockfile: &LockfileSource<'_>) -> Rule {
    let link = match &finding.url {
        Some(url) => format!("[{}]({url})", finding.id),
        None => finding.id.clone(),
    };
    let rows: Vec<(&str, String)> = vec![
        ("Severity", finding.severity.name().to_string()),
        (
            "CVSS",
            finding
                .cvss_base_score
                .map(|score| format!("{score:.1}"))
                .unwrap_or_default(),
        ),
        ("EPSS", epss_label(&finding.epss).unwrap_or_default()),
        ("Risk", risk_label(finding.risk).unwrap_or_default()),
        (
            "KEV",
            kev_label(&finding.known_exploited)
                .map(str::to_string)
                .unwrap_or_default(),
        ),
        ("Package", finding.package.to_string()),
        ("Version", finding.version.clone()),
        ("Ecosystem", finding.ecosystem.to_string()),
        ("Fix", fix_summary(finding)),
        ("Environments", finding.environments.join(", ")),
        ("Lock file", artifact_uri(lockfile.path)),
        ("Link", link),
    ];
    let text = std::iter::once(format!("Vulnerability {}", finding.id))
        .chain(
            rows.iter()
                .map(|(label, value)| format!("{label}: {value}")),
        )
        .collect::<Vec<_>>()
        .join("\n");
    let markdown = format!(
        "**Vulnerability {}**\n| {} |\n| {} |\n| {} |\n",
        finding.id,
        rows.iter()
            .map(|(label, _)| *label)
            .collect::<Vec<_>>()
            .join(" | "),
        rows.iter().map(|_| "---").collect::<Vec<_>>().join(" | "),
        rows.iter()
            .map(|(_, value)| value.replace('|', "\\|"))
            .collect::<Vec<_>>()
            .join(" | "),
    );
    Rule {
        id: rule_id(finding),
        name: finding.id.clone(),
        short_description: Message {
            text: format!(
                "{} {} vulnerability for {} package",
                finding.id,
                finding.severity.name(),
                finding.package
            ),
        },
        full_description: Message {
            text: finding
                .summary
                .clone()
                .unwrap_or_else(|| format!("{} affects {}", finding.id, finding.package)),
        },
        help_uri: finding.url.clone(),
        help: MultiformatMessage { text, markdown },
        properties: RuleProperties {
            security_severity: security_severity(finding),
            tags: vec!["security".to_string(), finding.severity.name().to_string()],
            purls: vec![purl(finding)],
        },
    }
}

/// GitHub maps `security-severity` onto its labels with CVSS thresholds
/// (critical >= 9.0, high >= 7.0, medium >= 4.0), so the CVSS base score
/// is used when known and the band's lower bound otherwise.
fn security_severity(finding: &Finding) -> String {
    match finding.cvss_base_score {
        Some(score) => format!("{score:.1}"),
        None => match finding.severity {
            SeverityBand::Critical => "9.0",
            SeverityBand::High => "7.0",
            SeverityBand::Medium => "4.0",
            SeverityBand::Low => "1.0",
            SeverityBand::Unknown => "0.0",
        }
        .to_string(),
    }
}

/// The result level, following grype: critical and high are errors,
/// medium a warning, the rest notes.
fn level(band: SeverityBand) -> &'static str {
    match band {
        SeverityBand::Critical | SeverityBand::High => "error",
        SeverityBand::Medium => "warning",
        SeverityBand::Low | SeverityBand::Unknown => "note",
    }
}

fn purl(finding: &Finding) -> String {
    let name = finding.package.as_str();
    let version = &finding.version;
    match &finding.ecosystem {
        PackageEcosystem::Pypi => format!("pkg:pypi/{name}@{version}"),
        PackageEcosystem::CondaForge => format!("pkg:conda/{name}@{version}?channel=conda-forge"),
        PackageEcosystem::Other(channel) => {
            format!("pkg:conda/{name}@{version}?channel={channel}")
        }
    }
}

fn result(finding: &Finding, uri: &str, lockfile_contents: &str) -> SarifResult {
    let suppressions = match finding.ignore_reason {
        Some(IgnoreReason::Always) => vec![Suppression {
            kind: "external",
            justification: "listed in the pixi-audit ignore list".to_string(),
        }],
        Some(IgnoreReason::UntilFixed) => vec![Suppression {
            kind: "external",
            justification: "ignored until a fix is released".to_string(),
        }],
        None => Vec::new(),
    };
    SarifResult {
        rule_id: rule_id(finding),
        kind: "fail",
        level: level(finding.severity),
        message: Message {
            text: format!(
                "{}: {} vulnerability in {} package {} {}; {}",
                finding.id,
                finding.severity.name(),
                finding.ecosystem,
                finding.package,
                finding.version,
                fix_summary(finding)
            ),
        },
        locations: vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: uri.to_string(),
                },
                region: Region {
                    start_line: package_line(lockfile_contents, finding),
                },
            },
        }],
        suppressions,
    }
}

/// The lock file path as code scanning expects it: relative to the git
/// repository containing it, else to the working directory, else as is.
/// Forward slashes either way.
fn artifact_uri(path: &Path) -> String {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let relative_to_root = git_repository_root(&absolute)
        .and_then(|root| absolute.strip_prefix(root).ok().map(Path::to_path_buf));
    let relative_to_cwd = || {
        std::env::current_dir()
            .ok()
            .and_then(|cwd| absolute.strip_prefix(cwd).ok().map(Path::to_path_buf))
    };
    relative_to_root
        .or_else(relative_to_cwd)
        .unwrap_or_else(|| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

/// The nearest ancestor of `path` holding a `.git` directory, or the
/// `.git` file of a worktree or submodule.
fn git_repository_root(path: &Path) -> Option<&Path> {
    path.ancestors()
        .skip(1)
        .find(|ancestor| ancestor.join(".git").exists())
}

/// The first line of the lock file naming the package at its version: the
/// archive filename in a package URL, such as `openssl-3.1.0-hd590300_3`
/// or `requests-2.32.0-py3-none-any.whl`. Line 1 when nothing matches.
fn package_line(contents: &str, finding: &Finding) -> usize {
    let version = finding.version.to_ascii_lowercase();
    let name = finding.package.as_str().to_ascii_lowercase();
    // Wheel and sdist filenames spell the name with underscores.
    let spellings = [name.clone(), name.replace('-', "_")];
    let needles: Vec<String> = spellings
        .iter()
        .flat_map(|spelling| {
            [
                format!("/{spelling}-{version}-"),
                format!("/{spelling}-{version}."),
            ]
        })
        .collect();
    contents
        .lines()
        .position(|line| {
            let line = line.to_ascii_lowercase();
            needles.iter().any(|needle| line.contains(needle.as_str()))
        })
        .map_or(1, |index| index + 1)
}

#[cfg(test)]
mod tests;
