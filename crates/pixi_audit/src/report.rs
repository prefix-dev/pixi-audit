use std::collections::{BTreeSet, HashMap};

use futures::{StreamExt, TryStreamExt};
use serde::Serialize;

use crate::{
    client::{AuditError, BasiliskClient},
    types::{BatchResult, OsvQuery, OsvSeverity, OsvVulnerability, QueryPackage},
};

/// How many `GET /v1/vulns/{id}` requests to keep in flight.
const MAX_CONCURRENT_DETAIL_FETCHES: usize = 16;

/// Where a locked package comes from, for vulnerability-query purposes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageEcosystem {
    /// A conda package from the conda-forge channel. The only ecosystem
    /// basilisk's query API answers for today.
    CondaForge,
    /// A PyPI package.
    Pypi,
    /// A conda package from another channel (e.g. bioconda), or a source
    /// package. The contained string is a human-readable origin.
    Other(String),
}

impl PackageEcosystem {
    /// Classifies a conda channel URL: conda-forge is the only ecosystem the
    /// vulnerability database can currently answer for; anything else is
    /// `Other` named after the channel's last URL segment.
    pub fn from_channel_url(channel_url: Option<&str>) -> Self {
        match channel_url {
            Some(url) => {
                let trimmed = url.trim_end_matches('/');
                if trimmed.ends_with("/conda-forge") {
                    PackageEcosystem::CondaForge
                } else {
                    let name = trimmed.rsplit('/').next().unwrap_or("unknown");
                    PackageEcosystem::Other(name.to_string())
                }
            }
            None => PackageEcosystem::Other("unknown".to_string()),
        }
    }

    /// The ecosystem string sent in OSV queries.
    pub fn osv_ecosystem(&self) -> &str {
        match self {
            PackageEcosystem::CondaForge => "conda-forge",
            PackageEcosystem::Pypi => "PyPI",
            PackageEcosystem::Other(origin) => origin,
        }
    }

    /// Whether basilisk can currently answer for this ecosystem. Packages
    /// outside this set are reported as "not checked" (unless a query for
    /// them returns a finding anyway).
    pub fn is_audited(&self) -> bool {
        matches!(self, PackageEcosystem::CondaForge)
    }
}

/// A deduplicated locked package to audit.
#[derive(Debug, Clone)]
pub struct AuditPackage {
    pub name: String,
    /// `None` when the version could not be determined (e.g. an unresolved
    /// conda source package). Such packages are never queried — a
    /// version-less OSV query matches every version ever affected — and are
    /// always reported as unchecked.
    pub version: Option<String>,
    pub ecosystem: PackageEcosystem,
    /// Environments (across all platforms) that contain this exact package.
    pub environments: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityBand {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityBand {
    /// The highest CVSS band across the document's severity entries.
    /// Understands the type labels basilisk emits: `CVSS_V3`/`CVSS_V3.0`/
    /// `CVSS_V3.1` (OSV and NVD sources), `CVSS_V4`, and `CVSS_V2.0`.
    /// Bands follow basilisk: critical >= 9.0, high >= 7.0, medium >= 4.0.
    pub fn from_severities(severities: &[OsvSeverity]) -> Self {
        severities
            .iter()
            .filter_map(|s| {
                if s.kind.starts_with("CVSS_V3") {
                    let base = s.score.parse::<cvss::v3::Base>().ok()?;
                    Some(Self::from_score(base.score().value()))
                } else if s.kind.starts_with("CVSS_V4") {
                    let vector = s.score.parse::<cvss::v4::Vector>().ok()?;
                    Some(Self::from_score(vector.score().value()))
                } else if s.kind.starts_with("CVSS_V2") {
                    // CVSS v2's qualitative scale has no critical band
                    // (high is 7.0-10.0), so cap the mapping there.
                    let score = crate::cvss_v2::base_score(&s.score)?;
                    Some(Self::from_score(score).min(SeverityBand::High))
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(SeverityBand::Unknown)
    }

    fn from_score(score: f64) -> Self {
        match score {
            s if s >= 9.0 => SeverityBand::Critical,
            s if s >= 7.0 => SeverityBand::High,
            s if s >= 4.0 => SeverityBand::Medium,
            _ => SeverityBand::Low,
        }
    }
}

impl std::fmt::Display for SeverityBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            SeverityBand::Critical => "critical",
            SeverityBand::High => "high",
            SeverityBand::Medium => "medium",
            SeverityBand::Low => "low",
            SeverityBand::Unknown => "unknown",
        };
        f.write_str(name)
    }
}

/// One (package, vulnerability) pair.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub package: String,
    pub version: String,
    pub ecosystem: String,
    pub environments: Vec<String>,
    pub id: String,
    pub aliases: Vec<String>,
    pub severity: SeverityBand,
    /// Fixed versions in the package's own ecosystem.
    pub fixed_versions: Vec<String>,
    /// Fixed versions of the same package in other ecosystems (e.g. the PyPI
    /// release that fixes an advisory reported against a conda-forge
    /// package). Informative only — those releases may not exist in the
    /// audited ecosystem yet.
    pub upstream_fixed_versions: Vec<String>,
    pub summary: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UncheckedPackage {
    pub package: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub ecosystem: String,
    pub environments: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditSummary {
    /// Packages in an ecosystem the database can answer for.
    pub audited: usize,
    pub vulnerable: usize,
    pub ignored: usize,
    pub unchecked: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditReport {
    pub vulnerabilities: Vec<Finding>,
    pub ignored: Vec<Finding>,
    pub unchecked: Vec<UncheckedPackage>,
    pub summary: AuditSummary,
}

fn build_query(package: &AuditPackage) -> OsvQuery {
    OsvQuery {
        package: QueryPackage {
            name: Some(package.name.to_lowercase()),
            ecosystem: Some(package.ecosystem.osv_ecosystem().to_string()),
            purl: None,
        },
        version: package.version.clone(),
        page_token: None,
    }
}

/// Fixed versions for `package_name` from an OSV document, split by origin:
/// the first vector holds `fixed` events from `affected` entries in the
/// queried `ecosystem` (or entries naming no package at all), the second
/// holds fixes for the same package name in *other* ecosystems. basilisk's
/// conda-forge entries carry no ranges — the fix data lives on the upstream
/// (PyPI/NVD/...) entries it preserves — so conflating the two would present
/// upstream release numbers as conda-forge fixed versions.
fn fixed_versions(
    doc: &OsvVulnerability,
    package_name: &str,
    ecosystem: &str,
) -> (Vec<String>, Vec<String>) {
    let mut same_ecosystem = Vec::new();
    let mut upstream = Vec::new();
    for affected in &doc.affected {
        let name_matches = affected
            .package
            .as_ref()
            .and_then(|p| p.name.as_deref())
            .is_none_or(|name| name.eq_ignore_ascii_case(package_name));
        if !name_matches {
            continue;
        }
        let ecosystem_matches = affected
            .package
            .as_ref()
            .and_then(|p| p.ecosystem.as_deref())
            .is_none_or(|e| e.eq_ignore_ascii_case(ecosystem));
        let versions = if ecosystem_matches {
            &mut same_ecosystem
        } else {
            &mut upstream
        };
        for range in &affected.ranges {
            for event in &range.events {
                if let Some(fixed) = &event.fixed
                    && !versions.contains(fixed)
                {
                    versions.push(fixed.clone());
                }
            }
        }
    }
    // A version already reported as fixed in the package's own ecosystem is
    // not additionally an "upstream" fix.
    upstream.retain(|version| !same_ecosystem.contains(version));
    (same_ecosystem, upstream)
}

fn advisory_url(doc: &OsvVulnerability) -> Option<String> {
    doc.references
        .iter()
        .find(|r| r.kind.as_deref() == Some("ADVISORY"))
        .or_else(|| doc.references.first())
        .map(|r| r.url.clone())
}

/// Audits `packages` against the vulnerability database, applying `ignore`
/// (vulnerability ids or aliases, case-insensitive).
///
/// A security audit must never silently drop findings, so there is
/// deliberately no partial-report mode: any detail fetch that fails after
/// retries fails the audit as a whole. The one exception is a 404 — the
/// batch index can briefly reference a document that is not served yet —
/// which degrades to an id-only finding (severity unknown) instead.
pub async fn audit(
    client: &BasiliskClient,
    packages: Vec<AuditPackage>,
    ignore: &[String],
) -> Result<AuditReport, AuditError> {
    // Only packages with a known version are queried; a version-less query
    // would match every version ever affected.
    let queryable: Vec<usize> = packages
        .iter()
        .enumerate()
        .filter(|(_, package)| package.version.is_some())
        .map(|(idx, _)| idx)
        .collect();
    let queries: Vec<OsvQuery> = queryable
        .iter()
        .map(|&idx| build_query(&packages[idx]))
        .collect();
    let query_results = client.query_batch(&queries).await?;
    let mut results: Vec<BatchResult> = vec![BatchResult::default(); packages.len()];
    for (&idx, result) in queryable.iter().zip(query_results) {
        results[idx] = result;
    }

    // Fetch each distinct vulnerability document once.
    let ids: BTreeSet<String> = results
        .iter()
        .flat_map(|r| r.vulns.iter().map(|v| v.id.clone()))
        .collect();
    let docs: HashMap<String, OsvVulnerability> = futures::stream::iter(ids)
        .map(|id| async move {
            match client.get_vuln(&id).await {
                Ok(doc) => Ok((id, doc)),
                Err(AuditError::Status { status, .. })
                    if status == reqwest::StatusCode::NOT_FOUND =>
                {
                    let doc = OsvVulnerability {
                        id: id.clone(),
                        ..Default::default()
                    };
                    Ok((id, doc))
                }
                Err(err) => Err(err),
            }
        })
        .buffer_unordered(MAX_CONCURRENT_DETAIL_FETCHES)
        .try_collect()
        .await?;

    let ignore_set: BTreeSet<String> = ignore.iter().map(|s| s.to_lowercase()).collect();

    let mut report = AuditReport::default();
    for (package, result) in packages.iter().zip(&results) {
        let audited = package.version.is_some() && package.ecosystem.is_audited();
        if audited {
            report.summary.audited += 1;
        }
        let mut found_any = false;
        for vuln_ref in &result.vulns {
            let doc = docs
                .get(&vuln_ref.id)
                .expect("every referenced vulnerability was fetched");
            // A withdrawn advisory must not be reported. basilisk already
            // excludes withdrawn advisories from matching; this is a
            // defensive client-side check.
            if doc.withdrawn.is_some() {
                continue;
            }
            found_any = true;
            let ecosystem = package.ecosystem.osv_ecosystem();
            let (fixed_versions, upstream_fixed_versions) =
                fixed_versions(doc, &package.name, ecosystem);
            let finding = Finding {
                package: package.name.clone(),
                version: package
                    .version
                    .clone()
                    .expect("only packages with a version are queried"),
                ecosystem: ecosystem.to_string(),
                environments: package.environments.clone(),
                id: doc.id.clone(),
                aliases: doc.aliases.clone(),
                severity: SeverityBand::from_severities(&doc.severity),
                fixed_versions,
                upstream_fixed_versions,
                summary: doc.summary.clone(),
                url: advisory_url(doc),
            };
            let is_ignored = ignore_set.contains(&finding.id.to_lowercase())
                || finding
                    .aliases
                    .iter()
                    .any(|a| ignore_set.contains(&a.to_lowercase()));
            if is_ignored {
                report.ignored.push(finding);
            } else {
                report.vulnerabilities.push(finding);
            }
        }
        if !found_any && !audited {
            report.unchecked.push(UncheckedPackage {
                package: package.name.clone(),
                version: package.version.clone(),
                ecosystem: package.ecosystem.osv_ecosystem().to_string(),
                environments: package.environments.clone(),
            });
        }
    }

    // Highest severity first, then by package name, for stable output.
    let order =
        |a: &Finding, b: &Finding| b.severity.cmp(&a.severity).then(a.package.cmp(&b.package));
    report.vulnerabilities.sort_by(order);
    report.ignored.sort_by(order);

    report.summary.vulnerable = report.vulnerabilities.len();
    report.summary.ignored = report.ignored.len();
    report.summary.unchecked = report.unchecked.len();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Json, Router,
        routing::{get, post},
    };
    use url::Url;

    use super::*;
    use crate::client::BasiliskClient;

    fn severity(kind: &str, score: &str) -> crate::types::OsvSeverity {
        crate::types::OsvSeverity {
            kind: kind.to_string(),
            score: score.to_string(),
        }
    }

    #[test]
    fn severity_band_from_cvss_vector() {
        // CVSS:3.1 9.8 => critical
        assert_eq!(
            SeverityBand::from_severities(&[severity(
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            )]),
            SeverityBand::Critical
        );
        // Unparsable => unknown
        assert_eq!(SeverityBand::from_severities(&[]), SeverityBand::Unknown);
    }

    #[test]
    fn severity_band_accepts_nvd_style_type_labels() {
        // basilisk's NVD ingestion labels entries "CVSS_V3.1" / "CVSS_V3.0".
        assert_eq!(
            SeverityBand::from_severities(&[severity(
                "CVSS_V3.1",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
            )]),
            SeverityBand::High
        );
    }

    #[test]
    fn severity_band_from_cvss_v4() {
        // CVSS:4.0 9.3 => critical
        assert_eq!(
            SeverityBand::from_severities(&[severity(
                "CVSS_V4",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
            )]),
            SeverityBand::Critical
        );
    }

    #[test]
    fn severity_band_from_cvss_v2() {
        // Known NVD base scores: 7.5 => high, 4.3 => medium.
        assert_eq!(
            SeverityBand::from_severities(&[severity("CVSS_V2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P")]),
            SeverityBand::High
        );
        assert_eq!(
            SeverityBand::from_severities(&[severity("CVSS_V2.0", "AV:N/AC:M/Au:N/C:P/I:N/A:N")]),
            SeverityBand::Medium
        );
        assert_eq!(
            SeverityBand::from_severities(&[severity("CVSS_V2.0", "AV:L/AC:H/Au:N/C:N/I:P/A:N")]),
            SeverityBand::Low
        );
    }

    #[test]
    fn cvss_v2_has_no_critical_band() {
        // v2's qualitative scale tops out at "high" (7.0-10.0); a 10.0 v2-only
        // advisory must not be promoted to critical.
        assert_eq!(
            SeverityBand::from_severities(&[severity("CVSS_V2.0", "AV:N/AC:L/Au:N/C:C/I:C/A:C")]),
            SeverityBand::High
        );
    }

    #[test]
    fn highest_band_across_mixed_severity_entries_wins() {
        assert_eq!(
            SeverityBand::from_severities(&[
                severity("CVSS_V2.0", "AV:N/AC:M/Au:N/C:P/I:N/A:N"), // medium
                severity("CVSS_V3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), // critical
            ]),
            SeverityBand::Critical
        );
    }

    /// A document shaped like basilisk's real output: the conda-forge entry
    /// carries `versions` + `database_specific` (no ranges); the upstream
    /// PyPI entry carries the ranges with `fixed` events.
    fn basilisk_shaped_doc() -> OsvVulnerability {
        serde_json::from_value(serde_json::json!({
            "id": "CVE-2026-9999",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "pillow", "purl": "pkg:pypi/pillow"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "10.2.0"}]}]
                },
                {
                    "package": {"ecosystem": "PyPI", "name": "django"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0.2"}]}]
                },
                {
                    "package": {
                        "ecosystem": "conda-forge",
                        "name": "pillow",
                        "purl": "pkg:conda/conda-forge/pillow"
                    },
                    "versions": ["10.0.0", "10.1.0"],
                    "database_specific": {"basilisk": {"applicability": "evaluated"}}
                }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn fixed_versions_only_come_from_the_queried_ecosystem() {
        let doc = basilisk_shaped_doc();
        // conda-forge entries carry no fixed events; the PyPI fix must not be
        // presented as a conda-forge fixed version.
        let (fixed, upstream) = fixed_versions(&doc, "pillow", "conda-forge");
        assert!(fixed.is_empty());
        assert_eq!(upstream, vec!["10.2.0"]);

        // Queried as PyPI, the same fix IS a same-ecosystem fixed version.
        let (fixed, upstream) = fixed_versions(&doc, "pillow", "PyPI");
        assert_eq!(fixed, vec!["10.2.0"]);
        assert!(upstream.is_empty());
    }

    #[test]
    fn upstream_fixed_versions_require_a_name_match() {
        // The django entry in the same advisory must not leak its fixed
        // version into pillow's report.
        let doc = basilisk_shaped_doc();
        let (fixed, upstream) = fixed_versions(&doc, "pillow", "conda-forge");
        assert!(!upstream.contains(&"5.0.2".to_string()));
        assert!(!fixed.contains(&"5.0.2".to_string()));
    }

    #[test]
    fn fix_present_in_own_ecosystem_is_not_repeated_as_upstream() {
        let doc: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "X",
            "affected": [
                {
                    "package": {"ecosystem": "conda-forge", "name": "pillow"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "10.2.0"}]}]
                },
                {
                    "package": {"ecosystem": "PyPI", "name": "pillow"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "10.2.0"}]}]
                }
            ]
        }))
        .unwrap();
        let (fixed, upstream) = fixed_versions(&doc, "pillow", "conda-forge");
        assert_eq!(fixed, vec!["10.2.0"]);
        assert!(
            upstream.is_empty(),
            "version already reported as fixed must not repeat as upstream: {upstream:?}"
        );
    }

    #[test]
    fn classify_channel_urls() {
        assert_eq!(
            PackageEcosystem::from_channel_url(Some("https://conda.anaconda.org/conda-forge/")),
            PackageEcosystem::CondaForge
        );
        assert_eq!(
            PackageEcosystem::from_channel_url(Some("https://prefix.dev/conda-forge")),
            PackageEcosystem::CondaForge
        );
        assert_eq!(
            PackageEcosystem::from_channel_url(Some("https://conda.anaconda.org/bioconda/")),
            PackageEcosystem::Other("bioconda".to_string())
        );
        assert_eq!(
            PackageEcosystem::from_channel_url(None),
            PackageEcosystem::Other("unknown".to_string())
        );
    }

    #[test]
    fn affected_entry_without_package_counts_as_same_ecosystem() {
        let doc: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "X",
            "affected": [{
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]
            }]
        }))
        .unwrap();
        let (fixed, upstream) = fixed_versions(&doc, "anything", "conda-forge");
        assert_eq!(fixed, vec!["1.2.3"]);
        assert!(upstream.is_empty());
    }

    fn vuln_doc() -> serde_json::Value {
        serde_json::json!({
            "id": "BSLK-1",
            "aliases": ["CVE-2026-1234"],
            "summary": "Buffer overflow in openssl",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{
                "package": {"ecosystem": "conda-forge", "name": "openssl"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.1"}]}]
            }],
            "references": [{"type": "ADVISORY", "url": "https://example.com/adv"}]
        })
    }

    /// Mock server: openssl 3.1.0 has BSLK-1, everything else is clean.
    async fn spawn_mock() -> Url {
        let app = Router::new()
            .route(
                "/v1/querybatch",
                post(|Json(body): Json<serde_json::Value>| async move {
                    let results: Vec<serde_json::Value> = body["queries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|q| {
                            if q["package"]["name"] == "openssl" {
                                serde_json::json!({"vulns": [{"id": "BSLK-1"}]})
                            } else {
                                serde_json::json!({})
                            }
                        })
                        .collect();
                    Json(serde_json::json!({"results": results}))
                }),
            )
            .route("/v1/vulns/{id}", get(|| async { Json(vuln_doc()) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Url::parse(&format!("http://{addr}/")).unwrap()
    }

    fn test_client(base: Url) -> BasiliskClient {
        let http = reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build();
        BasiliskClient::new(http, base)
    }

    fn packages() -> Vec<AuditPackage> {
        vec![
            AuditPackage {
                name: "openssl".to_string(),
                version: Some("3.1.0".to_string()),
                ecosystem: PackageEcosystem::CondaForge,
                environments: vec!["default".to_string()],
            },
            AuditPackage {
                name: "zlib".to_string(),
                version: Some("1.3".to_string()),
                ecosystem: PackageEcosystem::CondaForge,
                environments: vec!["default".to_string()],
            },
            AuditPackage {
                name: "requests".to_string(),
                version: Some("2.32.0".to_string()),
                ecosystem: PackageEcosystem::Pypi,
                environments: vec!["default".to_string()],
            },
        ]
    }

    #[tokio::test]
    async fn audit_reports_findings_and_unchecked() {
        let base = spawn_mock().await;
        let report = audit(&test_client(base), packages(), &[]).await.unwrap();

        assert_eq!(report.vulnerabilities.len(), 1);
        let finding = &report.vulnerabilities[0];
        assert_eq!(finding.package, "openssl");
        assert_eq!(finding.id, "BSLK-1");
        assert_eq!(finding.severity, SeverityBand::Critical);
        assert_eq!(finding.fixed_versions, vec!["3.1.1"]);
        assert_eq!(finding.url.as_deref(), Some("https://example.com/adv"));

        // The PyPI package is unchecked; the clean conda-forge package is not listed.
        assert_eq!(report.unchecked.len(), 1);
        assert_eq!(report.unchecked[0].package, "requests");

        assert_eq!(report.summary.audited, 2);
        assert_eq!(report.summary.vulnerable, 1);
        assert_eq!(report.summary.unchecked, 1);
        assert_eq!(report.summary.ignored, 0);
    }

    #[tokio::test]
    async fn ignored_findings_are_sorted_like_vulnerabilities() {
        // Every package returns the same finding; all of it is ignored.
        let app = Router::new()
            .route(
                "/v1/querybatch",
                post(|Json(body): Json<serde_json::Value>| async move {
                    let n = body["queries"].as_array().unwrap().len();
                    let results: Vec<serde_json::Value> = (0..n)
                        .map(|_| serde_json::json!({"vulns": [{"id": "BSLK-1"}]}))
                        .collect();
                    Json(serde_json::json!({"results": results}))
                }),
            )
            .route("/v1/vulns/{id}", get(|| async { Json(vuln_doc()) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let base = Url::parse(&format!("http://{addr}/")).unwrap();

        let report = audit(&test_client(base), packages(), &["BSLK-1".to_string()])
            .await
            .unwrap();

        // Same severity everywhere, so the tie-break is the package name.
        let order: Vec<&str> = report.ignored.iter().map(|f| f.package.as_str()).collect();
        assert_eq!(order, vec!["openssl", "requests", "zlib"]);
    }

    #[tokio::test]
    async fn ignore_list_matches_id_and_aliases_case_insensitively() {
        let base = spawn_mock().await;
        let report = audit(
            &test_client(base),
            packages(),
            &["cve-2026-1234".to_string()],
        )
        .await
        .unwrap();

        assert!(report.vulnerabilities.is_empty());
        assert_eq!(report.ignored.len(), 1);
        assert_eq!(report.ignored[0].id, "BSLK-1");
        assert_eq!(report.summary.ignored, 1);
    }

    /// Mock server where the only advisory has been withdrawn.
    async fn spawn_withdrawn_mock() -> Url {
        let mut doc = vuln_doc();
        doc["withdrawn"] = serde_json::json!("2026-02-01T00:00:00Z");
        let app = Router::new()
            .route(
                "/v1/querybatch",
                post(|Json(body): Json<serde_json::Value>| async move {
                    let results: Vec<serde_json::Value> = body["queries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|_| serde_json::json!({"vulns": [{"id": "BSLK-1"}]}))
                        .collect();
                    Json(serde_json::json!({"results": results}))
                }),
            )
            .route("/v1/vulns/{id}", get(move || async move { Json(doc) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Url::parse(&format!("http://{addr}/")).unwrap()
    }

    #[tokio::test]
    async fn unknown_version_packages_are_unchecked_and_never_queried() {
        // A version-less OSV query matches ALL versions of a package, which
        // would flood the report with false positives — so a package whose
        // version could not be determined must not be queried at all.
        let received: Arc<Mutex<usize>> = Arc::default();
        let received_clone = received.clone();
        let app = Router::new()
            .route(
                "/v1/querybatch",
                post(
                    move |axum::extract::State(received): axum::extract::State<
                        Arc<Mutex<usize>>,
                    >,
                          Json(body): Json<serde_json::Value>| async move {
                        let n = body["queries"].as_array().unwrap().len();
                        *received.lock().unwrap() += n;
                        let results: Vec<serde_json::Value> =
                            (0..n).map(|_| serde_json::json!({})).collect();
                        Json(serde_json::json!({"results": results}))
                    },
                ),
            )
            .with_state(received_clone);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let base = Url::parse(&format!("http://{addr}/")).unwrap();

        let packages = vec![
            AuditPackage {
                name: "mystery".to_string(),
                version: None,
                ecosystem: PackageEcosystem::CondaForge,
                environments: vec!["default".to_string()],
            },
            AuditPackage {
                name: "zlib".to_string(),
                version: Some("1.3".to_string()),
                ecosystem: PackageEcosystem::CondaForge,
                environments: vec!["default".to_string()],
            },
        ];
        let report = audit(&test_client(base), packages, &[]).await.unwrap();

        // Only zlib was queried; mystery is unchecked and not counted audited.
        assert_eq!(*received.lock().unwrap(), 1);
        assert!(report.vulnerabilities.is_empty());
        assert_eq!(report.unchecked.len(), 1);
        assert_eq!(report.unchecked[0].package, "mystery");
        assert_eq!(report.unchecked[0].version, None);
        assert_eq!(report.summary.audited, 1);
    }

    /// Mock server whose detail endpoint fails with `status` for every id.
    async fn spawn_broken_details_mock(status: axum::http::StatusCode) -> Url {
        let app = Router::new()
            .route(
                "/v1/querybatch",
                post(|Json(body): Json<serde_json::Value>| async move {
                    let n = body["queries"].as_array().unwrap().len();
                    let results: Vec<serde_json::Value> = (0..n)
                        .map(|_| serde_json::json!({"vulns": [{"id": "BSLK-GONE"}]}))
                        .collect();
                    Json(serde_json::json!({"results": results}))
                }),
            )
            .route("/v1/vulns/{id}", get(move || async move { status }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Url::parse(&format!("http://{addr}/")).unwrap()
    }

    #[tokio::test]
    async fn missing_detail_document_degrades_to_id_only_finding() {
        // The querybatch index can briefly reference an id whose document is
        // not yet served (404). The finding must still be reported — never
        // dropped — just without severity/summary detail.
        let base = spawn_broken_details_mock(axum::http::StatusCode::NOT_FOUND).await;
        let report = audit(&test_client(base), packages(), &[]).await.unwrap();

        assert_eq!(report.vulnerabilities.len(), 3);
        let finding = &report.vulnerabilities[0];
        assert_eq!(finding.id, "BSLK-GONE");
        assert_eq!(finding.severity, SeverityBand::Unknown);
        assert_eq!(finding.summary, None);
        assert!(finding.fixed_versions.is_empty());
    }

    #[tokio::test]
    async fn other_detail_fetch_errors_still_fail_the_audit() {
        let base = spawn_broken_details_mock(axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
        let err = audit(&test_client(base), packages(), &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn withdrawn_vulnerabilities_are_not_reported() {
        let base = spawn_withdrawn_mock().await;
        let report = audit(&test_client(base), packages(), &[]).await.unwrap();

        assert!(report.vulnerabilities.is_empty());
        assert!(report.ignored.is_empty());
        assert_eq!(report.summary.vulnerable, 0);
        // The PyPI package's only match is withdrawn, so it is NOT promoted
        // to a finding and stays unchecked.
        assert_eq!(report.unchecked.len(), 1);
        assert_eq!(report.unchecked[0].package, "requests");
    }

    #[tokio::test]
    async fn unchecked_package_with_finding_is_promoted() {
        // A PyPI-named "openssl" package would get the finding, not land in unchecked.
        let base = spawn_mock().await;
        let packages = vec![AuditPackage {
            name: "openssl".to_string(),
            version: Some("3.1.0".to_string()),
            ecosystem: PackageEcosystem::Pypi,
            environments: vec!["default".to_string()],
        }];
        let report = audit(&test_client(base), packages, &[]).await.unwrap();

        assert_eq!(report.vulnerabilities.len(), 1);
        assert!(report.unchecked.is_empty());
    }
}
