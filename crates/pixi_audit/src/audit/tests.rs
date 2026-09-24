use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    routing::{get, post},
};
use url::Url;

use super::*;
use crate::{
    CondaPublication, IgnoreScope, MatchApplicability, MatchedIdentity, MatchedIdentityKind,
    UpstreamFix, UpstreamOrigin,
};
use crate::{
    client::BasiliskClient,
    test_support::{
        basilisk_client as test_client, conda_name, pypi_client as test_pypi_client, pypi_name,
        spawn_router as spawn,
    },
    threat::RansomwareCampaignUse,
};

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
    spawn(app).await
}

async fn audit(
    client: &BasiliskClient,
    packages: Vec<AuditPackage>,
    ignore: IgnoreSpec<'_>,
) -> Result<AuditReport, AuditError> {
    let pypi_client = clean_pypi_client().await;
    super::audit(
        client,
        &pypi_client,
        packages,
        ignore,
        ThreatSources::default(),
    )
    .await
}

/// A PyPI backend that reports every package as clean.
async fn clean_pypi_client() -> PypiAuditClient {
    let app = Router::new().route(
        "/v1/querybatch",
        post(|Json(body): Json<serde_json::Value>| async move {
            let results = body["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|_| serde_json::json!({}))
                .collect::<Vec<_>>();
            Json(serde_json::json!({"results": results}))
        }),
    );
    test_pypi_client(spawn(app).await)
}

fn packages() -> Vec<AuditPackage> {
    vec![
        AuditPackage {
            name: conda_name("openssl"),
            version: Some("3.1.0".to_string()),
            ecosystem: PackageEcosystem::CondaForge,
            environments: vec!["default".to_string()],
        },
        AuditPackage {
            name: conda_name("zlib"),
            version: Some("1.3".to_string()),
            ecosystem: PackageEcosystem::CondaForge,
            environments: vec!["default".to_string()],
        },
        AuditPackage {
            name: pypi_name("requests"),
            version: Some("2.32.0".to_string()),
            ecosystem: PackageEcosystem::Pypi,
            environments: vec!["default".to_string()],
        },
    ]
}

/// Like `vuln_doc`, but with no fixed events anywhere (id BSLK-NOFIX).
fn vuln_doc_nofix() -> serde_json::Value {
    serde_json::json!({
        "id": "BSLK-NOFIX",
        "aliases": ["CVE-2026-7777"],
        "summary": "No fix yet",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{
            "package": {"ecosystem": "conda-forge", "name": "openssl"},
            "versions": ["3.1.0"]
        }]
    })
}

fn vuln_doc_with_git_fix() -> serde_json::Value {
    serde_json::json!({
        "id": "BSLK-GIT-FIX",
        "summary": "Fixed in source but not released",
        "affected": [{
            "package": {"ecosystem": "conda-forge", "name": "openssl"},
            "ranges": [{
                "type": "GIT",
                "events": [{"introduced": "0"}, {"fixed": "deadbeef"}]
            }]
        }]
    })
}

fn vuln_doc_with_basilisk_upstream_fix() -> serde_json::Value {
    serde_json::json!({
        "id": "CVE-2026-50219",
        "summary": "Known upstream fix",
        "affected": [{
            "package": {"ecosystem": "conda-forge", "name": "openssl"},
            "versions": ["3.1.0"],
            "database_specific": {"basilisk": {
                "fix_version": "3.1.1",
                "conda_publication": "not_published"
            }}
        }]
    })
}

/// Mock server serving `doc` for every openssl query.
async fn spawn_mock_serving(doc: serde_json::Value) -> Url {
    let vuln_id = doc["id"].as_str().unwrap().to_string();
    let doc_for_get = doc.clone();
    let app = Router::new()
        .route(
            "/v1/querybatch",
            post(move |Json(body): Json<serde_json::Value>| {
                let vuln_id = vuln_id.clone();
                async move {
                    let results: Vec<serde_json::Value> = body["queries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|q| {
                            if q["package"]["name"] == "openssl" {
                                serde_json::json!({"vulns": [{"id": vuln_id}]})
                            } else {
                                serde_json::json!({})
                            }
                        })
                        .collect();
                    Json(serde_json::json!({"results": results}))
                }
            }),
        )
        .route(
            "/v1/vulns/{id}",
            get(move || {
                let doc = doc_for_get.clone();
                async move { Json(doc) }
            }),
        );
    spawn(app).await
}

fn ignore_until_fixed(ids: &[String]) -> IgnoreSpec<'_> {
    IgnoreSpec {
        ignore: &[],
        ignore_until_fixed: ids,
        package_rules: &[],
        ignore_unfixed: false,
    }
}

#[tokio::test]
async fn until_fixed_with_no_known_fix_is_ignored_with_reason() {
    let base = spawn_mock_serving(vuln_doc_nofix()).await;
    let ids = vec!["BSLK-NOFIX".to_string()];
    let report = audit(&test_client(base), packages(), ignore_until_fixed(&ids))
        .await
        .unwrap();
    assert!(report.vulnerabilities.is_empty());
    assert_eq!(report.ignored.len(), 1);
    assert_eq!(
        report.ignored[0].ignore_reason,
        Some(IgnoreReason::UntilFixed)
    );
    // The JSON field serializes kebab-case.
    let json = serde_json::to_value(&report.ignored[0]).unwrap();
    assert_eq!(json["ignore_reason"], "until-fixed");
}

#[tokio::test]
async fn git_fix_does_not_disable_until_fixed_suppression() {
    let base = spawn_mock_serving(vuln_doc_with_git_fix()).await;
    let ids = vec!["BSLK-GIT-FIX".to_string()];
    let report = audit(&test_client(base), packages(), ignore_until_fixed(&ids))
        .await
        .unwrap();

    assert!(report.vulnerabilities.is_empty());
    assert_eq!(report.ignored.len(), 1);
    assert!(report.ignored[0].fixed_versions.is_empty());
    assert_eq!(
        report.ignored[0].ignore_reason,
        Some(IgnoreReason::UntilFixed)
    );
}

#[tokio::test]
async fn until_fixed_with_basilisk_fix_stays_vulnerable() {
    let base = spawn_mock_serving(vuln_doc_with_basilisk_upstream_fix()).await;
    let ids = vec!["CVE-2026-50219".to_string()];
    let report = audit(&test_client(base), packages(), ignore_until_fixed(&ids))
        .await
        .unwrap();

    assert_eq!(report.vulnerabilities.len(), 1);
    assert!(report.ignored.is_empty());
    assert_eq!(
        report.vulnerabilities[0].upstream_fixes,
        vec![UpstreamFix {
            version: "3.1.1".to_string(),
            origin: UpstreamOrigin::Project {
                conda_publication: CondaPublication::NotPublished,
            },
        }]
    );
}

fn package_rule(package: &str, id: Option<&str>, until_fixed: bool) -> PackageIgnore {
    PackageIgnore {
        scope: IgnoreScope {
            package: Some(package.to_string()),
            ..IgnoreScope::default()
        },
        id: id.map(str::to_string),
        until_fixed,
    }
}

#[tokio::test]
async fn package_rules_scope_suppression_to_one_package() {
    // BSLK-1 (alias CVE-2026-1234) affects openssl; nothing else is found.
    let cases: [(PackageIgnore, Option<IgnoreReason>); 6] = [
        // Every finding in the package, matched case-insensitively.
        (
            package_rule("OpenSSL", None, false),
            Some(IgnoreReason::Always),
        ),
        // Another package: no effect.
        (package_rule("zlib", None, false), None),
        // One id in the package, by alias.
        (
            package_rule("openssl", Some("cve-2026-1234"), false),
            Some(IgnoreReason::Always),
        ),
        // A different id in the package: no effect.
        (package_rule("openssl", Some("CVE-9999-1"), false), None),
        // Until-fixed lapses because BSLK-1 has a fix.
        (package_rule("openssl", None, true), None),
        // Until-fixed by id lapses the same way.
        (package_rule("openssl", Some("BSLK-1"), true), None),
    ];
    for (rule, expected) in cases {
        let base = spawn_mock().await;
        let rules = [rule.clone()];
        let spec = IgnoreSpec {
            package_rules: &rules,
            ..IgnoreSpec::default()
        };
        let report = audit(&test_client(base), packages(), spec).await.unwrap();
        let actual = report
            .ignored
            .first()
            .and_then(|finding| finding.ignore_reason);
        assert_eq!(actual, expected, "rule: {rule:?}");
        assert_eq!(
            report.vulnerabilities.len() + report.ignored.len(),
            1,
            "rule: {rule:?}"
        );
    }
}

#[tokio::test]
async fn scoped_id_rule_only_suppresses_the_selected_ecosystem_and_version() {
    let base = spawn_mock().await;
    let report = audit(&test_client(base), packages(), IgnoreSpec::default())
        .await
        .unwrap();
    let mut conda = report.vulnerabilities[0].clone();
    conda.package = conda_name("openssl");

    let anonymous_rule = PackageIgnore {
        scope: IgnoreScope {
            version: Some(conda.version.clone()),
            ..IgnoreScope::default()
        },
        ..PackageIgnore::default()
    };
    assert!(anonymous_rule.scope.matches(&conda));
    assert!(!anonymous_rule.applies_to(&conda));

    let mut pypi = conda.clone();
    pypi.package = pypi_name("openssl");
    pypi.ecosystem = PackageEcosystem::Pypi;

    // An unqualified scope uses the finding's ecosystem, not the first
    // version parser that accepts its bound.
    let mut scope = IgnoreScope {
        version: Some("1.0foo".into()),
        max_affected_version: Some("1.0foo".into()),
        ..IgnoreScope::default()
    };
    let mut finding = conda.clone();
    finding.version = "1.0foo".into();
    assert!(scope.matches(&finding));
    finding.ecosystem = PackageEcosystem::Pypi;
    assert!(!scope.matches(&finding));
    finding.version = "1.0".into();
    scope.version = Some("1.0.0".into());
    scope.max_affected_version = Some("1.0rc1".into());
    assert!(!scope.matches(&finding));
    scope.max_affected_version = Some("1.0".into());
    assert!(scope.matches(&finding));
    finding.ecosystem = PackageEcosystem::Other("custom".into());
    assert!(!scope.matches(&finding));
    finding.version = "not a version".into();
    assert!(IgnoreScope::default().matches(&finding));

    let rule = PackageIgnore {
        id: Some("CVE-2026-1234".to_string()),
        scope: IgnoreScope {
            ecosystem: Some("conda-forge".to_string()),
            version: Some("3.1.0".to_string()),
            ..IgnoreScope::default()
        },
        ..PackageIgnore::default()
    };
    assert!(rule.applies_to(&conda));
    assert!(!rule.applies_to(&pypi));
    conda.version = "3.1.1".to_string();
    assert!(!rule.applies_to(&conda));

    let rule = PackageIgnore {
        scope: IgnoreScope {
            package: Some("openssl".to_string()),
            max_affected_version: Some("3.1.0".to_string()),
            ..IgnoreScope::default()
        },
        ..PackageIgnore::default()
    };
    assert!(!rule.applies_to(&conda));
    conda.version = "3.1.0".to_string();
    assert!(rule.applies_to(&conda));
    conda.version = "3.0.9".to_string();
    assert!(rule.applies_to(&conda));
    let base = spawn_mock().await;
    let stale = [PackageIgnore {
        id: Some("CVE-2026-1234".to_string()),
        scope: IgnoreScope {
            ecosystem: Some("conda-forge".to_string()),
            version: Some("3.1.1".to_string()),
            ..IgnoreScope::default()
        },
        ..PackageIgnore::default()
    }];
    let report = audit(
        &test_client(base),
        packages(),
        IgnoreSpec {
            package_rules: &stale,
            ..IgnoreSpec::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(report.summary.vulnerable, 1);
    assert_eq!(
        report.unmatched_ignores,
        ["CVE-2026-1234 in ecosystem 'conda-forge' in version '3.1.1'"]
    );
}

#[tokio::test]
async fn package_rules_apply_until_fixed_when_no_fix_is_known() {
    let base = spawn_mock_serving(vuln_doc_nofix()).await;
    let rules = [package_rule("openssl", None, true)];
    let spec = IgnoreSpec {
        package_rules: &rules,
        ..IgnoreSpec::default()
    };
    let report = audit(&test_client(base), packages(), spec).await.unwrap();
    assert!(report.vulnerabilities.is_empty());
    assert_eq!(
        report.ignored[0].ignore_reason,
        Some(IgnoreReason::UntilFixed)
    );
}

#[tokio::test]
async fn ignore_rules_that_match_no_finding_are_reported() {
    // BSLK-1 (alias CVE-2026-1234) is the only finding. Matching is by id
    // or alias, case-insensitive, and an until-fixed rule that matched a
    // finding with a known fix still counts as matched.
    let base = spawn_mock().await;
    let ignore = vec![
        "cve-2026-1234".to_string(),
        "CVE-9999-0001".to_string(),
        "cve-9999-0001".to_string(),
    ];
    let until_fixed = vec!["bslk-1".to_string(), "GHSA-nope".to_string()];
    let spec = IgnoreSpec {
        ignore: &ignore,
        ignore_until_fixed: &until_fixed,
        ..IgnoreSpec::default()
    };
    let report = audit(&test_client(base), packages(), spec).await.unwrap();

    assert_eq!(report.ignored.len(), 1);
    assert_eq!(report.unmatched_ignores, ["CVE-9999-0001", "GHSA-nope"]);

    // Nothing to ignore, nothing unmatched.
    let base = spawn_mock().await;
    let report = audit(&test_client(base), packages(), IgnoreSpec::default())
        .await
        .unwrap();
    assert!(report.unmatched_ignores.is_empty());
}

#[tokio::test]
async fn ignore_unfixed_suppresses_only_findings_without_a_fix() {
    let spec = IgnoreSpec {
        ignore_unfixed: true,
        ..IgnoreSpec::default()
    };

    // No fix anywhere: suppressed with the until-fixed reason.
    let base = spawn_mock_serving(vuln_doc_nofix()).await;
    let report = audit(&test_client(base), packages(), spec).await.unwrap();
    assert!(report.vulnerabilities.is_empty());
    assert_eq!(
        report.ignored[0].ignore_reason,
        Some(IgnoreReason::UntilFixed)
    );

    // A conda-forge fix: reported.
    let base = spawn_mock().await;
    let report = audit(&test_client(base), packages(), spec).await.unwrap();
    assert_eq!(report.vulnerabilities.len(), 1);
    assert!(report.ignored.is_empty());

    // An upstream-only fix counts as a known fix too.
    let base = spawn_mock_serving(vuln_doc_with_basilisk_upstream_fix()).await;
    let report = audit(&test_client(base), packages(), spec).await.unwrap();
    assert_eq!(report.vulnerabilities.len(), 1);
    assert!(report.ignored.is_empty());
}

#[tokio::test]
async fn until_fixed_with_known_fix_stays_vulnerable() {
    // BSLK-1 has fixed 3.1.1, so suppression does not apply.
    let base = spawn_mock().await;
    let ids = vec!["BSLK-1".to_string()];
    let report = audit(&test_client(base), packages(), ignore_until_fixed(&ids))
        .await
        .unwrap();
    assert_eq!(report.vulnerabilities.len(), 1);
    assert!(report.ignored.is_empty());
    assert_eq!(report.vulnerabilities[0].ignore_reason, None);
}

#[tokio::test]
async fn until_fixed_matches_aliases_case_insensitively() {
    let base = spawn_mock_serving(vuln_doc_nofix()).await;
    let ids = vec!["cve-2026-7777".to_string()];
    let report = audit(&test_client(base), packages(), ignore_until_fixed(&ids))
        .await
        .unwrap();
    assert_eq!(report.ignored.len(), 1);
}

#[tokio::test]
async fn ignore_wins_over_until_fixed() {
    // BSLK-1 has a fix; plain ignore still suppresses it, reason Always.
    let base = spawn_mock().await;
    let ignore = vec!["BSLK-1".to_string()];
    let until = vec!["BSLK-1".to_string()];
    let spec = IgnoreSpec {
        ignore: &ignore,
        ignore_until_fixed: &until,
        package_rules: &[],
        ignore_unfixed: false,
    };
    let report = audit(&test_client(base), packages(), spec).await.unwrap();
    assert!(report.vulnerabilities.is_empty());
    assert_eq!(report.ignored.len(), 1);
    assert_eq!(report.ignored[0].ignore_reason, Some(IgnoreReason::Always));
}

#[tokio::test]
async fn plain_ignored_findings_carry_reason_always_and_it_serializes() {
    let base = spawn_mock().await;
    let ignore = vec!["BSLK-1".to_string()];
    let spec = IgnoreSpec {
        ignore: &ignore,
        ignore_until_fixed: &[],
        package_rules: &[],
        ignore_unfixed: false,
    };
    let report = audit(&test_client(base), packages(), spec).await.unwrap();
    assert_eq!(report.ignored[0].ignore_reason, Some(IgnoreReason::Always));
    let json = serde_json::to_value(&report.ignored[0]).unwrap();
    assert_eq!(json["ignore_reason"], "always");
    // Vulnerable findings must NOT carry the key at all.
    let base2 = spawn_mock().await;
    let clean = audit(&test_client(base2), packages(), IgnoreSpec::default())
        .await
        .unwrap();
    let vuln_json = serde_json::to_value(&clean.vulnerabilities[0]).unwrap();
    assert!(vuln_json.get("ignore_reason").is_none());
}

#[tokio::test]
async fn audit_reports_findings_and_unchecked() {
    let base = spawn_mock().await;
    let report = audit(&test_client(base), packages(), IgnoreSpec::default())
        .await
        .unwrap();

    assert_eq!(report.vulnerabilities.len(), 1);
    let finding = &report.vulnerabilities[0];
    assert_eq!(finding.package.as_str(), "openssl");
    assert_eq!(finding.id, "BSLK-1");
    assert_eq!(finding.severity, SeverityBand::Critical);
    assert_eq!(finding.fixed_versions, vec!["3.1.1"]);
    assert_eq!(
        finding.url.as_deref(),
        Some("https://basilisk.prefix.dev/advisories/BSLK-1")
    );

    // PyPI and clean conda-forge packages are audited and not listed as unchecked.
    assert!(report.unchecked.is_empty());

    assert_eq!(report.summary.audited, 3);
    assert_eq!(report.summary.vulnerable, 1);
    assert_eq!(report.summary.unchecked, 0);
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
    let base = spawn(app).await;

    let ignore = vec!["BSLK-1".to_string()];
    let spec = IgnoreSpec {
        ignore: &ignore,
        ignore_until_fixed: &[],
        package_rules: &[],
        ignore_unfixed: false,
    };
    let report = audit(&test_client(base), packages(), spec).await.unwrap();

    // Same severity everywhere, so the tie-break is the package name.
    let order: Vec<&str> = report.ignored.iter().map(|f| f.package.as_str()).collect();
    assert_eq!(order, vec!["openssl", "zlib"]);
}

#[tokio::test]
async fn ignore_list_matches_id_and_aliases_case_insensitively() {
    let base = spawn_mock().await;
    let ignore = vec!["cve-2026-1234".to_string()];
    let spec = IgnoreSpec {
        ignore: &ignore,
        ignore_until_fixed: &[],
        package_rules: &[],
        ignore_unfixed: false,
    };
    let report = audit(&test_client(base), packages(), spec).await.unwrap();

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
    spawn(app).await
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
                move |axum::extract::State(received): axum::extract::State<Arc<Mutex<usize>>>,
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
    let base = spawn(app).await;

    let packages = vec![
        AuditPackage {
            name: conda_name("mystery"),
            version: None,
            ecosystem: PackageEcosystem::CondaForge,
            environments: vec!["default".to_string()],
        },
        AuditPackage {
            name: conda_name("zlib"),
            version: Some("1.3".to_string()),
            ecosystem: PackageEcosystem::CondaForge,
            environments: vec!["default".to_string()],
        },
    ];
    let report = audit(&test_client(base), packages, IgnoreSpec::default())
        .await
        .unwrap();

    // Only zlib was queried; mystery is unchecked and not counted audited.
    assert_eq!(*received.lock().unwrap(), 1);
    assert!(report.vulnerabilities.is_empty());
    assert_eq!(report.unchecked.len(), 1);
    assert_eq!(report.unchecked[0].package.as_str(), "mystery");
    assert_eq!(report.unchecked[0].version, None);
    assert_eq!(report.summary.audited, 1);
}

#[tokio::test]
async fn other_ecosystem_packages_are_unchecked_and_never_queried() {
    // No backend answers for bioconda or source packages. Querying Basilisk
    // for them anyway could only ever produce findings that are counted
    // neither as audited nor as unchecked, so they are not sent at all.
    let received: Arc<Mutex<usize>> = Arc::default();
    let received_clone = received.clone();
    let app = Router::new()
        .route(
            "/v1/querybatch",
            post(
                move |axum::extract::State(received): axum::extract::State<Arc<Mutex<usize>>>,
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
    let base = spawn(app).await;

    let packages = vec![
        AuditPackage {
            name: conda_name("samtools"),
            version: Some("1.19".to_string()),
            ecosystem: PackageEcosystem::Other("bioconda".to_string()),
            environments: vec!["default".to_string()],
        },
        AuditPackage {
            name: conda_name("zlib"),
            version: Some("1.3".to_string()),
            ecosystem: PackageEcosystem::CondaForge,
            environments: vec!["default".to_string()],
        },
    ];
    let report = audit(&test_client(base), packages, IgnoreSpec::default())
        .await
        .unwrap();

    assert_eq!(*received.lock().unwrap(), 1);
    assert_eq!(report.unchecked.len(), 1);
    assert_eq!(report.unchecked[0].package.as_str(), "samtools");
    assert_eq!(
        report.unchecked[0].ecosystem,
        PackageEcosystem::Other("bioconda".to_string())
    );
    assert_eq!(report.summary.audited, 1);
    assert_eq!(report.summary.unchecked, 1);
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
    spawn(app).await
}

#[tokio::test]
async fn missing_detail_document_degrades_to_id_only_finding() {
    // The querybatch index can briefly reference an id whose document is
    // not yet served (404). The finding must still be reported — never
    // dropped — just without severity/summary detail.
    let base = spawn_broken_details_mock(axum::http::StatusCode::NOT_FOUND).await;
    let report = audit(&test_client(base), packages(), IgnoreSpec::default())
        .await
        .unwrap();

    assert_eq!(report.vulnerabilities.len(), 2);
    let finding = &report.vulnerabilities[0];
    assert_eq!(finding.id, "BSLK-GONE");
    assert_eq!(finding.severity, SeverityBand::Unknown);
    assert_eq!(finding.summary, None);
    assert!(finding.fixed_versions.is_empty());
}

#[tokio::test]
async fn other_detail_fetch_errors_still_fail_the_audit() {
    let base = spawn_broken_details_mock(axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
    let err = audit(&test_client(base), packages(), IgnoreSpec::default())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("500"), "unexpected error: {err}");
}

#[tokio::test]
async fn withdrawn_vulnerabilities_are_not_reported() {
    let base = spawn_withdrawn_mock().await;
    let report = audit(&test_client(base), packages(), IgnoreSpec::default())
        .await
        .unwrap();

    assert!(report.vulnerabilities.is_empty());
    assert!(report.ignored.is_empty());
    assert_eq!(report.summary.vulnerable, 0);
    // PyPI is audited independently through OSV, so a clean package is
    // audited rather than listed as unchecked.
    assert!(report.unchecked.is_empty());
}

async fn spawn_pypi_mock() -> Url {
    let app = Router::new()
        .route(
            "/v1/querybatch",
            post(|Json(body): Json<serde_json::Value>| async move {
                assert_eq!(body["queries"][0]["package"]["ecosystem"], "PyPI");
                assert_eq!(body["queries"][0]["package"]["name"], "requests-test");
                Json(serde_json::json!({
                    "results": [{"vulns": [{"id": "PYSEC-2026-1"}]}]
                }))
            }),
        )
        .route(
            "/v1/vulns/{id}",
            get(|| async {
                Json(serde_json::json!({
                    "id": "PYSEC-2026-1",
                    "modified": "2026-07-31T00:00:00Z",
                    "summary": "Python package\nvulnerability",
                    "aliases": ["CVE-2026-9999"],
                    "severity": [{
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"
                    }],
                    "affected": [{
                        "package": {"ecosystem": "PyPI", "name": "requests-test"},
                        "ranges": [{
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.32.1"}]
                        }]
                    }],
                    "references": [{
                        "type": "ADVISORY",
                        "url": "https://example.com/pypi-advisory"
                    }]
                }))
            }),
        );
    spawn(app).await
}

#[tokio::test]
async fn short_pypi_batch_response_fails_the_audit() {
    let app = Router::new().route(
        "/v1/querybatch",
        post(|| async { Json(serde_json::json!({"results": []})) }),
    );
    let pypi_client = test_pypi_client(spawn(app).await);
    let packages = vec![AuditPackage {
        name: pypi_name("requests"),
        version: Some("2.32.0".to_string()),
        ecosystem: PackageEcosystem::Pypi,
        environments: vec!["default".to_string()],
    }];

    let err = super::audit(
        &test_client(spawn_mock().await),
        &pypi_client,
        packages,
        IgnoreSpec::default(),
        ThreatSources::default(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AuditError::UnexpectedResponse { .. }),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn package_rules_match_pypi_names_under_pep_503() {
    let conda_base = spawn_mock().await;
    let pypi_client = test_pypi_client(spawn_pypi_mock().await);
    let packages = vec![AuditPackage {
        name: pypi_name("requests_test"),
        version: Some("2.32.0".to_string()),
        ecosystem: PackageEcosystem::Pypi,
        environments: vec!["default".to_string()],
    }];
    let rules = [PackageIgnore {
        scope: IgnoreScope {
            package: Some("Requests.Test".to_string()),
            ..IgnoreScope::default()
        },
        ..PackageIgnore::default()
    }];
    let report = super::audit(
        &test_client(conda_base),
        &pypi_client,
        packages,
        IgnoreSpec {
            package_rules: &rules,
            ..IgnoreSpec::default()
        },
        ThreatSources::default(),
    )
    .await
    .unwrap();

    assert!(report.vulnerabilities.is_empty());
    assert_eq!(report.ignored.len(), 1);
    assert_eq!(report.ignored[0].ignore_reason, Some(IgnoreReason::Always));
}

#[tokio::test]
async fn pypi_package_is_audited_with_osv() {
    let conda_base = spawn_mock().await;
    let pypi_client = test_pypi_client(spawn_pypi_mock().await);
    let packages = vec![AuditPackage {
        name: pypi_name("requests_test"),
        version: Some("2.32.0".to_string()),
        ecosystem: PackageEcosystem::Pypi,
        environments: vec!["default".to_string()],
    }];
    let report = super::audit(
        &test_client(conda_base),
        &pypi_client,
        packages,
        IgnoreSpec::default(),
        ThreatSources::default(),
    )
    .await
    .unwrap();

    assert_eq!(report.summary.audited, 1);
    assert_eq!(report.vulnerabilities.len(), 1);
    assert!(report.unchecked.is_empty());
    let finding = &report.vulnerabilities[0];
    assert_eq!(finding.package.as_str(), "requests-test");
    assert_eq!(finding.ecosystem, PackageEcosystem::Pypi);
    assert_eq!(finding.id, "PYSEC-2026-1");
    assert_eq!(
        finding.summary.as_deref(),
        Some("Python package vulnerability")
    );
    assert_eq!(finding.aliases, ["CVE-2026-9999"]);
    assert_eq!(finding.fixed_versions, ["2.32.1"]);
    // PyPI advisories are scored from their OSV CVSS vectors like any other.
    assert_eq!(finding.severity, SeverityBand::Medium);
    let cvss_base_score = finding.cvss_base_score.unwrap();
    assert!(
        (cvss_base_score - 5.3).abs() < 1e-9,
        "cvss base score: {cvss_base_score}"
    );
    assert_eq!(
        finding.url.as_deref(),
        Some("https://example.com/pypi-advisory")
    );
}

/// Like conda-forge `pnpm`, which is npm's pnpm: matched through the npm
/// purl, so the npm fixes are upstream fixes.
fn vuln_doc_purl_matched() -> serde_json::Value {
    serde_json::json!({
        "id": "CVE-2026-50014",
        "summary": "Fixed on npm",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "openssl", "purl": "pkg:npm/openssl"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "10.34.0"}]}]
            },
            {
                "package": {"ecosystem": "conda-forge", "name": "openssl"},
                "versions": ["3.1.0"],
                "database_specific": {"basilisk": {
                    "applicability": "evaluated",
                    "comparator": "semver",
                    "matcher_version": "v8",
                    "matched_identity": {"kind": "purl", "value": "pkg:npm/openssl"}
                }}
            }
        ]
    })
}

/// Like conda-forge `libpq` and CVE-2022-25852: a CPE match without
/// version bounds, while the same-name npm entry is another package.
fn vuln_doc_cpe_unbounded() -> serde_json::Value {
    serde_json::json!({
        "id": "CVE-2022-25852",
        "summary": "About the npm bindings",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "openssl", "purl": "pkg:npm/openssl"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.8.10"}]}]
            },
            {
                "package": {"ecosystem": "conda-forge", "name": "openssl"},
                "versions": ["3.1.0"],
                "database_specific": {"basilisk": {
                    "applicability": "version_unbounded",
                    "comparator": "conda",
                    "matcher_version": "v8",
                    "matched_identity": {"kind": "cpe", "value": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"}
                }}
            }
        ]
    })
}

#[tokio::test]
async fn purl_matched_finding_keeps_upstream_fixes_and_reports_its_match() {
    let base = spawn_mock_serving(vuln_doc_purl_matched()).await;
    let report = audit(&test_client(base), packages(), IgnoreSpec::default())
        .await
        .unwrap();

    assert_eq!(report.vulnerabilities.len(), 1);
    let finding = &report.vulnerabilities[0];
    assert!(finding.fixed_versions.is_empty());
    assert_eq!(
        finding.upstream_fixes,
        vec![UpstreamFix {
            version: "10.34.0".to_string(),
            origin: UpstreamOrigin::Ecosystem {
                ecosystem: "npm".to_string(),
            },
        }]
    );
    assert_eq!(finding.applicability, MatchApplicability::Evaluated);
    assert_eq!(
        finding.matched_identity,
        Some(MatchedIdentity {
            kind: MatchedIdentityKind::Purl,
            value: "pkg:npm/openssl".to_string(),
        })
    );
    let json = serde_json::to_value(finding).unwrap();
    assert_eq!(json["applicability"], "evaluated");
    assert_eq!(
        json["matched_identity"],
        serde_json::json!({"kind": "purl", "value": "pkg:npm/openssl"})
    );
}

#[tokio::test]
async fn cpe_matched_finding_has_no_upstream_fixes() {
    let base = spawn_mock_serving(vuln_doc_cpe_unbounded()).await;
    let report = audit(&test_client(base), packages(), IgnoreSpec::default())
        .await
        .unwrap();

    assert_eq!(report.vulnerabilities.len(), 1);
    let finding = &report.vulnerabilities[0];
    assert!(finding.fixed_versions.is_empty());
    assert!(
        finding.upstream_fixes.is_empty(),
        "npm openssl is not conda-forge openssl: {:?}",
        finding.upstream_fixes
    );
    assert_eq!(finding.applicability, MatchApplicability::VersionUnbounded);
    assert_eq!(
        finding.matched_identity.as_ref().map(|i| i.kind),
        Some(MatchedIdentityKind::Cpe)
    );
    let json = serde_json::to_value(finding).unwrap();
    assert_eq!(json["applicability"], "version-unbounded");
    assert_eq!(json["matched_identity"]["kind"], "cpe");

    // With no fix known anywhere, until-fixed suppression applies.
    let base = spawn_mock_serving(vuln_doc_cpe_unbounded()).await;
    let ids = vec!["CVE-2022-25852".to_string()];
    let report = audit(&test_client(base), packages(), ignore_until_fixed(&ids))
        .await
        .unwrap();
    assert!(report.vulnerabilities.is_empty());
    assert_eq!(report.ignored.len(), 1);
}

#[tokio::test]
async fn findings_without_match_metadata_are_unspecified() {
    // A plain OSV document from basilisk, and a PyPI finding from OSV.dev.
    let base = spawn_mock().await;
    let report = audit(&test_client(base), packages(), IgnoreSpec::default())
        .await
        .unwrap();
    let finding = &report.vulnerabilities[0];
    assert_eq!(finding.applicability, MatchApplicability::Unspecified);
    assert_eq!(finding.matched_identity, None);
    let json = serde_json::to_value(finding).unwrap();
    assert_eq!(json["applicability"], "unspecified");
    assert_eq!(json["matched_identity"], serde_json::Value::Null);

    let pypi_client = test_pypi_client(spawn_pypi_mock().await);
    let packages = vec![AuditPackage {
        name: pypi_name("requests_test"),
        version: Some("2.32.0".to_string()),
        ecosystem: PackageEcosystem::Pypi,
        environments: vec!["default".to_string()],
    }];
    let report = super::audit(
        &test_client(spawn_mock().await),
        &pypi_client,
        packages,
        IgnoreSpec::default(),
        ThreatSources::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        report.vulnerabilities[0].applicability,
        MatchApplicability::Unspecified
    );
    assert_eq!(report.vulnerabilities[0].matched_identity, None);
}

/// EPSS and KEV feeds where CVE-2026-1234 (BSLK-1's alias) is scored and
/// KEV-listed and nothing else is. The KEV catalog is served at `kev.json`.
async fn spawn_threat_mock() -> Url {
    let app = Router::new()
        .route(
            "/data/v1/epss",
            get(
                |axum::extract::Query(query): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| async move {
                    let data: Vec<serde_json::Value> = query
                        .get("cve")
                        .map(|cves| cves.split(','))
                        .into_iter()
                        .flatten()
                        .filter(|cve| cve.eq_ignore_ascii_case("CVE-2026-1234"))
                        .map(|cve| {
                            serde_json::json!({
                                "cve": cve,
                                "epss": "0.500000000",
                                "percentile": "0.900000000",
                                "date": "2026-09-01"
                            })
                        })
                        .collect();
                    Json(serde_json::json!({"status": "OK", "data": data}))
                },
            ),
        )
        .route(
            "/kev.json",
            get(|| async {
                Json(serde_json::json!({
                    "dateReleased": "2026-09-01T19:22:46.2162Z",
                    "vulnerabilities": [{
                        "cveID": "CVE-2026-1234",
                        "vendorProject": "OpenSSL",
                        "product": "OpenSSL",
                        "vulnerabilityName": "OpenSSL buffer overflow",
                        "dateAdded": "2026-08-01",
                        "requiredAction": "Apply updates per vendor instructions.",
                        "dueDate": "2026-08-22",
                        "knownRansomwareCampaignUse": "Unknown",
                        "notes": ""
                    }]
                }))
            }),
        );
    spawn(app).await
}

fn threat_clients(base: &Url) -> (EpssClient, KevClient) {
    let http = reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build();
    (
        EpssClient::new(http.clone(), base.clone()),
        KevClient::new(http, base.join("kev.json").unwrap()),
    )
}

#[tokio::test]
async fn threat_data_is_attached_to_findings_and_ranks_them() {
    let base = spawn_mock().await;
    let (epss_client, kev_client) = threat_clients(&spawn_threat_mock().await);
    let threat = ThreatSources {
        epss: Some(&epss_client),
        kev: Some(&kev_client),
    };
    let pypi_client = clean_pypi_client().await;
    let report = super::audit(
        &test_client(base),
        &pypi_client,
        packages(),
        IgnoreSpec::default(),
        threat,
    )
    .await
    .unwrap();

    assert_eq!(
        report.threat_data,
        ThreatDataStatus {
            epss: ThreatSourceStatus::Loaded {
                date: Some("2026-09-01".to_string())
            },
            kev: ThreatSourceStatus::Loaded {
                date: Some("2026-09-01".to_string())
            },
        }
    );
    let finding = &report.vulnerabilities[0];
    assert_eq!(finding.epss.len(), 1);
    assert_eq!(finding.epss[0].cve, "CVE-2026-1234");
    assert_eq!(finding.epss[0].epss, 0.5);
    assert_eq!(finding.epss[0].percentile, 0.9);
    assert_eq!(finding.known_exploited.len(), 1);
    assert_eq!(finding.known_exploited[0].vendor_project, "OpenSSL");
    assert_eq!(
        finding.known_exploited[0].known_ransomware_campaign_use,
        RansomwareCampaignUse::Unknown
    );
    // Critical (9.0) averaged with CVSS 9.8 => 0.94; KEV-listed so threat
    // is 1.0 and the boost 1.05 => 98.7.
    assert_eq!(finding.cvss_base_score, Some(9.8));
    assert!(
        (finding.risk.value() - 98.7).abs() < 1e-9,
        "risk: {}",
        finding.risk.value()
    );

    // Ignored findings are enriched too.
    let ignore = vec!["BSLK-1".to_string()];
    let base = spawn_mock().await;
    let report = super::audit(
        &test_client(base),
        &pypi_client,
        packages(),
        IgnoreSpec {
            ignore: &ignore,
            ..IgnoreSpec::default()
        },
        threat,
    )
    .await
    .unwrap();
    assert_eq!(report.ignored[0].epss.len(), 1);
    assert_eq!(report.ignored[0].known_exploited.len(), 1);
}

#[tokio::test]
async fn unreachable_threat_sources_degrade_to_a_status() {
    let base = spawn_mock().await;
    // A server without the feeds: every threat request is a 404.
    let (epss_client, kev_client) = threat_clients(&spawn_mock().await);
    let threat = ThreatSources {
        epss: Some(&epss_client),
        kev: Some(&kev_client),
    };
    let pypi_client = clean_pypi_client().await;
    let report = super::audit(
        &test_client(base),
        &pypi_client,
        packages(),
        IgnoreSpec::default(),
        threat,
    )
    .await
    .unwrap();

    assert_eq!(report.vulnerabilities.len(), 1);
    let finding = &report.vulnerabilities[0];
    assert!(finding.epss.is_empty());
    assert!(finding.known_exploited.is_empty());
    assert_eq!(finding.risk, RiskScore::NONE);
    for status in [&report.threat_data.epss, &report.threat_data.kev] {
        match status {
            ThreatSourceStatus::Failed { error } => {
                assert!(error.contains("404"), "error: {error}")
            }
            ThreatSourceStatus::Disabled | ThreatSourceStatus::Loaded { .. } => {
                panic!("expected a failed status, got {status:?}")
            }
        }
    }
}

#[tokio::test]
async fn findings_are_ordered_by_risk_then_severity() {
    // Two advisories on openssl: BSLK-1 (critical, scored) and BSLK-NOFIX
    // (critical, no CVE score because its alias is unscored).
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
                            serde_json::json!({"vulns": [{"id": "BSLK-NOFIX"}, {"id": "BSLK-1"}]})
                        } else {
                            serde_json::json!({})
                        }
                    })
                    .collect();
                Json(serde_json::json!({"results": results}))
            }),
        )
        .route(
            "/v1/vulns/{id}",
            get(
                |axum::extract::Path(id): axum::extract::Path<String>| async move {
                    if id == "BSLK-1" {
                        Json(vuln_doc())
                    } else {
                        Json(vuln_doc_nofix())
                    }
                },
            ),
        );
    let base = spawn(app).await;
    let (epss_client, kev_client) = threat_clients(&spawn_threat_mock().await);
    let threat = ThreatSources {
        epss: Some(&epss_client),
        kev: Some(&kev_client),
    };
    let pypi_client = clean_pypi_client().await;
    let mut report = super::audit(
        &test_client(base),
        &pypi_client,
        packages(),
        IgnoreSpec::default(),
        threat,
    )
    .await
    .unwrap();

    let ids = |report: &AuditReport| -> Vec<String> {
        report
            .vulnerabilities
            .iter()
            .map(|finding| finding.id.clone())
            .collect()
    };
    // Default: risk first, so the scored advisory leads.
    assert_eq!(ids(&report), ["BSLK-1", "BSLK-NOFIX"]);
    // Vulnerability id order is alphabetical.
    report.sort(SortStrategy::Vulnerability);
    assert_eq!(ids(&report), ["BSLK-1", "BSLK-NOFIX"]);
    // Same severity everywhere, so severity order falls through to risk.
    report.sort(SortStrategy::Severity);
    assert_eq!(ids(&report), ["BSLK-1", "BSLK-NOFIX"]);
    // KEV-listed first; the unlisted one follows regardless of risk.
    report.sort(SortStrategy::Kev);
    assert_eq!(ids(&report), ["BSLK-1", "BSLK-NOFIX"]);
}

#[tokio::test]
async fn advisory_aliases_count_once_before_suppression() {
    let app = Router::new()
        .route(
            "/v1/querybatch",
            post(|Json(body): Json<serde_json::Value>| async move {
                let results: Vec<_> = body["queries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|q| {
                        if q["package"]["name"] == "openssl" {
                            serde_json::json!({"vulns": [
                                {"id": "PYSEC-1"}, {"id": "CVE-1"},
                                {"id": "BSLK-OTHER"}, {"id": "GHSA-1"},
                                {"id": "BSLK-OTHER-ALIAS"}
                            ]})
                        } else {
                            serde_json::json!({})
                        }
                    })
                    .collect();
                Json(serde_json::json!({"results": results}))
            }),
        )
        .route(
            "/v1/vulns/{id}",
            get(
                |axum::extract::Path(id): axum::extract::Path<String>| async move {
                    let (aliases, fixes) = match id.as_str() {
                        "PYSEC-1" => (vec!["GHSA-1"], vec![]),
                        "GHSA-1" => (vec!["CVE-1"], vec!["3.1.1"]),
                        "CVE-1" => (vec![], vec!["3.1.2"]),
                        "BSLK-OTHER-ALIAS" => (vec!["BSLK-OTHER"], vec![]),
                        _ => (vec![], vec![]),
                    };
                    Json(serde_json::json!({
                        "id": id,
                        "aliases": aliases,
                        "affected": [{
                            "package": {"ecosystem": "conda-forge", "name": "openssl"},
                            "ranges": fixes.iter().map(|fix| serde_json::json!({
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": fix}]
                            })).collect::<Vec<_>>()
                        }]
                    }))
                },
            ),
        );
    let base = spawn(app).await;
    let ids = vec!["CVE-1".to_string()];
    let spec = IgnoreSpec {
        ignore: &ids,
        ..IgnoreSpec::default()
    };
    let report = audit(&test_client(base), packages(), spec).await.unwrap();
    assert_eq!(report.vulnerabilities.len(), 1);
    assert_eq!(report.vulnerabilities[0].id, "BSLK-OTHER");
    assert_eq!(report.vulnerabilities[0].aliases, ["BSLK-OTHER-ALIAS"]);
    assert_eq!(report.summary.ignored, 1);
    assert!(report.unmatched_ignores.is_empty());
    let finding = &report.ignored[0];
    assert_eq!(finding.id, "PYSEC-1");
    assert_eq!(finding.aliases, ["CVE-1", "GHSA-1"]);
    assert_eq!(finding.fixed_versions, ["3.1.1", "3.1.2"]);
}
