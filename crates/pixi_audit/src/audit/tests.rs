use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    routing::{get, post},
};
use url::Url;

use super::*;
use crate::{
    client::BasiliskClient,
    test_support::{
        basilisk_client as test_client, pypi_client as test_pypi_client, spawn_router as spawn,
    },
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
    let pypi_client = test_pypi_client(spawn(app).await);
    super::audit(client, &pypi_client, packages, ignore).await
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
        report.vulnerabilities[0].upstream_fixed_versions,
        vec!["3.1.1"]
    );
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
    assert_eq!(finding.package, "openssl");
    assert_eq!(finding.id, "BSLK-1");
    assert_eq!(finding.severity, SeverityBand::Critical);
    assert_eq!(finding.fixed_versions, vec!["3.1.1"]);
    assert_eq!(finding.url.as_deref(), Some("https://example.com/adv"));

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
    let report = audit(&test_client(base), packages, IgnoreSpec::default())
        .await
        .unwrap();

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
                    "summary": "Python package vulnerability",
                    "aliases": ["CVE-2026-9999"],
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
        name: "requests".to_string(),
        version: Some("2.32.0".to_string()),
        ecosystem: PackageEcosystem::Pypi,
        environments: vec!["default".to_string()],
    }];

    let err = super::audit(
        &test_client(spawn_mock().await),
        &pypi_client,
        packages,
        IgnoreSpec::default(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AuditError::UnexpectedResponse { .. }),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn pypi_package_is_audited_with_osv() {
    let conda_base = spawn_mock().await;
    let pypi_client = test_pypi_client(spawn_pypi_mock().await);
    let packages = vec![AuditPackage {
        name: "requests_test".to_string(),
        version: Some("2.32.0".to_string()),
        ecosystem: PackageEcosystem::Pypi,
        environments: vec!["default".to_string()],
    }];
    let report = super::audit(
        &test_client(conda_base),
        &pypi_client,
        packages,
        IgnoreSpec::default(),
    )
    .await
    .unwrap();

    assert_eq!(report.summary.audited, 1);
    assert_eq!(report.vulnerabilities.len(), 1);
    assert!(report.unchecked.is_empty());
    let finding = &report.vulnerabilities[0];
    assert_eq!(finding.package, "requests_test");
    assert_eq!(finding.ecosystem, "PyPI");
    assert_eq!(finding.id, "PYSEC-2026-1");
    assert_eq!(finding.aliases, ["CVE-2026-9999"]);
    assert_eq!(finding.fixed_versions, ["2.32.1"]);
    assert_eq!(finding.severity, SeverityBand::Unknown);
    assert_eq!(
        finding.url.as_deref(),
        Some("https://example.com/pypi-advisory")
    );
}
