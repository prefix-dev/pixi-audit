use std::{
    process::Output,
    sync::{Arc, Mutex},
};

use axum::{Json, Router, routing::get};
use pixi_audit_test_support::{epss_router, kev_router, osv_router, spawn_router};
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_pixi-audit");
const LOCK: &str = include_str!("data/pixi.lock");
const PYPI_URL: &str =
    "https://files.pythonhosted.org/packages/py3/r/requests/requests-2.32.0-py3-none-any.whl";
const CRITICAL: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const MEDIUM: &str = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N";

type Queries = Arc<Mutex<Vec<Value>>>;

fn database(
    documents: Vec<Value>,
    matches: Vec<(&'static str, &'static str)>,
) -> (Router, Queries) {
    let queries = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&queries);
    let app = osv_router(
        move |batch| {
            recorded.lock().unwrap().extend(
                batch
                    .iter()
                    .map(|query| serde_json::to_value(query).unwrap()),
            );
            serde_json::from_value(json!({
                "results": batch.iter().map(|query| {
                    match matches.iter().find(|(name, _)| query.package.name.as_deref() == Some(*name)) {
                        Some((_, id)) => json!({"vulns": [{"id": id}]}),
                        None => json!({}),
                    }
                }).collect::<Vec<_>>()
            }))
            .unwrap()
        },
        documents
            .into_iter()
            .map(|doc| serde_json::from_value(doc).unwrap()),
    );
    (app, queries)
}

fn empty_feeds() -> Router {
    epss_router(vec![]).merge(kev_router(json!({"vulnerabilities": []})))
}

async fn run_cli(app: Router, lock: String, args: Vec<&str>) -> Output {
    let base = spawn_router(app).await.to_string();
    let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
    tokio::task::spawn_blocking(move || {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join("pixi.lock"), lock).unwrap();
        std::process::Command::new(BIN)
            .current_dir(workspace.path())
            .args(["pixi.lock", "--json"])
            .args(args)
            .env_remove("PIXI_AUDIT_TOKEN")
            .env("PIXI_AUDIT_BASILISK_URL", &base)
            .env("PIXI_AUDIT_OSV_URL", &base)
            .env("PIXI_AUDIT_EPSS_BASE_URL", &base)
            .env("PIXI_AUDIT_KEV_URL", format!("{base}kev.json"))
            .env("PIXI_CACHE_DIR", workspace.path().join("cache"))
            .output()
            .expect("binary runs")
    })
    .await
    .unwrap()
}

fn report(output: &Output, exit: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(exit),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON report")
}

fn openssl_advisory() -> Value {
    json!({
        "id": "CVE-2026-1234",
        "affected": [{
            "package": {"ecosystem": "conda-forge", "name": "openssl"},
            "severity": [{"type": "CVSS_V3", "score": CRITICAL}]
        }]
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn affected_severity_is_package_specific_and_controls_the_exit_threshold() {
    let doc = json!({
        "id": "SHARED-1",
        "severity": null,
        "affected": [
            {
                "package": {"ecosystem": "conda-forge", "name": "openssl"},
                "severity": [{"type": "CVSS_V3", "score": MEDIUM}]
            },
            {
                "package": {"ecosystem": "PyPI", "name": "Ruamel.YAML"},
                "severity": [{"type": "CVSS_V3", "score": CRITICAL}]
            },
            {
                "package": {"ecosystem": "conda-forge", "name": "unrelated"},
                "severity": [{"type": "CVSS_V3", "score": CRITICAL}]
            },
            {
                "package": {"ecosystem": "npm", "name": "unrelated-node"},
                "severity": [{"type": "CVSS_V3", "score": CRITICAL}]
            }
        ]
    });
    for (args, exit, count) in [
        (vec!["--fail-on", "high"], 1, 2),
        (vec!["--fail-on", "high", "--environment", "prod"], 0, 1),
    ] {
        let (app, _) = database(
            vec![doc.clone()],
            vec![("openssl", "SHARED-1"), ("ruamel-yaml", "SHARED-1")],
        );
        let output = run_cli(
            app.merge(empty_feeds()),
            LOCK.replace("requests", "ruamel_yaml"),
            args,
        )
        .await;
        let report = report(&output, exit);
        let matches = report["matches"].as_array().unwrap();
        assert_eq!(matches.len(), count);
        let conda = matches
            .iter()
            .find(|entry| entry["package"] == "openssl")
            .unwrap();
        assert_eq!(conda["severity"], "medium");
        assert_eq!(conda["cvss_base_score"], 5.3);
        if count == 2 {
            let python = matches
                .iter()
                .find(|entry| entry["package"] == "ruamel-yaml")
                .unwrap();
            assert_eq!(python["severity"], "critical");
            assert_eq!(python["cvss_base_score"], 9.8);
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn top_level_and_package_scores_keep_maximum_rating_and_nonzero_mean() {
    let mut doc = openssl_advisory();
    doc["severity"] = json!([
        {"type": "CVSS_V3", "score": MEDIUM},
        {"type": "CVSS_V3", "score": "not a vector"},
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}
    ]);
    let (app, _) = database(vec![doc], vec![("openssl", "CVE-2026-1234")]);
    let output = run_cli(
        app.merge(empty_feeds()),
        LOCK.into(),
        vec!["--fail-on", "critical"],
    )
    .await;
    let report = report(&output, 1);
    assert_eq!(report["matches"][0]["severity"], "critical");
    let score = report["matches"][0]["cvss_base_score"].as_f64().unwrap();
    assert!((score - 7.55).abs() < 1e-9, "score: {score}");
}

#[tokio::test(flavor = "multi_thread")]
async fn matched_identity_controls_cross_ecosystem_severity_and_fixes() {
    for (kind, identity, exit, severity, score, fixes) in [
        (
            "purl",
            "pkg:npm/native-wrapper@1.0.0?arch=x86",
            1,
            "critical",
            7.55,
            1,
        ),
        (
            "cpe",
            "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            0,
            "medium",
            5.3,
            0,
        ),
    ] {
        let doc = json!({
            "id": "IDENTITY-1",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "native-wrapper", "purl": "pkg:npm/native-wrapper"},
                    "severity": [{"type": "CVSS_V3", "score": CRITICAL}],
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]
                },
                {
                    "package": {"ecosystem": "conda-forge", "name": "openssl"},
                    "severity": [{"type": "CVSS_V3", "score": MEDIUM}],
                    "versions": ["3.1.0"],
                    "database_specific": {"basilisk": {
                        "applicability": "evaluated",
                        "matched_identity": {"kind": kind, "value": identity}
                    }}
                }
            ]
        });
        let (app, _) = database(vec![doc], vec![("openssl", "IDENTITY-1")]);
        let output = run_cli(
            app.merge(empty_feeds()),
            LOCK.into(),
            vec!["--fail-on", "high"],
        )
        .await;
        let report = report(&output, exit);
        let entry = &report["matches"][0];
        assert_eq!(entry["severity"], severity, "identity kind: {kind}");
        assert!((entry["cvss_base_score"].as_f64().unwrap() - score).abs() < 1e-9);
        assert_eq!(
            entry["other_ecosystem_fixes"].as_array().unwrap().len(),
            fixes
        );
        assert_eq!(entry["fixed_versions"], json!([]));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_advisory_aborts_both_databases_even_when_findings_would_be_ignored() {
    for package in ["openssl", "requests"] {
        let (app, _) = database(vec![], vec![(package, "MISSING-1")]);
        let output = run_cli(
            app.merge(empty_feeds()),
            LOCK.into(),
            vec![
                "--ignore",
                "MISSING-1",
                "--fail-on",
                "critical",
                "--warn-only-ecosystem",
                "conda-forge",
            ],
        )
        .await;
        assert_eq!(
            output.status.code(),
            Some(2),
            "package: {package}; output: {output:?}"
        );
        assert!(
            output.stdout.is_empty(),
            "partial report for {package}: {output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("404"),
            "{output:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn python_source_provenance_controls_queries_and_not_audited_counts() {
    for (source, public) in [
        (PYPI_URL, true),
        (
            "https://files.pythonhosted.org:443/packages/requests-2.32.0-py3-none-any.whl",
            true,
        ),
        (
            "https://private.example/requests-2.32.0-py3-none-any.whl",
            false,
        ),
        (
            "https://files.pythonhosted.org.evil.example/packages/requests-2.32.0-py3-none-any.whl",
            false,
        ),
        (
            "http://files.pythonhosted.org/packages/requests-2.32.0-py3-none-any.whl",
            false,
        ),
        (
            "https://files.pythonhosted.org:8443/packages/requests-2.32.0-py3-none-any.whl",
            false,
        ),
        (
            "https://files.pythonhosted.org/other/requests-2.32.0-py3-none-any.whl",
            false,
        ),
        ("./requests", false),
        (
            "git+https://github.com/example/requests.git#1234567890123456789012345678901234567890",
            false,
        ),
    ] {
        let (app, queries) = database(vec![], vec![]);
        let output = run_cli(
            app.merge(empty_feeds()),
            LOCK.replace(PYPI_URL, source),
            vec![],
        )
        .await;
        let report = report(&output, 0);
        assert_eq!(
            report["summary"]["audited"],
            if public { 2 } else { 1 },
            "{source}"
        );
        assert_eq!(
            report["summary"]["not_audited"],
            if public { 1 } else { 2 },
            "{source}"
        );
        let queries = queries.lock().unwrap();
        assert_eq!(
            queries.len(),
            if public { 2 } else { 1 },
            "{source}: {queries:?}"
        );
        assert_eq!(
            queries
                .iter()
                .any(|query| query["package"]["name"] == "requests"),
            public,
            "{source}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn conda_channel_provenance_controls_queries_including_labels() {
    for (channel, public) in [
        ("https://conda.anaconda.org/conda-forge", true),
        ("https://prefix.dev/conda-forge", true),
        ("https://conda.anaconda.org/conda-forge/label/main", true),
        ("https://private.example/conda-forge", false),
        ("https://conda.anaconda.org.evil.example/conda-forge", false),
        ("https://prefix.dev/private/conda-forge", false),
        ("http://conda.anaconda.org/conda-forge", false),
        (
            "https://conda.anaconda.org:8443/conda-forge/label/main",
            false,
        ),
    ] {
        let (app, queries) = database(vec![], vec![]);
        let output = run_cli(
            app.merge(empty_feeds()),
            LOCK.replace("https://conda.anaconda.org/conda-forge", channel),
            vec![],
        )
        .await;
        let report = report(&output, 0);
        assert_eq!(
            report["summary"]["audited"],
            if public { 2 } else { 1 },
            "{channel}"
        );
        assert_eq!(
            report["summary"]["not_audited"],
            if public { 1 } else { 2 },
            "{channel}"
        );
        let queries = queries.lock().unwrap();
        assert_eq!(
            queries.len(),
            if public { 2 } else { 1 },
            "{channel}: {queries:?}"
        );
        assert_eq!(
            queries
                .iter()
                .any(|query| query["package"]["name"] == "openssl"),
            public,
            "{channel}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_threat_feeds_fail_independently_without_losing_findings() {
    for (epss, kev, epss_status, kev_status) in [
        (
            json!({"message": "wrong service"}),
            json!({"vulnerabilities": []}),
            "failed",
            "loaded",
        ),
        (
            json!({"data": []}),
            json!({"message": "wrong service"}),
            "loaded",
            "failed",
        ),
        (json!({}), json!({}), "failed", "failed"),
        (
            json!({"data": []}),
            json!({"vulnerabilities": []}),
            "loaded",
            "loaded",
        ),
    ] {
        let (app, _) = database(vec![openssl_advisory()], vec![("openssl", "CVE-2026-1234")]);
        let epss = Router::new().route(
            "/data/v1/epss",
            get(move || {
                let body = epss.clone();
                async move { Json(body) }
            }),
        );
        let output = run_cli(app.merge(epss).merge(kev_router(kev)), LOCK.into(), vec![]).await;
        let report = report(&output, 1);
        assert_eq!(report["matches"].as_array().unwrap().len(), 1);
        assert_eq!(report["matches"][0]["id"], "CVE-2026-1234");
        assert_eq!(report["matches"][0]["severity"], "critical");
        assert_eq!(report["threat_data"]["epss"]["status"], epss_status);
        assert_eq!(report["threat_data"]["kev"]["status"], kev_status);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unicode_advisory_identifiers_preserve_cve_alias_threat_enrichment() {
    let mut doc = openssl_advisory();
    doc["id"] = json!("ABCé-1");
    doc["aliases"] = json!(["ABCé-2", "cVe-2026-1234", "CVE-2026-1234"]);
    let (app, _) = database(vec![doc], vec![("openssl", "ABCé-1")]);
    let app = app
        .merge(epss_router(vec![json!({
            "cve": "CVE-2026-1234", "epss": "0.5", "percentile": "0.9", "date": "2026-09-01"
        })]))
        .merge(kev_router(json!({"vulnerabilities": []})));
    let output = run_cli(app, LOCK.into(), vec![]).await;
    let report = report(&output, 1);
    assert_eq!(report["matches"][0]["id"], "ABCé-1");
    assert_eq!(report["matches"][0]["epss"].as_array().unwrap().len(), 1);
    assert_eq!(report["matches"][0]["epss"][0]["cve"], "CVE-2026-1234");
    assert_eq!(report["matches"][0]["epss"][0]["epss"], 0.5);
    assert_eq!(report["threat_data"]["epss"]["status"], "loaded");
}

#[tokio::test(flavor = "multi_thread")]
async fn unrelated_ecosystem_severity_cannot_bypass_the_unknown_severity_policy() {
    let doc = json!({
        "id": "PYTHON-1",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "requests"}, "versions": ["2.32.0"]},
            {
                "package": {"ecosystem": "npm", "name": "requests"},
                "severity": [{"type": "CVSS_V3", "score": MEDIUM}]
            }
        ]
    });
    let (app, _) = database(vec![doc], vec![("requests", "PYTHON-1")]);
    let output = run_cli(
        app.merge(empty_feeds()),
        LOCK.into(),
        vec!["--fail-on", "high"],
    )
    .await;
    let report = report(&output, 1);
    assert_eq!(report["matches"][0]["severity"], "unknown");
    assert!(report["matches"][0].get("cvss_base_score").is_none());
}
