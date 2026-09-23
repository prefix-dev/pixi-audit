use std::collections::HashMap;
use std::path::Path;
use std::process::Output;

use axum::{
    Json, Router,
    extract::Query,
    routing::{get, post},
};

const BIN: &str = env!("CARGO_BIN_EXE_pixi-audit");

fn lockfile() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/pixi.lock")
        .to_string_lossy()
        .into_owned()
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

async fn spawn_mock(vulnerable: bool) -> String {
    let app = Router::new()
        .route(
            "/v1/querybatch",
            post(move |Json(body): Json<serde_json::Value>| async move {
                let results: Vec<serde_json::Value> = body["queries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|q| {
                        if vulnerable && q["package"]["name"] == "openssl" {
                            serde_json::json!({"vulns": [{"id": "BSLK-1"}]})
                        } else {
                            serde_json::json!({})
                        }
                    })
                    .collect();
                Json(serde_json::json!({"results": results}))
            }),
        )
        .route("/v1/vulns/{id}", get(|| async { Json(vuln_doc()) }))
        .merge(threat_routes());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/")
}

/// EPSS and KEV feeds where CVE-2026-1234 is scored and KEV-listed and
/// nothing else is. The KEV catalog is served at `kev.json`.
fn threat_routes() -> Router {
    Router::new()
        .route(
            "/data/v1/epss",
            get(|Query(query): Query<HashMap<String, String>>| async move {
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
            }),
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
        )
}

/// Environment pointing every backend and feed at the mock at `base_url`,
/// with the HTTP cache in a throwaway directory.
fn audit_env(base_url: &str, cache_dir: &Path) -> Vec<(&'static str, std::ffi::OsString)> {
    vec![
        ("PIXI_AUDIT_BASE_URL", base_url.into()),
        ("PIXI_AUDIT_PYPI_BASE_URL", base_url.into()),
        ("PIXI_AUDIT_EPSS_BASE_URL", base_url.into()),
        ("PIXI_AUDIT_KEV_URL", format!("{base_url}kev.json").into()),
        ("PIXI_CACHE_DIR", cache_dir.into()),
    ]
}

/// Runs the binary without blocking the tokio worker serving the mock.
async fn run_cli(base_url: String, args: Vec<String>) -> Output {
    run_cli_env(base_url, args, vec![]).await
}

/// Like `run_cli`; `env` is applied last, so it can override any of the
/// defaults from `audit_env`.
async fn run_cli_env(base_url: String, args: Vec<String>, env: Vec<(&str, &str)>) -> Output {
    let env: Vec<(String, String)> = env
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    tokio::task::spawn_blocking(move || {
        let cache = tempfile::tempdir().unwrap();
        std::process::Command::new(BIN)
            .args(&args)
            .envs(audit_env(&base_url, cache.path()))
            .envs(env)
            .output()
            .expect("binary runs")
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn vulnerable_lockfile_reports_and_exits_1() {
    let base = spawn_mock(true).await;
    let output = run_cli(base, vec![lockfile()]).await;

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let row = stdout
        .lines()
        .find(|line| line.contains("BSLK-1"))
        .unwrap_or_else(|| panic!("no finding row in stdout: {stdout}"));
    let cells: Vec<&str> = row.split_whitespace().collect();
    // Critical (9.0) averaged with CVSS 9.8, KEV-listed => 0.94 * 1.05.
    assert_eq!(
        cells,
        [
            "(conda)", "openssl", "3.1.0", "3.1.1", "BSLK-1", "Critical", "90th", "·", "50.0%",
            "98.7", "(kev)", "default,", "prod"
        ],
        "stdout: {stdout}"
    );
    assert!(stdout.contains("by severity: 1 critical, 0 high"));
    assert!(stdout.contains("by status:   1 fixed, 0 not-fixed, 0 ignored"));
    // Piped output carries no escape codes.
    assert!(!stdout.contains('\x1b'), "stdout: {stdout}");
    assert!(stdout.contains("Unchecked (1)"));
    assert!(stdout.contains("Assessment\n"), "stdout: {stdout}");
    assert!(
        stdout.lines().any(|line| {
            line.contains("Fix available in audited ecosystem:")
                && line.ends_with("1 of 1 vulnerability across 1 audited package")
        }),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains(
            "Fixed releases in the audited ecosystem are available for 1 vulnerability across 1 audited package, but `--fix` requires a `pixi.toml` or `pyproject.toml` next to the audited lock file."
        ),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("Add `--explain` for scoring and report definitions."));
    assert!(!stdout.contains("How this report works"));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Auditing "), "stderr: {stderr}");
    assert!(!stderr.contains('\x1b'), "stderr: {stderr}");
    assert!(
        stderr.contains("error: audit found vulnerabilities"),
        "stderr: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn warn_only_conda_reports_without_failing() {
    let base = spawn_mock(true).await;
    let output = run_cli_env(
        base,
        vec![
            lockfile(),
            "--warn-only".to_string(),
            "conda-forge".to_string(),
            "--json".to_string(),
        ],
        vec![("GITHUB_ACTIONS", "true")],
    )
    .await;
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["vulnerable"], 1);
    assert_eq!(report["vulnerabilities"][0]["ecosystem"], "conda-forge");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("::warning title=BSLK-1"), "{stderr}");
    assert!(!stderr.contains("::error"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn explain_describes_the_human_report_after_next_steps() {
    let base = spawn_mock(true).await;
    let output = run_cli(base, vec![lockfile(), "--explain".to_string()]).await;

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let actions = stdout.find("Next steps").unwrap();
    let explanation = stdout.find("How this report works").unwrap();
    assert!(actions < explanation, "stdout: {stdout}");
    assert!(!stdout.contains("Add `--explain` for scoring and report definitions."));
    for heading in [
        "Counts",
        "Threat signals",
        "Prioritization",
        "Fixes",
        "Coverage",
    ] {
        assert!(
            stdout.contains(heading),
            "missing {heading:?} in stdout:\n{stdout}"
        );
    }
    for expected in [
        "A 0–100 score for ordering individual findings.",
        "highest EPSS probability",
        "`kev` alone means CISA does not mark that use as Known.",
        "CISA confirms exploitation in the wild.",
        "Estimated chance of exploitation within 30 days.",
        "The package source lacks vulnerability database coverage.",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in stdout:\n{stdout}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn explain_rejects_machine_readable_formats() {
    let base = spawn_mock(true).await;
    for args in [
        vec![lockfile(), "--json".to_string(), "--explain".to_string()],
        vec![
            lockfile(),
            "--format".to_string(),
            "sarif".to_string(),
            "--explain".to_string(),
        ],
    ] {
        let output = run_cli(base.clone(), args).await;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains(
                "`--explain` is available only with `--format table` or `--format grouped`"
            ),
            "stderr: {stderr}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn threat_data_is_serialized() {
    let base = spawn_mock(true).await;
    let output = run_cli(base, vec![lockfile(), "--json".to_string()]).await;
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = &report["vulnerabilities"][0];
    assert_eq!(finding["epss"][0]["cve"], "CVE-2026-1234");
    assert_eq!(finding["epss"][0]["epss"], 0.5);
    assert_eq!(finding["known_exploited"][0]["vendor_project"], "OpenSSL");
    assert_eq!(finding["cvss_base_score"], 9.8);
    let risk = finding["risk"].as_f64().unwrap();
    assert!((risk - 98.7).abs() < 1e-9, "risk: {risk}");
    assert_eq!(report["threat_data"]["epss"]["status"], "loaded");
    assert_eq!(report["threat_data"]["kev"]["date"], "2026-09-01");
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_threat_sources_warn_but_do_not_fail_the_audit() {
    let base = spawn_mock(true).await;
    // Port 9 (discard) refuses connections immediately.
    let output = run_cli_env(
        base,
        vec![lockfile(), "--json".to_string()],
        vec![
            ("PIXI_AUDIT_EPSS_BASE_URL", "http://127.0.0.1:9/"),
            ("PIXI_AUDIT_KEV_URL", "http://127.0.0.1:9/kev.json"),
        ],
    )
    .await;

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["vulnerabilities"][0]["id"], "BSLK-1");
    assert_eq!(report["vulnerabilities"][0]["risk"], 0.0);
    assert_eq!(report["threat_data"]["epss"]["status"], "failed");
    assert_eq!(report["threat_data"]["kev"]["status"], "failed");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("warning: EPSS scores unavailable"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("warning: KEV catalog unavailable"),
        "stderr: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sarif_format_points_at_the_lock_file() {
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![lockfile(), "--format".to_string(), "sarif".to_string()],
    )
    .await;

    assert_eq!(output.status.code(), Some(1));
    let log: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is exactly one SARIF document");
    assert_eq!(log["version"], "2.1.0");
    let run = &log["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "pixi-audit");
    let rule = &run["tool"]["driver"]["rules"][0];
    assert_eq!(rule["id"], "BSLK-1-openssl");
    assert_eq!(rule["properties"]["security-severity"], "9.8");
    assert!(
        rule["help"]["markdown"]
            .as_str()
            .unwrap()
            .contains("| 50.0% (90th) | 98.7 | kev |"),
        "{rule}"
    );
    let result = &run["results"][0];
    assert_eq!(result["ruleId"], "BSLK-1-openssl");
    assert_eq!(result["level"], "error");
    let location = &result["locations"][0]["physicalLocation"];
    // Relative to this repository's root, as code scanning expects.
    assert_eq!(
        location["artifactLocation"]["uri"],
        "crates/pixi_audit_cli/tests/data/pixi.lock"
    );
    // The openssl package URL is on line 8 of the fixture.
    assert_eq!(location["region"]["startLine"], 8);
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_lockfile_exits_0() {
    let base = spawn_mock(false).await;
    let output = run_cli(base, vec![lockfile()]).await;

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("No vulnerabilities found"),
        "stdout: {stdout}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fields_and_sort_by_shape_the_table() {
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![
            lockfile(),
            "--fields".to_string(),
            "vulnerability,name,url".to_string(),
            "--sort-by".to_string(),
            "name".to_string(),
        ],
    )
    .await;

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let header = stdout
        .lines()
        .find(|line| line.contains("Vulnerability"))
        .unwrap();
    assert_eq!(
        header.split_whitespace().collect::<Vec<_>>(),
        ["Vulnerability", "Name", "URL"]
    );
    let row = stdout.lines().find(|line| line.contains("BSLK-1")).unwrap();
    assert_eq!(
        row.split_whitespace().collect::<Vec<_>>(),
        [
            "BSLK-1",
            "(conda)",
            "openssl",
            "https://basilisk.prefix.dev/advisories/BSLK-1"
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grouped_format_prints_findings_per_package() {
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![lockfile(), "--format".to_string(), "grouped".to_string()],
    )
    .await;

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("openssl 3.1.0 (conda-forge) — default, prod"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("fixed in: 3.1.1"));
    // Without hyperlink support the grouped format prints the Basilisk URL.
    assert!(
        stdout.contains("https://basilisk.prefix.dev/advisories/BSLK-1"),
        "stdout: {stdout}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn github_actions_get_annotations_on_stderr() {
    let base = spawn_mock(true).await;
    let output = run_cli_env(base, vec![lockfile()], vec![("GITHUB_ACTIONS", "true")]).await;

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(
            "::error title=BSLK-1 in openssl 3.1.0::critical severity, risk 98.7, known exploited, fixed in 3.1.1"
        ),
        "stderr: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("::error"), "stdout: {stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn json_mode_emits_only_the_report_on_stdout() {
    let base = spawn_mock(true).await;
    let output = run_cli(base, vec![lockfile(), "--json".to_string()]).await;

    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is exactly one JSON document");
    assert_eq!(report["summary"]["vulnerable"], 1);
    assert_eq!(report["vulnerabilities"][0]["id"], "BSLK-1");
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_ignore_rules_warn_on_stderr() {
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![
            lockfile(),
            "--json".to_string(),
            "--ignore".to_string(),
            "cve-2026-1234".to_string(),
            "--ignore".to_string(),
            "CVE-0000-0000".to_string(),
            "--ignore-until-fixed".to_string(),
            "GHSA-stale".to_string(),
        ],
    )
    .await;

    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("warning: ignore rule 'CVE-0000-0000' matched no finding"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("warning: ignore rule 'GHSA-stale' matched no finding"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("'cve-2026-1234'"), "stderr: {stderr}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["unmatched_ignores"],
        serde_json::json!(["CVE-0000-0000", "GHSA-stale"])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ignored_finding_exits_0_but_is_reported() {
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![
            lockfile(),
            "--ignore".to_string(),
            "cve-2026-1234".to_string(),
        ],
    )
    .await;

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Ignored (1)"), "stdout: {stdout}");
    let row = stdout.lines().find(|line| line.contains("BSLK-1")).unwrap();
    assert!(
        row.contains("openssl") && row.ends_with("always"),
        "row: {row}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn environment_filter_limits_the_audit() {
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![lockfile(), "--environment".to_string(), "prod".to_string()],
    )
    .await;

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("Unchecked"), "stdout: {stdout}");
    let row = stdout.lines().find(|line| line.contains("BSLK-1")).unwrap();
    let cells: Vec<&str> = row.split_whitespace().collect();
    assert!(
        cells.contains(&"prod") && !cells.contains(&"default,"),
        "row: {row}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_environment_exits_2() {
    let base = spawn_mock(false).await;
    let output = run_cli(
        base,
        vec![lockfile(), "--environment".to_string(), "nope".to_string()],
    )
    .await;

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("no environment named 'nope'"),
        "stderr: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_lockfile_exits_2() {
    let base = spawn_mock(false).await;
    let output = run_cli(base, vec!["does-not-exist.lock".to_string()]).await;

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("does-not-exist.lock"), "stderr: {stderr}");
}

/// A vuln doc with no fixed events anywhere (severity MEDIUM so severity
/// tests can gate above it).
fn vuln_doc_nofix_medium() -> serde_json::Value {
    serde_json::json!({
        "id": "BSLK-NOFIX",
        "aliases": ["CVE-2026-7777"],
        "summary": "No fix yet",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}],
        "affected": [{
            "package": {"ecosystem": "conda-forge", "name": "openssl"},
            "versions": ["3.1.0"]
        }]
    })
}

fn vuln_doc_basilisk_upstream_fix() -> serde_json::Value {
    serde_json::json!({
        "id": "CVE-2026-50219",
        "summary": "Known upstream fix",
        "affected": [{
            "package": {"ecosystem": "conda-forge", "name": "openssl"},
            "versions": ["3.1.0"],
            "database_specific": {"basilisk": {
                "fix_version": "2.8.2",
                "conda_publication": "not_published"
            }}
        }]
    })
}

/// Mock that serves `doc` for openssl at `vulnerable_version` only.
async fn spawn_mock_versioned(doc: serde_json::Value, vulnerable_version: &str) -> String {
    let vuln_id = doc["id"].as_str().unwrap().to_string();
    let version = vulnerable_version.to_string();
    let doc_for_get = doc.clone();
    let app = Router::new()
        .route(
            "/v1/querybatch",
            post(move |Json(body): Json<serde_json::Value>| {
                let vuln_id = vuln_id.clone();
                let version = version.clone();
                async move {
                    let results: Vec<serde_json::Value> = body["queries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|q| {
                            if q["package"]["name"] == "openssl" && q["version"] == version.as_str()
                            {
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
        )
        .merge(threat_routes());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/")
}

/// Copies the fixture lockfile into a temp workspace with the given
/// manifest content; returns the tempdir (keep it alive).
fn temp_workspace(manifest_name: &str, manifest_content: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(lockfile(), dir.path().join("pixi.lock")).unwrap();
    std::fs::write(dir.path().join(manifest_name), manifest_content).unwrap();
    dir
}

/// Like run_cli but with a working directory and extra env.
async fn run_cli_in(
    dir: std::path::PathBuf,
    base_url: String,
    args: Vec<String>,
    path_override: Option<std::ffi::OsString>,
) -> Output {
    tokio::task::spawn_blocking(move || {
        let cache = tempfile::tempdir().unwrap();
        let mut cmd = std::process::Command::new(BIN);
        cmd.args(&args)
            .current_dir(&dir)
            .envs(audit_env(&base_url, cache.path()));
        if let Some(path) = path_override {
            cmd.env("PATH", path);
        }
        cmd.output().expect("binary runs")
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn basilisk_upstream_fix_is_rendered() {
    let base = spawn_mock_versioned(vuln_doc_basilisk_upstream_fix(), "3.1.0").await;
    let output = run_cli(base, vec![lockfile()]).await;

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("upstream: 2.8.2"), "stdout: {stdout}");
    assert!(!stdout.contains("not-fixed  "), "stdout: {stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn severity_threshold_gates_exit_code_but_not_output() {
    // MEDIUM finding vs --severity high => exit 0, finding still printed.
    let base = spawn_mock_versioned(vuln_doc_nofix_medium(), "3.1.0").await;
    let output = run_cli(
        base,
        vec![lockfile(), "--severity".to_string(), "high".to_string()],
    )
    .await;
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("BSLK-NOFIX"), "stdout: {stdout}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("below the 'high' severity threshold"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("error: audit found vulnerabilities"));
}

#[tokio::test(flavor = "multi_thread")]
async fn severity_threshold_still_fails_at_or_above() {
    // CRITICAL finding vs --severity high => exit 1.
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![lockfile(), "--severity".to_string(), "high".to_string()],
    )
    .await;
    assert_eq!(output.status.code(), Some(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn ignore_until_fixed_suppresses_only_unfixed_findings() {
    // No fix known => suppressed, marked, exit 0.
    let base = spawn_mock_versioned(vuln_doc_nofix_medium(), "3.1.0").await;
    let output = run_cli(
        base,
        vec![
            lockfile(),
            "--ignore-until-fixed".to_string(),
            "BSLK-NOFIX".to_string(),
        ],
    )
    .await;
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("until a fix is released"),
        "stdout: {stdout}"
    );

    // Fix known (BSLK-1 fixes at 3.1.1) => NOT suppressed, exit 1.
    let base = spawn_mock(true).await;
    let output = run_cli(
        base,
        vec![
            lockfile(),
            "--ignore-until-fixed".to_string(),
            "BSLK-1".to_string(),
        ],
    )
    .await;
    assert_eq!(output.status.code(), Some(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn ignore_unfixed_suppresses_unfixed_findings_until_a_fix_exists() {
    // No fix known => ignored with the until-fixed reason, exit 0.
    let base = spawn_mock_versioned(vuln_doc_nofix_medium(), "3.1.0").await;
    let output = run_cli(base, vec![lockfile(), "--ignore-unfixed".to_string()]).await;
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Ignored (1)"), "stdout: {stdout}");
    assert!(
        stdout.contains("until a fix is released"),
        "stdout: {stdout}"
    );

    // Fix known => still reported, exit 1.
    let base = spawn_mock(true).await;
    let output = run_cli(base, vec![lockfile(), "--ignore-unfixed".to_string()]).await;
    assert_eq!(output.status.code(), Some(1));

    // The config key does the same.
    let workspace = temp_workspace(
        "pixi.toml",
        "[workspace]\nname = \"demo\"\n\n[tool.pixi-audit]\nignore-unfixed = true\n",
    );
    let base = spawn_mock_versioned(vuln_doc_nofix_medium(), "3.1.0").await;
    let output = run_cli_in(workspace.path().to_path_buf(), base, vec![], None).await;
    assert_eq!(output.status.code(), Some(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_and_config_file_drive_a_bare_invocation() {
    let workspace = temp_workspace(
        "pixi.toml",
        "[workspace]\nname = \"demo\"\n\n[tool.pixi-audit]\nignore = [\"BSLK-1\"]\n",
    );
    // Run bare (no lockfile arg) from a nested directory.
    let nested = workspace.path().join("src");
    std::fs::create_dir(&nested).unwrap();
    let base = spawn_mock(true).await;
    let output = run_cli_in(nested, base, vec![], None).await;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Ignored (1)"), "stdout: {stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ignore_subcommand_records_rules_in_the_manifest() {
    let workspace = temp_workspace("pixi.toml", "[workspace]\nname = \"demo\"\n");
    let base = spawn_mock(true).await;
    let output = run_cli_in(
        workspace.path().to_path_buf(),
        base.clone(),
        vec![
            "ignore".to_string(),
            "cve-2026-1234".to_string(),
            "--reason".to_string(),
            "known".to_string(),
        ],
        None,
    )
    .await;
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("Ignoring cve-2026-1234 in"),
        "stderr: {stderr}"
    );
    let manifest = std::fs::read_to_string(workspace.path().join("pixi.toml")).unwrap();
    assert_eq!(
        manifest,
        "[workspace]\nname = \"demo\"\n\n[tool.pixi-audit]\nignore = [{ id = \"cve-2026-1234\", reason = \"known\" }]\n"
    );

    // The rule applies to the next audit.
    let output = run_cli_in(workspace.path().to_path_buf(), base.clone(), vec![], None).await;
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Ignored (1)"), "stdout: {stdout}");

    // Listing it again, in any spelling, changes nothing.
    let output = run_cli_in(
        workspace.path().to_path_buf(),
        base,
        vec!["ignore".to_string(), "CVE-2026-1234".to_string()],
        None,
    )
    .await;
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("already listed"), "stderr: {stderr}");
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("pixi.toml")).unwrap(),
        manifest
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ignore_subcommand_can_scope_a_rule_to_a_package() {
    let workspace = temp_workspace("pixi.toml", "[workspace]\nname = \"demo\"\n");
    let base = spawn_mock(true).await;
    let output = run_cli_in(
        workspace.path().to_path_buf(),
        base.clone(),
        vec![
            "ignore".to_string(),
            "--package".to_string(),
            "OpenSSL".to_string(),
            "--reason".to_string(),
            "vendored".to_string(),
        ],
        None,
    )
    .await;
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("Ignoring package 'OpenSSL' in"),
        "stderr: {stderr}"
    );
    let manifest = std::fs::read_to_string(workspace.path().join("pixi.toml")).unwrap();
    assert!(
        manifest.contains("ignore = [{ package = \"OpenSSL\", reason = \"vendored\" }]"),
        "{manifest}"
    );

    let output = run_cli_in(workspace.path().to_path_buf(), base, vec![], None).await;
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Ignored (1)"), "stdout: {stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_ignore_rules_warn_and_no_longer_apply() {
    let workspace = temp_workspace(
        "pixi.toml",
        "[workspace]\nname = \"demo\"\n\n[tool.pixi-audit]\nignore = [{ id = \"CVE-2026-1234\", until = 2000-01-01 }]\n",
    );
    let base = spawn_mock(true).await;
    let output = run_cli_in(workspace.path().to_path_buf(), base, vec![], None).await;
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("ignore rule 'CVE-2026-1234'") && stderr.contains("expired on 2000-01-01"),
        "stderr: {stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bare_invocation_outside_a_workspace_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let base = spawn_mock(false).await;
    let output = run_cli_in(dir.path().to_path_buf(), base, vec![], None).await;
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("no pixi workspace found"),
        "stderr: {stderr}"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn fix_runs_pixi_update_and_reaudits() {
    use std::os::unix::fs::PermissionsExt;

    let workspace = temp_workspace(
        "pixi.toml",
        "[workspace]\nname = \"demo\"\n\n[dependencies]\nopenssl = \">=3.1.0,<4\"\n",
    );
    // "Fixed" lockfile: openssl bumped to 3.1.1 (the mock only flags 3.1.0).
    let fixed_lock = std::fs::read_to_string(lockfile())
        .unwrap()
        .replace("openssl-3.1.0-hd590300_3", "openssl-3.1.1-hd590300_0");
    std::fs::write(workspace.path().join("fixed.lock"), fixed_lock).unwrap();
    // Fake pixi: records argv, swaps in the fixed lockfile.
    let bin_dir = workspace.path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let fake_pixi = bin_dir.join("pixi");
    std::fs::write(
        &fake_pixi,
        format!(
            "#!/bin/sh\necho \"$@\" > '{ws}/pixi-args.txt'\ncp '{ws}/fixed.lock' '{ws}/pixi.lock'\n",
            ws = workspace.path().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake_pixi, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path_override = {
        let mut paths = vec![bin_dir.clone()];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        std::env::join_paths(paths).unwrap()
    };

    let base = spawn_mock_versioned(vuln_doc(), "3.1.0").await;
    let output = run_cli_in(
        workspace.path().to_path_buf(),
        base,
        vec!["--fix".to_string()],
        Some(path_override),
    )
    .await;

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("fixed: raised 1 manifest constraint to known fixed versions"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("fixed: resolved 1 of 1 vulnerabilities via pixi update"),
        "stderr: {stderr}"
    );
    let manifest = std::fs::read_to_string(workspace.path().join("pixi.toml")).unwrap();
    assert!(manifest.contains(">=3.1.1"), "manifest: {manifest}");
    assert!(manifest.contains("<4"), "manifest: {manifest}");
    let args = std::fs::read_to_string(workspace.path().join("pixi-args.txt")).unwrap();
    assert!(args.contains("update"), "pixi argv: {args}");
    assert!(args.contains("--manifest-path"), "pixi argv: {args}");
    assert!(args.contains("openssl"), "pixi argv: {args}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("No vulnerabilities found"),
        "stdout: {stdout}"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn fix_without_pixi_on_path_exits_2() {
    let workspace = temp_workspace("pixi.toml", "[workspace]\nname = \"demo\"\n");
    let empty_dir = workspace.path().join("empty");
    std::fs::create_dir(&empty_dir).unwrap();
    let base = spawn_mock(true).await;
    let output = run_cli_in(
        workspace.path().to_path_buf(),
        base,
        vec!["--fix".to_string()],
        Some(empty_dir.into_os_string()),
    )
    .await;
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("is pixi on PATH?"), "stderr: {stderr}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn fix_skips_pixi_update_when_no_fix_is_known() {
    use std::os::unix::fs::PermissionsExt;

    // The only fix is upstream (not published on conda-forge), so there is
    // nothing to update to and `pixi update` must not run.
    let workspace = temp_workspace(
        "pixi.toml",
        "[workspace]\nname = \"demo\"\n\n[dependencies]\nopenssl = \">=3\"\n",
    );
    let bin_dir = workspace.path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let fake_pixi = bin_dir.join("pixi");
    std::fs::write(
        &fake_pixi,
        format!(
            "#!/bin/sh\necho \"$@\" > '{ws}/pixi-args.txt'\n",
            ws = workspace.path().display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake_pixi, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path_override = {
        let mut paths = vec![bin_dir.clone()];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        std::env::join_paths(paths).unwrap()
    };

    let base = spawn_mock_versioned(vuln_doc_basilisk_upstream_fix(), "3.1.0").await;
    let output = run_cli_in(
        workspace.path().to_path_buf(),
        base,
        vec!["--fix".to_string()],
        Some(path_override),
    )
    .await;

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("no fixed release is known for the vulnerable packages"),
        "stderr: {stderr}"
    );
    assert!(
        !workspace.path().join("pixi-args.txt").exists(),
        "pixi update must not run"
    );
    let manifest = std::fs::read_to_string(workspace.path().join("pixi.toml")).unwrap();
    assert!(
        manifest.contains("openssl = \">=3\""),
        "manifest: {manifest}"
    );
}

/// Shaped like CVE-2022-25852 for conda-forge `libpq`: a CPE match with
/// no version bounds, plus a same-name npm package that has a fix.
fn vuln_doc_cpe_unbounded() -> serde_json::Value {
    serde_json::json!({
        "id": "CVE-2022-25852",
        "summary": "About the npm bindings",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
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

/// Shaped like CVE-2026-50014 for conda-forge `pnpm`, which is npm's
/// pnpm: matched through the npm purl, with the fixes on npm.
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
                "package": {"ecosystem": "npm", "name": "openssl", "purl": "pkg:npm/openssl"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "11.0.0"}, {"fixed": "11.4.0"}]}]
            },
            {
                "package": {"ecosystem": "conda-forge", "name": "openssl"},
                "versions": ["3.1.0"],
                "database_specific": {"basilisk": {
                    "applicability": "evaluated",
                    "comparator": "semver",
                    "conda_publication": "not_published",
                    "fix_version": "11.4.0",
                    "matcher_version": "v8",
                    "matched_identity": {"kind": "purl", "value": "pkg:npm/openssl"}
                }}
            }
        ]
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn cpe_match_without_version_bounds_shows_no_upstream_fix() {
    let base = spawn_mock_versioned(vuln_doc_cpe_unbounded(), "3.1.0").await;
    let output = run_cli(base.clone(), vec![lockfile()]).await;

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let row = stdout
        .lines()
        .find(|line| line.contains("CVE-2022-25852"))
        .unwrap_or_else(|| panic!("no finding row in stdout: {stdout}"));
    assert!(row.contains("CVE-2022-25852 (no version limits)"), "{row}");
    assert!(!stdout.contains("npm"), "stdout: {stdout}");
    assert!(
        stdout.contains("by status:   0 fixed, 1 not-fixed, 0 ignored, 1 no version limits"),
        "stdout: {stdout}"
    );

    let output = run_cli(
        base.clone(),
        vec![
            lockfile(),
            "--fields".to_string(),
            "vulnerability,match".to_string(),
        ],
    )
    .await;
    let stdout = String::from_utf8(output.stdout).unwrap();
    let row = stdout
        .lines()
        .find(|line| line.contains("CVE-2022-25852"))
        .unwrap();
    assert!(row.contains("CVE-2022-25852  no version limits"), "{row}");

    let output = run_cli(base, vec![lockfile(), "--json".to_string()]).await;
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = &report["vulnerabilities"][0];
    assert_eq!(finding["applicability"], "version-unbounded");
    assert_eq!(finding["matched_identity"]["kind"], "cpe");
    assert_eq!(finding["upstream_fixes"], serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn purl_match_keeps_the_other_ecosystem_fixes() {
    let base = spawn_mock_versioned(vuln_doc_purl_matched(), "3.1.0").await;
    let output = run_cli(base.clone(), vec![lockfile()]).await;

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let row = stdout
        .lines()
        .find(|line| line.contains("CVE-2026-50014"))
        .unwrap_or_else(|| panic!("no finding row in stdout: {stdout}"));
    assert!(
        row.contains("npm: 10.34.0, npm: 11.4.0  CVE-2026-50014  Unknown"),
        "row: {row}"
    );
    assert!(!stdout.contains("unbounded"), "stdout: {stdout}");

    let output = run_cli(base, vec![lockfile(), "--json".to_string()]).await;
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = &report["vulnerabilities"][0];
    assert_eq!(finding["applicability"], "evaluated");
    assert_eq!(
        finding["matched_identity"],
        serde_json::json!({"kind": "purl", "value": "pkg:npm/openssl"})
    );
    assert_eq!(
        finding["upstream_fixes"],
        serde_json::json!([
            {"version": "10.34.0", "origin": "ecosystem", "ecosystem": "npm"},
            {"version": "11.4.0", "origin": "ecosystem", "ecosystem": "npm"}
        ])
    );
}
