use std::path::Path;
use std::process::Output;

use axum::{
    Json, Router,
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
        .route("/v1/vulns/{id}", get(|| async { Json(vuln_doc()) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/")
}

/// Runs the binary without blocking the tokio worker serving the mock.
async fn run_cli(base_url: String, args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(BIN)
            .args(&args)
            .env("PIXI_AUDIT_BASE_URL", base_url)
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
    assert!(
        stdout.contains("openssl 3.1.0 (conda-forge) — default, prod"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("BSLK-1"));
    assert!(stdout.contains("CRITICAL"));
    assert!(stdout.contains("fixed in: 3.1.1"));
    assert!(stdout.contains("https://example.com/adv"));
    assert!(stdout.contains("2 package(s) could not be checked:"));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("error: audit found vulnerabilities"),
        "stderr: {stderr}"
    );
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
    assert!(stdout.contains("Ignored 1 finding(s):"), "stdout: {stdout}");
    assert!(stdout.contains("BSLK-1 (openssl 3.1.0)"));
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
    assert!(!stdout.contains("could not be checked"), "stdout: {stdout}");
    assert!(stdout.contains("openssl 3.1.0 (conda-forge) — prod"));
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
