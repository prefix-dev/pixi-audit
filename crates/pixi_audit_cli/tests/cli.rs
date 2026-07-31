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
        );
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
        let mut cmd = std::process::Command::new(BIN);
        cmd.args(&args)
            .current_dir(&dir)
            .env("PIXI_AUDIT_BASE_URL", base_url);
        if let Some(path) = path_override {
            cmd.env("PATH", path);
        }
        cmd.output().expect("binary runs")
    })
    .await
    .unwrap()
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
        stdout.contains("BSLK-NOFIX (openssl 3.1.0) — until a fix is released"),
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
    assert!(stdout.contains("Ignored 1 finding(s):"), "stdout: {stdout}");
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

    let workspace = temp_workspace("pixi.toml", "[workspace]\nname = \"demo\"\n");
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
        stderr.contains("fixed: resolved 1 of 1 vulnerabilities via pixi update"),
        "stderr: {stderr}"
    );
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
