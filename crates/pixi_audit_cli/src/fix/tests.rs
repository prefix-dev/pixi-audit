use pixi_audit::{AuditReport, AuditSummary, Finding, PackageEcosystem, SeverityBand};

use super::*;

fn finding(package: &str, id: &str) -> Finding {
    finding_with_fix(package, id, "conda-forge", &[])
}

fn finding_with_fix(package: &str, id: &str, ecosystem: &str, fixed_versions: &[&str]) -> Finding {
    Finding {
        package: package.to_string(),
        version: "1.0".to_string(),
        ecosystem: match ecosystem {
            "PyPI" => PackageEcosystem::Pypi,
            _ => PackageEcosystem::CondaForge,
        },
        environments: vec![],
        id: id.to_string(),
        aliases: vec![],
        severity: SeverityBand::High,
        fixed_versions: fixed_versions.iter().map(ToString::to_string).collect(),
        upstream_fixed_versions: vec![],
        summary: None,
        url: None,
        ignore_reason: None,
    }
}

#[test]
fn vulnerable_package_names_dedupes_and_skips_ignored() {
    let report = AuditReport {
        vulnerabilities: vec![
            finding("openssl", "CVE-1"),
            finding("openssl", "CVE-2"),
            finding("pillow", "CVE-3"),
        ],
        ignored: vec![finding("zlib", "CVE-4")],
        summary: AuditSummary::default(),
        ..Default::default()
    };
    assert_eq!(vulnerable_package_names(&report), vec!["openssl", "pillow"]);
}

#[test]
fn empty_report_yields_no_names() {
    assert!(vulnerable_package_names(&AuditReport::default()).is_empty());
}

#[test]
fn bumps_constraints_across_pixi_dependency_tables() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("pixi.toml");
    std::fs::write(
        &manifest,
        r#"[workspace]
name = "demo"

[tasks]
test = "cargo test"

[dependencies]
openssl = ">=1,<4" # keep this comment
zlib = { version = ">=1", channel = "conda-forge" }

[feature.test.pypi-dependencies]
requests = ">=2,<3"
urllib3 = { git = "https://example.com/urllib3" }

[target.linux-64.host-dependencies]
openssl = { version = ">=1", build = "*_0" }
"#,
    )
    .unwrap();
    let report = AuditReport {
        vulnerabilities: vec![
            finding_with_fix("openssl", "CVE-1", "conda-forge", &["3.1.1"]),
            finding_with_fix("requests", "PYSEC-1", "PyPI", &["2.9.0"]),
            finding_with_fix("requests", "PYSEC-2", "PyPI", &["2.10.0"]),
        ],
        ..Default::default()
    };

    assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 3);
    let content = std::fs::read_to_string(&manifest).unwrap();
    let value: toml::Value = toml::from_str(&content).unwrap();
    let openssl = value["dependencies"]["openssl"].as_str().unwrap();
    assert!(openssl.contains(">=3.1.1"), "constraint: {openssl}");
    assert!(openssl.contains("<4"), "constraint: {openssl}");
    assert_eq!(
        value["dependencies"]["zlib"]["version"].as_str(),
        Some(">=1")
    );
    let requests = value["feature"]["test"]["pypi-dependencies"]["requests"]
        .as_str()
        .unwrap();
    assert!(requests.contains(">=2.10.0"), "constraint: {requests}");
    assert!(requests.contains("<3"), "constraint: {requests}");
    assert_eq!(
        value["feature"]["test"]["pypi-dependencies"]["urllib3"]["git"].as_str(),
        Some("https://example.com/urllib3")
    );
    let target_openssl = value["target"]["linux-64"]["host-dependencies"]["openssl"]["version"]
        .as_str()
        .unwrap();
    assert!(
        target_openssl.contains(">=3.1.1"),
        "constraint: {target_openssl}"
    );
    assert!(content.contains("# keep this comment"));
    assert_eq!(value["tasks"]["test"].as_str(), Some("cargo test"));
}

#[test]
fn bumps_only_tool_pixi_in_pyproject() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("pyproject.toml");
    std::fs::write(
        &manifest,
        r#"[project]
dependencies = ["requests>=2"]

[tool.pixi.workspace]
name = "demo"

[tool.pixi.pypi-dependencies]
requests = { version = ">=2", extras = ["socks"] }
"#,
    )
    .unwrap();
    let report = AuditReport {
        vulnerabilities: vec![finding_with_fix("Requests", "PYSEC-1", "PyPI", &["2.33.0"])],
        ..Default::default()
    };

    assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 1);
    let content = std::fs::read_to_string(&manifest).unwrap();
    let value: toml::Value = toml::from_str(&content).unwrap();
    assert_eq!(
        value["project"]["dependencies"][0].as_str(),
        Some("requests>=2")
    );
    let requests = value["tool"]["pixi"]["pypi-dependencies"]["requests"]["version"]
        .as_str()
        .unwrap();
    assert!(requests.contains(">=2.33.0"), "constraint: {requests}");
    assert_eq!(
        value["tool"]["pixi"]["pypi-dependencies"]["requests"]["extras"][0].as_str(),
        Some("socks")
    );
}

#[test]
fn bumps_multiline_inline_dependency_maps() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("pixi.toml");
    std::fs::write(
        &manifest,
        r#"[workspace]
name = "demo"

[feature.test]
dependencies = {
    openssl = ">=1,<4",
}
pypi-dependencies = {
    requests = { version = ">=2,<3", extras = ["socks"] },
}
"#,
    )
    .unwrap();
    let report = AuditReport {
        vulnerabilities: vec![
            finding_with_fix("openssl", "CVE-1", "conda-forge", &["3.1.1"]),
            finding_with_fix("requests", "PYSEC-1", "PyPI", &["2.33.0"]),
        ],
        ..Default::default()
    };

    assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 2);
    let content = std::fs::read_to_string(manifest).unwrap();
    let value: toml::Value = toml::from_str(&content).unwrap();
    let openssl = value["feature"]["test"]["dependencies"]["openssl"]
        .as_str()
        .unwrap();
    assert!(openssl.contains(">=3.1.1"), "constraint: {openssl}");
    assert!(openssl.contains("<4"), "constraint: {openssl}");
    let requests = value["feature"]["test"]["pypi-dependencies"]["requests"]["version"]
        .as_str()
        .unwrap();
    assert!(requests.contains(">=2.33.0"), "constraint: {requests}");
    assert!(requests.contains("<3"), "constraint: {requests}");
    assert_eq!(
        value["feature"]["test"]["pypi-dependencies"]["requests"]["extras"][0].as_str(),
        Some("socks")
    );
}

#[test]
fn chooses_lowest_fixed_release_branch() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("pixi.toml");
    std::fs::write(
        &manifest,
        r#"[workspace]
name = "demo"

[pypi-dependencies]
requests = ">=1,<2"
"#,
    )
    .unwrap();
    let report = AuditReport {
        vulnerabilities: vec![finding_with_fix(
            "requests",
            "PYSEC-1",
            "PyPI",
            &["2.1", "1.5"],
        )],
        ..Default::default()
    };

    assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 1);
    let content = std::fs::read_to_string(manifest).unwrap();
    assert!(content.contains(">=1.5"), "manifest: {content}");
    assert!(content.contains("<2"), "manifest: {content}");
    assert!(!content.contains(">=2.1"), "manifest: {content}");
}

#[test]
fn leaves_constraint_unchanged_when_no_fix_satisfies_it() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("pixi.toml");
    let content = r#"[workspace]
name = "demo"

[pypi-dependencies]
requests = ">=1,<1.5"
"#;
    std::fs::write(&manifest, content).unwrap();
    let report = AuditReport {
        vulnerabilities: vec![finding_with_fix(
            "requests",
            "PYSEC-1",
            "PyPI",
            &["2.0", "1.5"],
        )],
        ..Default::default()
    };

    assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 0);
    assert_eq!(std::fs::read_to_string(manifest).unwrap(), content);
}
