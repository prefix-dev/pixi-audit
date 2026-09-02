use pixi_audit::{
    AuditReport, AuditSummary, Finding, MatchApplicability, PackageEcosystem, PackageName,
    SeverityBand,
};

use super::*;

fn finding(package: &str, id: &str) -> Finding {
    finding_with_fix(package, id, "conda-forge", &[])
}

fn finding_with_fix(package: &str, id: &str, ecosystem: &str, fixed_versions: &[&str]) -> Finding {
    let ecosystem = match ecosystem {
        "PyPI" => PackageEcosystem::Pypi,
        _ => PackageEcosystem::CondaForge,
    };
    Finding {
        package: PackageName::parse(&ecosystem, package).unwrap(),
        version: "1.0".to_string(),
        ecosystem,
        environments: vec![],
        id: id.to_string(),
        aliases: vec![],
        severity: SeverityBand::High,
        fixed_versions: fixed_versions.iter().map(ToString::to_string).collect(),
        upstream_fixes: vec![],
        applicability: MatchApplicability::Unspecified,
        matched_identity: None,
        summary: None,
        url: None,
        ignore_reason: None,
    }
}

#[test]
fn fixable_package_names_dedupes_and_skips_ignored_and_unfixed() {
    let mut upstream_only = finding("pillow", "CVE-5");
    upstream_only.upstream_fixes = vec![pixi_audit::UpstreamFix {
        version: "10.2.0".to_string(),
        origin: pixi_audit::UpstreamOrigin::Ecosystem {
            ecosystem: "PyPI".to_string(),
        },
    }];
    let report = AuditReport {
        vulnerabilities: vec![
            finding_with_fix("openssl", "CVE-1", "conda-forge", &["3.1.1"]),
            finding_with_fix("openssl", "CVE-2", "conda-forge", &["3.1.2"]),
            finding_with_fix("zlib", "CVE-3", "conda-forge", &["1.3.1"]),
            // No fixed release at all, or only upstream: nothing to update to.
            finding("libexpat", "CVE-4"),
            upstream_only,
        ],
        ignored: vec![finding_with_fix("curl", "CVE-6", "conda-forge", &["8.0"])],
        summary: AuditSummary::default(),
        ..Default::default()
    };
    assert_eq!(fixable_package_names(&report), vec!["openssl", "zlib"]);
}

#[test]
fn empty_report_yields_no_names() {
    assert!(fixable_package_names(&AuditReport::default()).is_empty());
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
fn unparseable_fixed_versions_are_skipped_not_compared_as_text() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("pixi.toml");
    std::fs::write(
        &manifest,
        r#"[workspace]
name = "demo"

[pypi-dependencies]
requests = "*"
"#,
    )
    .unwrap();
    // "10.0" sorts before "9.0" as text; typed comparison must pick 10.0 as
    // the lowest fix above the locked 9.5, and ignore the junk entry.
    let mut finding = finding_with_fix(
        "requests",
        "PYSEC-1",
        "PyPI",
        &["not-a-version", "10.0", "11.0"],
    );
    finding.version = "9.5".to_string();
    let report = AuditReport {
        vulnerabilities: vec![finding],
        ..Default::default()
    };

    assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 1);
    let content = std::fs::read_to_string(manifest).unwrap();
    assert!(content.contains(">=10.0"), "manifest: {content}");
    assert!(!content.contains(">=11.0"), "manifest: {content}");
}

#[test]
fn manifest_keys_match_findings_under_ecosystem_normalization() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("pixi.toml");
    std::fs::write(
        &manifest,
        r#"[workspace]
name = "demo"

[dependencies]
OpenSSL = ">=1"

[pypi-dependencies]
"Ruamel.YAML" = "*"
zope__interface = ">=0.5"
"#,
    )
    .unwrap();
    // Findings carry normalized names; the manifest spells them differently.
    let report = AuditReport {
        vulnerabilities: vec![
            finding_with_fix("openssl", "CVE-1", "conda-forge", &["3.1.1"]),
            finding_with_fix("ruamel-yaml", "PYSEC-1", "PyPI", &["1.18.7"]),
            finding_with_fix("zope-interface", "PYSEC-2", "PyPI", &["6.0"]),
        ],
        ..Default::default()
    };

    let changed = bump_manifest_constraints(&manifest, &report).unwrap();
    let content = std::fs::read_to_string(manifest).unwrap();
    assert_eq!(changed, 3, "manifest: {content}");
    let value: toml::Value = toml::from_str(&content).unwrap();
    let openssl = value["dependencies"]["OpenSSL"].as_str().unwrap();
    assert!(openssl.contains(">=3.1.1"), "constraint: {openssl}");
    let ruamel = value["pypi-dependencies"]["Ruamel.YAML"].as_str().unwrap();
    assert!(ruamel.contains(">=1.18.7"), "constraint: {ruamel}");
    let zope = value["pypi-dependencies"]["zope__interface"]
        .as_str()
        .unwrap();
    assert!(zope.contains(">=6.0"), "constraint: {zope}");
}

#[test]
fn raising_a_constraint_replaces_implied_lower_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("pixi.toml");
    std::fs::write(
        &manifest,
        r#"[workspace]
name = "demo"

[dependencies]
openssl = ">=1,<4"
zlib = ">1.2"

[pypi-dependencies]
requests = ">=2,<3"
urllib3 = ">1.0,!=1.5"
"#,
    )
    .unwrap();
    let report = AuditReport {
        vulnerabilities: vec![
            finding_with_fix("openssl", "CVE-1", "conda-forge", &["3.1.1"]),
            finding_with_fix("zlib", "CVE-2", "conda-forge", &["1.3"]),
            finding_with_fix("requests", "PYSEC-1", "PyPI", &["2.10.0"]),
            finding_with_fix("urllib3", "PYSEC-2", "PyPI", &["2.0"]),
        ],
        ..Default::default()
    };

    assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 4);
    let content = std::fs::read_to_string(&manifest).unwrap();
    let value: toml::Value = toml::from_str(&content).unwrap();
    // The old lower bound is gone, the upper bound and exclusions stay.
    assert_eq!(
        value["dependencies"]["openssl"].as_str(),
        Some("<4,>=3.1.1")
    );
    assert_eq!(value["dependencies"]["zlib"].as_str(), Some(">=1.3"));
    assert_eq!(
        value["pypi-dependencies"]["requests"].as_str(),
        Some(">=2.10.0, <3")
    );
    assert_eq!(
        value["pypi-dependencies"]["urllib3"].as_str(),
        Some("!=1.5, >=2.0")
    );

    // A second run with the same fixes is a no-op.
    assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 0);
    assert_eq!(std::fs::read_to_string(&manifest).unwrap(), content);
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
