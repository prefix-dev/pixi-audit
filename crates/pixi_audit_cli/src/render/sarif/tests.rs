use pixi_audit::{
    AuditReport, AuditSummary, EpssScore, IgnoreMode, KevEntry, Match, MatchConfidence,
    MatchedIdentity, MatchedIdentityKind, PackageEcosystem, PackageId, PackageName,
    RansomwareCampaignUse, RiskScore, SeverityRating,
};

use super::{LockFileSource, SarifLog};

const LOCK_FILE: &str = "version: 6
environments:
  default:
    channels:
    - url: https://conda.anaconda.org/conda-forge/
    packages:
      linux-64:
      - conda: https://conda.anaconda.org/conda-forge/linux-64/openssl-3.1.0-hd590300_3.conda
      - pypi: https://files.pythonhosted.org/packages/py3/r/ruamel_yaml/ruamel_yaml-0.18.6-py3-none-any.whl
packages:
- conda: https://conda.anaconda.org/conda-forge/linux-64/openssl-3.1.0-hd590300_3.conda
";

fn vuln_match(id: &str, severity: SeverityRating) -> Match {
    Match {
        package: PackageId {
            name: PackageName::conda("openssl").unwrap(),
            version: "3.1.0".to_string(),
            ecosystem: PackageEcosystem::CondaForge,
        },
        environments: vec!["default".to_string(), "prod".to_string()],
        id: id.to_string(),
        aliases: vec![],
        severity,
        cvss_base_score: Some(9.8),
        fixed_versions: vec!["3.1.1".to_string()],
        other_ecosystem_fixes: vec![],
        upstream_releases: vec![],
        match_confidence: MatchConfidence::Unspecified,
        matched_identity: None,
        summary: Some("Buffer overflow in openssl".to_string()),
        url: Some(format!("https://osv.dev/{id}")),
        epss: vec![EpssScore {
            cve: id.to_string(),
            epss: 0.5,
            percentile: 0.9,
            date: "2026-09-01".to_string(),
        }],
        kev: vec![KevEntry {
            cve: id.to_string(),
            vendor_project: "OpenSSL".to_string(),
            product: "OpenSSL".to_string(),
            vulnerability_name: "OpenSSL overflow".to_string(),
            date_added: "2026-08-01".to_string(),
            required_action: "Apply updates".to_string(),
            due_date: "2026-08-22".to_string(),
            known_ransomware_campaign_use: RansomwareCampaignUse::Unknown,
            notes: String::new(),
        }],
        risk: RiskScore::NONE,
        ignore_mode: None,
    }
}

/// The log for `report` over a lock file in a fresh directory outside any
/// repository, and the URI that file is expected to be written as.
fn log(report: &AuditReport) -> (serde_json::Value, String) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pixi.lock");
    let lock_file = LockFileSource {
        path: &path,
        contents: LOCK_FILE,
    };
    let log = serde_json::to_value(SarifLog::from_report(report, &lock_file)).unwrap();
    (log, path.to_string_lossy().replace('\\', "/"))
}

#[test]
fn one_rule_per_vulnerability_and_package_with_github_properties() {
    let mut scored = vuln_match("CVE-2026-0001", SeverityRating::Critical);
    scored.risk = RiskScore::compute(
        scored.severity,
        scored.cvss_base_score,
        &scored.epss,
        &scored.kev,
    );
    let report = AuditReport {
        matches: vec![scored],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let (log, uri) = log(&report);

    assert_eq!(log["version"], "2.1.0");
    let driver = &log["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "pixi-audit");
    assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
    let rule = &driver["rules"][0];
    assert_eq!(rule["id"], "CVE-2026-0001-openssl");
    assert_eq!(rule["name"], "CVE-2026-0001");
    assert_eq!(
        rule["shortDescription"]["text"],
        "CVE-2026-0001 critical vulnerability for openssl package"
    );
    assert_eq!(
        rule["fullDescription"]["text"],
        "Buffer overflow in openssl"
    );
    assert_eq!(rule["helpUri"], "https://osv.dev/CVE-2026-0001");
    assert_eq!(rule["properties"]["security-severity"], "9.8");
    assert_eq!(
        rule["properties"]["tags"],
        serde_json::json!(["security", "critical"])
    );
    assert_eq!(
        rule["properties"]["purls"],
        serde_json::json!(["pkg:conda/openssl@3.1.0?channel=conda-forge"])
    );
    let markdown = rule["help"]["markdown"].as_str().unwrap();
    assert!(
        markdown.contains("| 50.0% (90th) | 98.7 | kev |"),
        "{markdown}"
    );
    assert!(
        markdown.contains("[CVE-2026-0001](https://osv.dev/CVE-2026-0001)"),
        "{markdown}"
    );
    let text = rule["help"]["text"].as_str().unwrap();
    assert!(text.contains("Fix: fixed in 3.1.1"), "{text}");
    assert!(text.contains(&format!("Lock file: {uri}")), "{text}");
    // No basilisk match metadata: the rows are there but empty.
    assert!(
        text.contains("\nMatch confidence: \nMatched identity: \n"),
        "{text}"
    );
}

#[test]
fn weak_matches_and_identities_are_reported() {
    let mut unbounded = vuln_match("CVE-2022-25852", SeverityRating::High);
    unbounded.fixed_versions = vec![];
    unbounded.match_confidence = MatchConfidence::VersionUnbounded;
    unbounded.matched_identity = Some(MatchedIdentity {
        kind: MatchedIdentityKind::Cpe,
        value: "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*".to_string(),
    });
    let mut evaluated = vuln_match("CVE-2026-0001", SeverityRating::Critical);
    evaluated.match_confidence = MatchConfidence::Evaluated;
    evaluated.matched_identity = Some(MatchedIdentity {
        kind: MatchedIdentityKind::Purl,
        value: "pkg:npm/openssl".to_string(),
    });
    let report = AuditReport {
        matches: vec![unbounded, evaluated],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 2,
            ..Default::default()
        },
        ..Default::default()
    };
    let (log, _) = log(&report);
    let run = &log["runs"][0];

    let unbounded = &run["tool"]["driver"]["rules"][0]["help"]["text"];
    let unbounded = unbounded.as_str().unwrap();
    assert!(
        unbounded.contains("\nMatch confidence: no version limits\n"),
        "{unbounded}"
    );
    assert!(
        unbounded.contains("\nMatched identity: cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*\n"),
        "{unbounded}"
    );
    assert_eq!(
        run["results"][0]["message"]["text"],
        "CVE-2022-25852: high vulnerability in conda-forge package openssl 3.1.0. \
         no known fixed version. confidence: no version limits"
    );

    let evaluated = run["tool"]["driver"]["rules"][1]["help"]["text"]
        .as_str()
        .unwrap();
    assert!(
        evaluated.contains("\nMatched identity: pkg:npm/openssl\n"),
        "{evaluated}"
    );
}

#[test]
fn results_point_at_the_package_line_and_carry_suppressions() {
    let mut ignored = vuln_match("CVE-2026-0002", SeverityRating::Medium);
    ignored.ignore_mode = Some(IgnoreMode::UntilFixed);
    ignored.fixed_versions = vec![];
    let mut pypi = vuln_match("GHSA-1", SeverityRating::Low);
    pypi.package.name = PackageName::pypi("ruamel-yaml").unwrap();
    pypi.package.version = "0.18.6".to_string();
    pypi.package.ecosystem = PackageEcosystem::Pypi;
    pypi.cvss_base_score = None;
    let report = AuditReport {
        matches: vec![vuln_match("CVE-2026-0001", SeverityRating::High), pypi],
        ignored: vec![ignored],
        summary: AuditSummary {
            audited: 2,
            vulnerable: 2,
            ignored: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let (log, uri) = log(&report);
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);

    let conda = &results[0];
    assert_eq!(conda["ruleId"], "CVE-2026-0001-openssl");
    assert_eq!(conda["level"], "error");
    let location = &conda["locations"][0]["physicalLocation"];
    assert_eq!(location["artifactLocation"]["uri"], uri);
    assert_eq!(location["region"]["startLine"], 8);
    assert!(conda.get("suppressions").is_none());

    // PEP 503 names are spelled with underscores in wheel filenames.
    let wheel = &results[1];
    assert_eq!(wheel["level"], "note");
    assert_eq!(
        wheel["locations"][0]["physicalLocation"]["region"]["startLine"],
        9
    );
    let rules = log["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    let wheel_rule = rules
        .iter()
        .find(|r| r["id"] == "GHSA-1-ruamel-yaml")
        .unwrap();
    assert_eq!(wheel_rule["properties"]["security-severity"], "1.0");
    assert_eq!(
        wheel_rule["properties"]["purls"],
        serde_json::json!(["pkg:pypi/ruamel-yaml@0.18.6"])
    );

    let ignored_result = &results[2];
    assert_eq!(ignored_result["level"], "warning");
    assert_eq!(
        ignored_result["suppressions"],
        serde_json::json!([{
            "kind": "external",
            "justification": "ignored until a fix is released"
        }])
    );
}

#[test]
fn a_package_missing_from_the_lock_file_text_falls_back_to_line_1() {
    let mut elsewhere = vuln_match("CVE-2026-0003", SeverityRating::Low);
    elsewhere.package.version = "9.9.9".to_string();
    let report = AuditReport {
        matches: vec![elsewhere],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let (log, _) = log(&report);
    assert_eq!(
        log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        1
    );
}

#[test]
fn artifact_uri_is_relative_to_the_git_repository_root() {
    let repository = tempfile::tempdir().unwrap();
    std::fs::create_dir(repository.path().join(".git")).unwrap();
    let nested = repository.path().join("apps").join("web");
    std::fs::create_dir_all(&nested).unwrap();
    let lock_file = nested.join("pixi.lock");
    std::fs::write(&lock_file, LOCK_FILE).unwrap();

    let report = AuditReport {
        matches: vec![vuln_match("CVE-2026-0001", SeverityRating::High)],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let log = serde_json::to_value(SarifLog::from_report(
        &report,
        &LockFileSource {
            path: &lock_file,
            contents: LOCK_FILE,
        },
    ))
    .unwrap();
    let result = &log["runs"][0]["results"][0];
    assert_eq!(result["kind"], "fail");
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "apps/web/pixi.lock"
    );
    assert_eq!(
        log["runs"][0]["invocations"],
        serde_json::json!([{"executionSuccessful": true}])
    );

    // Outside any repository and the working directory, the path is used
    // as given.
    let elsewhere = tempfile::tempdir().unwrap();
    let lock_file = elsewhere.path().join("pixi.lock");
    let log = serde_json::to_value(SarifLog::from_report(
        &report,
        &LockFileSource {
            path: &lock_file,
            contents: LOCK_FILE,
        },
    ))
    .unwrap();
    let uri = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        ["uri"]
        .as_str()
        .unwrap();
    assert_eq!(uri, lock_file.to_string_lossy().replace('\\', "/"));
}

#[test]
fn a_clean_report_has_no_rules_or_results() {
    let (log, _) = log(&AuditReport::default());
    assert_eq!(
        log["runs"][0]["tool"]["driver"]["rules"],
        serde_json::json!([])
    );
    assert_eq!(log["runs"][0]["results"], serde_json::json!([]));
}
