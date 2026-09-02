use std::path::Path;

use pixi_audit::{
    AuditReport, AuditSummary, EpssScore, Finding, IgnoreReason, KnownExploited,
    MatchApplicability, PackageEcosystem, PackageName, RansomwareCampaignUse, RiskScore,
    SeverityBand,
};

use super::{LockfileSource, SarifLog};

const LOCKFILE: &str = "version: 6
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

fn finding(id: &str, severity: SeverityBand) -> Finding {
    Finding {
        package: PackageName::conda("openssl").unwrap(),
        version: "3.1.0".to_string(),
        ecosystem: PackageEcosystem::CondaForge,
        environments: vec!["default".to_string(), "prod".to_string()],
        id: id.to_string(),
        aliases: vec![],
        severity,
        cvss_base_score: Some(9.8),
        fixed_versions: vec!["3.1.1".to_string()],
        upstream_fixes: vec![],
        applicability: MatchApplicability::Unspecified,
        matched_identity: None,
        summary: Some("Buffer overflow in openssl".to_string()),
        url: Some(format!("https://osv.dev/{id}")),
        epss: vec![EpssScore {
            cve: id.to_string(),
            epss: 0.5,
            percentile: 0.9,
            date: "2026-09-01".to_string(),
        }],
        known_exploited: vec![KnownExploited {
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
        ignore_reason: None,
    }
}

fn log(report: &AuditReport) -> serde_json::Value {
    let lockfile = LockfileSource {
        path: Path::new("pixi.lock"),
        contents: LOCKFILE,
    };
    serde_json::to_value(SarifLog::from_report(report, &lockfile)).unwrap()
}

#[test]
fn one_rule_per_vulnerability_and_package_with_github_properties() {
    let mut scored = finding("CVE-2026-0001", SeverityBand::Critical);
    scored.risk = RiskScore::compute(
        scored.severity,
        scored.cvss_base_score,
        &scored.epss,
        &scored.known_exploited,
    );
    let report = AuditReport {
        vulnerabilities: vec![scored],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let log = log(&report);

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
    assert!(text.contains("Lock file: pixi.lock"), "{text}");
}

#[test]
fn results_point_at_the_package_line_and_carry_suppressions() {
    let mut ignored = finding("CVE-2026-0002", SeverityBand::Medium);
    ignored.ignore_reason = Some(IgnoreReason::UntilFixed);
    ignored.fixed_versions = vec![];
    let mut pypi = finding("GHSA-1", SeverityBand::Low);
    pypi.package = PackageName::pypi("ruamel-yaml").unwrap();
    pypi.version = "0.18.6".to_string();
    pypi.ecosystem = PackageEcosystem::Pypi;
    pypi.cvss_base_score = None;
    let report = AuditReport {
        vulnerabilities: vec![finding("CVE-2026-0001", SeverityBand::High), pypi],
        ignored: vec![ignored],
        summary: AuditSummary {
            audited: 2,
            vulnerable: 2,
            ignored: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let log = log(&report);
    let results = log["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);

    let conda = &results[0];
    assert_eq!(conda["ruleId"], "CVE-2026-0001-openssl");
    assert_eq!(conda["level"], "error");
    assert_eq!(
        conda["message"]["text"],
        "CVE-2026-0001: high vulnerability in conda-forge package openssl 3.1.0; fixed in 3.1.1"
    );
    let location = &conda["locations"][0]["physicalLocation"];
    assert_eq!(location["artifactLocation"]["uri"], "pixi.lock");
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

    let suppressed = &results[2];
    assert_eq!(suppressed["level"], "warning");
    assert_eq!(
        suppressed["suppressions"],
        serde_json::json!([{
            "kind": "external",
            "justification": "ignored until a fix is released"
        }])
    );
    assert!(
        suppressed["message"]["text"]
            .as_str()
            .unwrap()
            .ends_with("no known fixed version")
    );
}

#[test]
fn a_package_missing_from_the_lock_file_text_falls_back_to_line_1() {
    let mut elsewhere = finding("CVE-2026-0003", SeverityBand::Low);
    elsewhere.version = "9.9.9".to_string();
    let report = AuditReport {
        vulnerabilities: vec![elsewhere],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let log = log(&report);
    assert_eq!(
        log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        1
    );
}

#[test]
fn a_clean_report_has_no_rules_or_results() {
    let log = log(&AuditReport::default());
    assert_eq!(
        log["runs"][0]["tool"]["driver"]["rules"],
        serde_json::json!([])
    );
    assert_eq!(log["runs"][0]["results"], serde_json::json!([]));
}
