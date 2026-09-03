use pixi_audit::{
    AuditReport, AuditSummary, EpssScore, Finding, KnownExploited, MatchApplicability,
    PackageEcosystem, PackageName, RansomwareCampaignUse, RiskScore, SeverityBand,
    ThreatDataStatus, ThreatSourceStatus, UncheckedPackage,
};

use pixi_audit::{CondaPublication, UpstreamFix, UpstreamOrigin};

use super::*;

fn on_pypi(version: &str) -> UpstreamFix {
    UpstreamFix {
        version: version.to_string(),
        origin: UpstreamOrigin::Ecosystem {
            ecosystem: "PyPI".to_string(),
        },
    }
}

fn project_release(version: &str, conda_publication: CondaPublication) -> UpstreamFix {
    UpstreamFix {
        version: version.to_string(),
        origin: UpstreamOrigin::Project { conda_publication },
    }
}

#[test]
fn upstream_fixes_say_where_they_exist() {
    let cases = [
        (on_pypi("3.2.0"), "PyPI: 3.2.0", "3.2.0 on PyPI"),
        (
            project_release("2.8.2", CondaPublication::NotPublished),
            "upstream: 2.8.2",
            "2.8.2 released upstream, no conda-forge build",
        ),
        (
            project_release("2.8.2", CondaPublication::Unknown),
            "upstream: 2.8.2 (unconfirmed)",
            "2.8.2 released upstream, conda-forge build unconfirmed",
        ),
    ];
    for (fix, label, sentence) in cases {
        assert_eq!(upstream_fix_label(&fix), label);
        assert_eq!(describe_upstream_fix(&fix), sentence);
    }
}

fn finding(package: &str, id: &str, severity: SeverityBand) -> Finding {
    Finding {
        package: PackageName::conda(package).unwrap(),
        version: "3.1.0".to_string(),
        ecosystem: PackageEcosystem::CondaForge,
        environments: vec!["default".to_string(), "prod".to_string()],
        id: id.to_string(),
        aliases: vec![],
        severity,
        cvss_base_score: None,
        fixed_versions: vec!["3.1.4".to_string()],
        upstream_fixes: vec![],
        applicability: MatchApplicability::Unspecified,
        matched_identity: None,
        summary: None,
        url: Some(format!("https://osv.dev/{id}")),
        epss: vec![],
        known_exploited: vec![],
        risk: RiskScore::NONE,
        ignore_reason: None,
    }
}

fn loaded_threat_data() -> ThreatDataStatus {
    ThreatDataStatus {
        epss: ThreatSourceStatus::Loaded {
            date: Some("2026-09-01".to_string()),
        },
        kev: ThreatSourceStatus::Loaded {
            date: Some("2026-09-01".to_string()),
        },
    }
}

fn kev_entry(cve: &str, ransomware: RansomwareCampaignUse) -> KnownExploited {
    KnownExploited {
        cve: cve.to_string(),
        vendor_project: "OpenSSL".to_string(),
        product: "OpenSSL".to_string(),
        vulnerability_name: "OpenSSL overflow".to_string(),
        date_added: "2026-08-01".to_string(),
        required_action: "Apply updates".to_string(),
        due_date: "2026-08-22".to_string(),
        known_ransomware_campaign_use: ransomware,
        notes: String::new(),
    }
}

#[test]
fn threat_cells_render_risk_epss_and_kev() {
    let mut scored = finding("openssl", "CVE-2026-0001", SeverityBand::Critical);
    scored.epss = vec![EpssScore {
        cve: "CVE-2026-0001".to_string(),
        epss: 0.9077,
        percentile: 0.99796,
        date: "2026-09-01".to_string(),
    }];
    scored.known_exploited = vec![kev_entry("CVE-2026-0001", RansomwareCampaignUse::Known)];
    scored.risk = RiskScore::compute(scored.severity, None, &scored.epss, &scored.known_exploited);
    let mut tiny = finding("openssl", "CVE-2026-0002", SeverityBand::Low);
    tiny.epss = vec![EpssScore {
        cve: "CVE-2026-0002".to_string(),
        epss: 0.0004,
        percentile: 0.112,
        date: "2026-09-01".to_string(),
    }];
    tiny.risk = RiskScore::compute(tiny.severity, None, &tiny.epss, &[]);
    let unscored = finding("openssl", "CVE-2026-0003", SeverityBand::Medium);
    let report = AuditReport {
        vulnerabilities: vec![scored, tiny, unscored],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 3,
            ..Default::default()
        },
        threat_data: loaded_threat_data(),
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    assert!(
        text.contains(
            "  CVE-2026-0001  CRITICAL  risk  99.0 (kev, ransomware)  epss 99th · 90.8%  fixed in: 3.1.4\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "  CVE-2026-0002  LOW       risk < 0.1  epss 11th · < 0.1%  fixed in: 3.1.4\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("  CVE-2026-0003  MEDIUM    risk   n/a  epss n/a  fixed in: 3.1.4\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "  • Highest finding risk score:         99.0 / 100\n  \
         • CISA KEV matches:                   1 CVE — exploitation confirmed in the wild"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "  • Fix available in audited ecosystem: 3 of 3 vulnerabilities across 1 audited package"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "  • Prioritize 1 CISA KEV match; exploitation has been confirmed in the wild."
        )
    );
}

#[test]
fn threat_cells_are_omitted_when_no_source_is_configured() {
    let report = AuditReport {
        vulnerabilities: vec![finding("openssl", "CVE-2026-0001", SeverityBand::High)],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    assert!(
        text.contains("  CVE-2026-0001  HIGH      fixed in: 3.1.4\n"),
        "{text}"
    );
    assert!(!text.contains("  risk "));
    assert!(!text.contains("  epss "));
}

#[test]
fn unavailable_kev_catalog_is_not_reported_as_zero() {
    let report = AuditReport {
        vulnerabilities: vec![finding("openssl", "CVE-2026-0001", SeverityBand::High)],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        threat_data: ThreatDataStatus {
            epss: ThreatSourceStatus::Disabled,
            kev: ThreatSourceStatus::Failed {
                error: "request timed out".to_string(),
            },
        },
        ..Default::default()
    };

    let text = render_human(&report, RenderOptions::default());
    assert!(
        text.contains("  • CISA KEV matches:                   n/a — CISA KEV catalog unavailable")
    );
    assert!(!text.contains("CISA KEV matches:                   0 CVEs"));
}

#[test]
fn kev_is_marked_on_the_risk_cell() {
    let mut listed = finding("openssl", "CVE-2026-0001", SeverityBand::High);
    listed.known_exploited = vec![kev_entry("CVE-2026-0001", RansomwareCampaignUse::Unknown)];
    listed.risk = RiskScore::compute(listed.severity, None, &[], &listed.known_exploited);
    let report = AuditReport {
        vulnerabilities: vec![listed],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        threat_data: ThreatDataStatus {
            epss: ThreatSourceStatus::Disabled,
            kev: ThreatSourceStatus::Loaded { date: None },
        },
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    // High (7.5 / 10) with threat 1.0 and the 1.05 boost; no EPSS cell
    // since that source is off.
    assert!(
        text.contains("  CVE-2026-0001  HIGH      risk  78.8 (kev)  fixed in: 3.1.4\n"),
        "{text}"
    );
}

#[test]
fn unknown_severity_keeps_threat_cells() {
    let mut unknown = finding("requests", "PYSEC-2026-1", SeverityBand::Unknown);
    unknown.ecosystem = PackageEcosystem::Pypi;
    unknown.epss = vec![EpssScore {
        cve: "CVE-2026-9999".to_string(),
        epss: 0.25,
        percentile: 0.953,
        date: "2026-09-01".to_string(),
    }];
    unknown.risk = RiskScore::compute(unknown.severity, None, &unknown.epss, &[]);
    let report = AuditReport {
        vulnerabilities: vec![unknown],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        threat_data: loaded_threat_data(),
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    assert!(
        text.contains("  PYSEC-2026-1  risk  12.5  epss 95th · 25.0%  fixed in: 3.1.4\n"),
        "{text}"
    );
    assert!(text.contains("  • CISA KEV matches:                   0 CVEs"));
}

#[test]
fn empty_report_renders_clean_summary() {
    let report = AuditReport {
        summary: AuditSummary {
            audited: 5,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    assert_eq!(
        text,
        "No vulnerabilities found (5 audited, 0 ignored, 0 unchecked)\n\nNext steps\n  • None. No vulnerabilities were found in checked packages.\n"
    );
}

#[test]
fn findings_are_grouped_per_package_with_fix_and_url() {
    let mut second = finding("openssl", "CVE-2026-0002", SeverityBand::Medium);
    second.fixed_versions = vec![];
    second.upstream_fixes = vec![on_pypi("3.2.0")];
    second.url = None;
    let report = AuditReport {
        vulnerabilities: vec![
            finding("openssl", "CVE-2026-0001", SeverityBand::High),
            second,
        ],
        summary: AuditSummary {
            audited: 10,
            vulnerable: 2,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    assert_eq!(
        text.matches("openssl 3.1.0 (conda-forge) — default, prod")
            .count(),
        1
    );
    assert!(text.contains("CVE-2026-0001  HIGH      fixed in: 3.1.4"));
    assert!(text.contains("https://osv.dev/CVE-2026-0001"));
    assert!(text.contains("CVE-2026-0002  MEDIUM    fix released elsewhere: 3.2.0 on PyPI"));
    assert!(
        text.contains("2 vulnerabilities in 1 package(s) (10 audited, 0 ignored, 0 unchecked)")
    );
    assert!(text.contains(
        "  • Fix available in audited ecosystem: 1 of 2 vulnerabilities across 1 audited package"
    ));
    assert!(text.contains("  • Fix only upstream:                  1 vulnerability"));
    assert!(text.contains("  • No known fix:                       0 vulnerabilities"));
    assert!(text.contains(
        "Re-run this audit with `--fix` to ask pixi to update 1 package name. Fixed releases in the audited ecosystem are available for 1 vulnerability."
    ));
    assert!(text.contains("1 vulnerability has a fix only upstream; `--fix` cannot install it."));
}

#[test]
fn hyperlinks_wrap_the_id_and_replace_the_url_line() {
    let mut without_url = finding("openssl", "CVE-2026-0002", SeverityBand::Medium);
    without_url.url = None;
    let report = AuditReport {
        vulnerabilities: vec![
            finding("openssl", "CVE-2026-0001", SeverityBand::High),
            without_url,
        ],
        summary: AuditSummary {
            audited: 10,
            vulnerable: 2,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = render_human(
        &report,
        RenderOptions {
            hyperlinks: true,
            ..Default::default()
        },
    );
    assert!(text.contains(
        "  \x1b]8;;https://osv.dev/CVE-2026-0001\x1b\\CVE-2026-0001\x1b]8;;\x1b\\  HIGH      fixed in: 3.1.4\n"
    ));
    assert!(!text.contains("\n  https://osv.dev/CVE-2026-0001"));
    assert!(text.contains("\n  CVE-2026-0002  MEDIUM    fixed in: 3.1.4\n"));
}

#[test]
fn findings_from_different_ecosystems_are_separate_packages() {
    let conda = finding("openssl", "CVE-2026-0001", SeverityBand::High);
    let mut pypi = finding("openssl", "CVE-2026-0002", SeverityBand::Medium);
    pypi.package = PackageName::pypi("openssl").unwrap();
    pypi.ecosystem = PackageEcosystem::Pypi;
    pypi.environments = vec!["docs".to_string()];
    let report = AuditReport {
        vulnerabilities: vec![conda, pypi],
        summary: AuditSummary {
            audited: 2,
            vulnerable: 2,
            ..Default::default()
        },
        ..Default::default()
    };

    let text = render_human(&report, RenderOptions::default());
    assert!(text.contains("openssl 3.1.0 (conda-forge) — default, prod"));
    assert!(text.contains("openssl 3.1.0 (PyPI) — docs"));
    assert!(text.contains("2 vulnerabilities in 2 package(s)"));
    assert!(text.contains(
        "Fix available in audited ecosystem: 2 of 2 vulnerabilities across 2 audited packages"
    ));
    assert!(text.contains("Re-run this audit with `--fix` to ask pixi to update 1 package name."));
}

#[test]
fn finding_without_any_fix_says_so() {
    let mut f = finding("openssl", "CVE-2026-0003", SeverityBand::Unknown);
    f.fixed_versions = vec![];
    let report = AuditReport {
        vulnerabilities: vec![f],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    assert!(text.contains("CVE-2026-0003  no known fixed version"));
    assert!(!text.contains("UNKNOWN"));
    assert!(text.contains(
        "1 vulnerability has no known fix. Remove, replace, or mitigate the affected dependencies"
    ));
}

#[test]
fn grouped_report_after_fix_recommends_review_instead_of_retry() {
    let report = AuditReport {
        vulnerabilities: vec![finding("openssl", "CVE-2026-0001", SeverityBand::Critical)],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = render_human(
        &report,
        RenderOptions {
            fix_attempted: true,
            ..Default::default()
        },
    );
    assert!(text.contains(
        "`--fix` completed, but 1 vulnerability with a fix in the audited ecosystem remains. Review dependency constraints and pixi's solver output."
    ));
    assert!(!text.contains("Re-run this audit with `--fix`"));
}

#[test]
fn grouped_report_without_manifest_does_not_offer_fix() {
    let report = AuditReport {
        vulnerabilities: vec![finding("openssl", "CVE-2026-0001", SeverityBand::Critical)],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = render_human(
        &report,
        RenderOptions {
            manifest_available: false,
            ..Default::default()
        },
    );
    assert!(text.contains(
        "Fixed releases in the audited ecosystem are available for 1 vulnerability across 1 audited package, but `--fix` requires a `pixi.toml` or `pyproject.toml` next to the audited lock file."
    ));
    assert!(!text.contains("Re-run this audit with `--fix` to ask pixi"));
}

#[test]
fn ignored_and_unchecked_sections_render() {
    let report = AuditReport {
        ignored: vec![finding("openssl", "CVE-2026-0001", SeverityBand::High)],
        unchecked: vec![UncheckedPackage {
            package: PackageName::conda("samtools").unwrap(),
            version: Some("1.19".to_string()),
            ecosystem: PackageEcosystem::Other("bioconda".to_string()),
            environments: vec!["default".to_string()],
        }],
        summary: AuditSummary {
            audited: 3,
            vulnerable: 0,
            ignored: 1,
            unchecked: 1,
        },
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    assert!(
        text.starts_with("1 package(s) could not be checked:"),
        "{text}"
    );
    assert!(text.contains("Ignored 1 finding(s):"));
    assert!(text.contains("  CVE-2026-0001 (openssl 3.1.0)"));
    assert!(text.contains("1 package(s) could not be checked:"));
    assert!(text.contains("  samtools 1.19 (bioconda) — default"));
    assert!(text.contains("No vulnerabilities found (3 audited, 1 ignored, 1 unchecked)"));
    assert!(text.contains("No active vulnerabilities were found in checked packages."));
    assert!(text.contains("Review 1 ignored finding periodically."));
    assert!(text.contains(
        "Review 1 unchecked package; its source is not covered by the configured vulnerability databases."
    ));
}

#[test]
fn until_fixed_ignores_are_marked() {
    let mut always = finding("openssl", "CVE-2026-0001", SeverityBand::High);
    always.ignore_reason = Some(pixi_audit::IgnoreReason::Always);
    let mut until = finding("openssl", "CVE-2026-0002", SeverityBand::High);
    until.ignore_reason = Some(pixi_audit::IgnoreReason::UntilFixed);
    let report = AuditReport {
        ignored: vec![always, until],
        summary: AuditSummary {
            ignored: 2,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    assert!(text.contains("  CVE-2026-0001 (openssl 3.1.0)\n"));
    assert!(text.contains("  CVE-2026-0002 (openssl 3.1.0) — until a fix is released\n"));
}

#[test]
fn unchecked_package_without_version_renders_question_mark() {
    let report = AuditReport {
        unchecked: vec![UncheckedPackage {
            package: PackageName::conda("mypkg").unwrap(),
            version: None,
            ecosystem: PackageEcosystem::Other("unknown".to_string()),
            environments: vec!["default".to_string()],
        }],
        summary: AuditSummary {
            unchecked: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        render_human(&report, RenderOptions::default()).contains("  mypkg ? (unknown) — default")
    );
}

#[test]
fn weak_matches_carry_a_note() {
    let mut unbounded = finding("libpq", "CVE-2022-25852", SeverityBand::High);
    unbounded.fixed_versions = vec![];
    unbounded.applicability = MatchApplicability::VersionUnbounded;
    let mut unevaluated = finding("libpq", "CVE-2026-0009", SeverityBand::Medium);
    unevaluated.applicability = MatchApplicability::Unevaluated;
    let mut evaluated = finding("libpq", "CVE-2026-0010", SeverityBand::Low);
    evaluated.applicability = MatchApplicability::Evaluated;
    let report = AuditReport {
        vulnerabilities: vec![unbounded, unevaluated, evaluated],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 3,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    assert!(
        text.contains(
            "CVE-2022-25852  HIGH      no known fixed version  match: version unbounded\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("CVE-2026-0009  MEDIUM    fixed in: 3.1.4  match: unevaluated\n"),
        "{text}"
    );
    assert!(
        text.contains("CVE-2026-0010  LOW       fixed in: 3.1.4\n"),
        "{text}"
    );
}
