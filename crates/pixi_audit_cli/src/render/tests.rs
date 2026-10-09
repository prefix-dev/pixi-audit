use pixi_audit::{
    AuditPackage, AuditReport, AuditSummary, EpssScore, IgnoreMode, KevEntry, Match,
    PackageEcosystem, PackageId, PackageName, RansomwareCampaignUse, RiskScore, SeverityRating,
    ThreatDataStatus, ThreatSourceStatus,
};

use pixi_audit::{CondaForgeBuild, OtherEcosystemFix, UpstreamRelease};

use super::*;

fn on_pypi(version: &str) -> OtherEcosystemFix {
    OtherEcosystemFix {
        version: version.to_string(),
        ecosystem: "PyPI".to_string(),
    }
}

fn upstream_release(version: &str, conda_forge_build: CondaForgeBuild) -> UpstreamRelease {
    UpstreamRelease {
        version: version.to_string(),
        conda_forge_build,
    }
}

#[test]
fn other_ecosystem_fixes_say_where_they_exist() {
    let fix = on_pypi("3.2.0");
    assert_eq!(other_ecosystem_fix_label(&fix), "PyPI: 3.2.0");
    assert_eq!(describe_other_ecosystem_fix(&fix), "3.2.0 on PyPI");
}

#[test]
fn upstream_releases_say_whether_conda_forge_has_a_build() {
    let cases = [
        (
            upstream_release("2.8.2", CondaForgeBuild::Missing),
            "upstream: 2.8.2",
            "2.8.2 released upstream, no conda-forge build",
        ),
        (
            upstream_release("2.8.2", CondaForgeBuild::Unknown),
            "upstream: 2.8.2 (unconfirmed)",
            "2.8.2 released upstream, conda-forge build unconfirmed",
        ),
        (
            upstream_release("2.8.2", CondaForgeBuild::Available),
            "upstream: 2.8.2",
            "2.8.2 released upstream",
        ),
    ];
    for (release, label, sentence) in cases {
        assert_eq!(upstream_release_label(&release), label);
        assert_eq!(describe_upstream_release(&release), sentence);
    }
}

#[test]
fn fixes_elsewhere_list_other_ecosystems_before_upstream_releases() {
    let mut vuln_match = vuln_match("openssl", "CVE-2026-0002", SeverityRating::Medium);
    vuln_match.fixed_versions = vec![];
    vuln_match.other_ecosystem_fixes = vec![on_pypi("3.2.0")];
    vuln_match.upstream_releases = vec![upstream_release("3.2.1", CondaForgeBuild::Missing)];
    assert_eq!(
        fix_elsewhere_labels(&vuln_match),
        vec!["PyPI: 3.2.0".to_string(), "upstream: 3.2.1".to_string()]
    );
    assert_eq!(
        describe_fixes_elsewhere(&vuln_match),
        "3.2.0 on PyPI; 3.2.1 released upstream, no conda-forge build"
    );
}

fn vuln_match(package: &str, id: &str, severity: SeverityRating) -> Match {
    Match {
        package: PackageId {
            name: PackageName::conda(package).unwrap(),
            version: "3.1.0".to_string(),
            ecosystem: PackageEcosystem::CondaForge,
        },
        environments: vec!["default".to_string(), "prod".to_string()],
        id: id.to_string(),
        aliases: vec![],
        severity,
        cvss_base_score: None,
        fixed_versions: vec!["3.1.4".to_string()],
        other_ecosystem_fixes: vec![],
        upstream_releases: vec![],
        match_confidence: MatchConfidence::Unspecified,
        matched_identity: None,
        summary: None,
        url: Some(format!("https://osv.dev/{id}")),
        epss: vec![],
        kev: vec![],
        risk: RiskScore::NONE,
        ignore_mode: None,
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

fn kev_entry(cve: &str, ransomware: RansomwareCampaignUse) -> KevEntry {
    KevEntry {
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
    let mut scored = vuln_match("openssl", "CVE-2026-0001", SeverityRating::Critical);
    scored.epss = vec![
        EpssScore {
            cve: "CVE-2026-0000".to_string(),
            epss: 0.01,
            percentile: 0.4,
            date: "2026-09-01".to_string(),
        },
        EpssScore {
            cve: "CVE-2026-0001".to_string(),
            epss: 0.9077,
            percentile: 0.99796,
            date: "2026-09-01".to_string(),
        },
    ];
    scored.kev = vec![kev_entry("CVE-2026-0001", RansomwareCampaignUse::Known)];
    scored.risk = RiskScore::compute(scored.severity, None, &scored.epss, &scored.kev);
    let mut tiny = vuln_match("openssl", "CVE-2026-0002", SeverityRating::Low);
    tiny.epss = vec![EpssScore {
        cve: "CVE-2026-0002".to_string(),
        epss: 0.0004,
        percentile: 0.112,
        date: "2026-09-01".to_string(),
    }];
    tiny.risk = RiskScore::compute(tiny.severity, None, &tiny.epss, &[]);
    let unscored = vuln_match("openssl", "CVE-2026-0003", SeverityRating::Medium);
    let report = AuditReport {
        matches: vec![scored, tiny, unscored],
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
        text.contains("  CVE-2026-0001  CRITICAL  risk  99.0 (kev, ransomware)  epss 99th · 90.8%"),
        "{text}"
    );
    assert!(
        text.contains("  CVE-2026-0002  LOW       risk < 0.1  epss 11th · < 0.1%"),
        "{text}"
    );
    assert!(
        text.contains("  CVE-2026-0003  MEDIUM    risk   n/a  epss n/a"),
        "{text}"
    );
    assert!(
        text.lines()
            .any(|line| { line.contains("Highest risk score:") && line.ends_with("99.0 / 100") }),
        "{text}"
    );
    assert!(
        text.lines().any(|line| {
            line.contains("CISA KEV matches:")
                && line.ends_with("1 CVE — exploitation confirmed in the wild")
        }),
        "{text}"
    );
    assert!(
        text.lines().any(|line| {
            line.contains("Fix available in audited ecosystem:")
                && line.ends_with("3 of 3 vulnerabilities across 1 audited package")
        }),
        "{text}"
    );
    assert!(text.contains(
        "  • Prioritize 1 CISA KEV match because exploitation has been confirmed in the wild."
    ));
}

#[test]
fn threat_cells_are_omitted_when_no_source_is_configured() {
    let report = AuditReport {
        matches: vec![vuln_match("openssl", "CVE-2026-0001", SeverityRating::High)],
        summary: AuditSummary {
            audited: 1,
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    assert!(!text.contains("  risk "));
    assert!(!text.contains("  epss "));
}

#[test]
fn unavailable_kev_catalog_is_not_reported_as_zero() {
    let report = AuditReport {
        matches: vec![vuln_match("openssl", "CVE-2026-0001", SeverityRating::High)],
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
    assert!(text.lines().any(|line| {
        line.contains("CISA KEV matches:") && line.ends_with("n/a — CISA KEV catalog unavailable")
    }));
    assert!(!text.contains("CISA KEV matches:                      0 CVEs"));
}

#[test]
fn kev_is_marked_on_the_risk_cell() {
    let mut listed = vuln_match("openssl", "CVE-2026-0001", SeverityRating::High);
    listed.kev = vec![kev_entry("CVE-2026-0001", RansomwareCampaignUse::Unknown)];
    listed.risk = RiskScore::compute(listed.severity, None, &[], &listed.kev);
    let report = AuditReport {
        matches: vec![listed],
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
        text.contains("  CVE-2026-0001  HIGH      risk  78.8 (kev)"),
        "{text}"
    );
}

#[test]
fn explain_adds_contextual_definitions_after_actions() {
    let mut listed = vuln_match("openssl", "CVE-2026-0001", SeverityRating::High);
    listed.epss = vec![EpssScore {
        cve: "CVE-2026-0001".to_string(),
        epss: 0.5,
        percentile: 0.9,
        date: "2026-09-01".to_string(),
    }];
    listed.kev = vec![kev_entry("CVE-2026-0001", RansomwareCampaignUse::Unknown)];
    listed.match_confidence = MatchConfidence::VersionUnbounded;
    listed.risk = RiskScore::compute(listed.severity, None, &listed.epss, &listed.kev);

    let mut ignored = vuln_match("libxml2", "CVE-2026-0002", SeverityRating::Low);
    ignored.ignore_mode = Some(IgnoreMode::Permanent);
    let report = AuditReport {
        matches: vec![listed],
        ignored: vec![ignored],
        not_audited: vec![AuditPackage {
            name: PackageName::conda("samtools").unwrap(),
            version: Some("1.2".to_string()),
            ecosystem: PackageEcosystem::Other("bioconda".to_string()),
            environments: vec!["default".to_string()],
        }],
        summary: AuditSummary {
            audited: 3,
            vulnerable: 1,
            ignored: 1,
            not_audited: 1,
        },
        threat_data: loaded_threat_data(),
        ..Default::default()
    };
    let text = render_human(
        &report,
        RenderOptions {
            explain: true,
            ..Default::default()
        },
    );
    let actions = text.find("Recommendations").unwrap();
    let explanation = text.find("Definitions").unwrap();
    assert!(actions < explanation, "{text}");
    assert!(
        text.contains(
            "Definitions\n\n  Counts\n    Package              One locked name, version, and source.\n"
        ),
        "{text}"
    );
    let threat = text.find("\n  Threat data\n").unwrap();
    let risk = text.find("\n  Risk\n").unwrap();
    assert!(threat < risk, "{text}");
    assert!(
        text.contains(
            "\n    Risk      A 0–100 score for ordering individual vulnerability matches.\n      Formula   min(threat × severity × boost, 1) × 100.\n    Threat"
        ),
        "{text}"
    );
    assert!(text.contains("\n  Fixes\n"), "{text}");
    assert!(text.contains("\n  Ignored and not audited\n"), "{text}");
    for expected in [
        "A 0–100 score for ordering individual vulnerability matches.",
        "highest EPSS probability",
        "Critical .90, high .75, medium/unknown .50, low .30.",
        "CISA confirms exploitation in the wild.",
        "Estimated chance of exploitation within 30 days.",
        "`kev` alone means CISA does not mark that use as Known.",
        "A fixed release exists for the audited package source.",
        "Fix only elsewhere",
        "Audit sources list no fixed release.",
        "Excluded from active totals and the failure decision.",
        "The package source lacks vulnerability database coverage.",
        "The advisory has no usable version bounds",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }
    assert!(!text.contains("\n    Version not checked"), "{text}");
}

#[test]
fn unknown_severity_keeps_threat_cells() {
    let mut unknown = vuln_match("requests", "PYSEC-2026-1", SeverityRating::Unknown);
    unknown.package.ecosystem = PackageEcosystem::Pypi;
    unknown.epss = vec![EpssScore {
        cve: "CVE-2026-9999".to_string(),
        epss: 0.25,
        percentile: 0.953,
        date: "2026-09-01".to_string(),
    }];
    unknown.risk = RiskScore::compute(unknown.severity, None, &unknown.epss, &[]);
    let report = AuditReport {
        matches: vec![unknown],
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
    assert!(
        text.lines()
            .any(|line| line.contains("CISA KEV matches:") && line.ends_with("0 CVEs"))
    );
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
        "No vulnerabilities found (5 audited, 0 ignored, 0 not audited)\n\nRecommendations\n  • None. No vulnerabilities were found in audited packages.\n\nAdd `--explain` for scoring and report definitions.\n"
    );
}

#[test]
fn matches_are_grouped_per_package_with_fix_and_url() {
    let mut second = vuln_match("openssl", "CVE-2026-0002", SeverityRating::Medium);
    second.fixed_versions = vec![];
    second.other_ecosystem_fixes = vec![on_pypi("3.2.0")];
    second.url = None;
    let report = AuditReport {
        matches: vec![
            vuln_match("openssl", "CVE-2026-0001", SeverityRating::High),
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
        text.contains("2 vulnerabilities in 1 package(s) (10 audited, 0 ignored, 0 not audited)")
    );
    assert!(text.lines().any(|line| {
        line.contains("Fix available in audited ecosystem:")
            && line.ends_with("1 of 2 vulnerabilities across 1 audited package")
    }));
    assert!(
        text.lines()
            .any(|line| line.contains("Fix only elsewhere:") && line.ends_with("1 vulnerability"))
    );
    assert!(
        text.lines()
            .any(|line| line.contains("No known fix:") && line.ends_with("0 vulnerabilities"))
    );
    assert!(text.contains(
        "Re-run this audit with `--fix` to ask pixi to update 1 package name. Fixed releases in the audited ecosystem are available for 1 vulnerability."
    ));
    assert!(text.contains("1 vulnerability has a fix only elsewhere. `--fix` cannot install it."));
}

#[test]
fn hyperlinks_wrap_the_id_and_replace_the_url_line() {
    let mut without_url = vuln_match("openssl", "CVE-2026-0002", SeverityRating::Medium);
    without_url.url = None;
    let report = AuditReport {
        matches: vec![
            vuln_match("openssl", "CVE-2026-0001", SeverityRating::High),
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
    assert!(
        text.contains("  \x1b]8;;https://osv.dev/CVE-2026-0001\x1b\\CVE-2026-0001\x1b]8;;\x1b\\")
    );
    assert!(!text.contains("\n  https://osv.dev/CVE-2026-0001"));
    assert!(text.contains("\n  CVE-2026-0002  MEDIUM"));
}

#[test]
fn matches_from_different_ecosystems_are_separate_packages() {
    let conda = vuln_match("openssl", "CVE-2026-0001", SeverityRating::High);
    let mut pypi = vuln_match("openssl", "CVE-2026-0002", SeverityRating::Medium);
    pypi.package.name = PackageName::pypi("openssl").unwrap();
    pypi.package.ecosystem = PackageEcosystem::Pypi;
    pypi.environments = vec!["docs".to_string()];
    let report = AuditReport {
        matches: vec![conda, pypi],
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
    assert!(text.lines().any(|line| {
        line.contains("Fix available in audited ecosystem:")
            && line.ends_with("2 of 2 vulnerabilities across 2 audited packages")
    }));
    assert!(text.contains("Re-run this audit with `--fix` to ask pixi to update 1 package name."));
}

#[test]
fn match_without_any_fix_says_so() {
    let mut no_fix = vuln_match("openssl", "CVE-2026-0003", SeverityRating::Unknown);
    no_fix.fixed_versions = vec![];
    let report = AuditReport {
        matches: vec![no_fix],
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
        matches: vec![vuln_match(
            "openssl",
            "CVE-2026-0001",
            SeverityRating::Critical,
        )],
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
        matches: vec![vuln_match(
            "openssl",
            "CVE-2026-0001",
            SeverityRating::Critical,
        )],
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
fn ignored_and_not_audited_sections_render() {
    let report = AuditReport {
        ignored: vec![vuln_match("openssl", "CVE-2026-0001", SeverityRating::High)],
        not_audited: vec![AuditPackage {
            name: PackageName::conda("samtools").unwrap(),
            version: Some("1.19".to_string()),
            ecosystem: PackageEcosystem::Other("bioconda".to_string()),
            environments: vec!["default".to_string()],
        }],
        summary: AuditSummary {
            audited: 3,
            vulnerable: 0,
            ignored: 1,
            not_audited: 1,
        },
        ..Default::default()
    };
    let text = render_human(&report, RenderOptions::default());
    assert!(
        text.starts_with("1 package(s) could not be audited:"),
        "{text}"
    );
    assert!(text.contains("Ignored 1 vulnerability match(es):"));
    assert!(text.contains("  CVE-2026-0001 (openssl 3.1.0)"));
    assert!(text.contains("1 package(s) could not be audited:"));
    assert!(text.contains("  samtools 1.19 (bioconda) — default"));
    assert!(text.contains("No vulnerabilities found (3 audited, 1 ignored, 1 not audited)"));
    assert!(text.contains("No active vulnerabilities were found in audited packages."));
    assert!(text.contains("Review 1 ignored vulnerability match periodically."));
    assert!(text.contains(
        "Review 1 package that was not audited. Its source is not covered by the configured vulnerability databases."
    ));
}

#[test]
fn until_fixed_ignores_are_marked() {
    let mut permanent = vuln_match("openssl", "CVE-2026-0001", SeverityRating::High);
    permanent.ignore_mode = Some(pixi_audit::IgnoreMode::Permanent);
    let mut until = vuln_match("openssl", "CVE-2026-0002", SeverityRating::High);
    until.ignore_mode = Some(pixi_audit::IgnoreMode::UntilFixed);
    let report = AuditReport {
        ignored: vec![permanent, until],
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
fn not_audited_package_without_version_renders_question_mark() {
    let report = AuditReport {
        not_audited: vec![AuditPackage {
            name: PackageName::conda("mypkg").unwrap(),
            version: None,
            ecosystem: PackageEcosystem::Other("unknown".to_string()),
            environments: vec!["default".to_string()],
        }],
        summary: AuditSummary {
            not_audited: 1,
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
    let mut unbounded = vuln_match("libpq", "CVE-2022-25852", SeverityRating::High);
    unbounded.fixed_versions = vec![];
    unbounded.match_confidence = MatchConfidence::VersionUnbounded;
    let mut unevaluated = vuln_match("libpq", "CVE-2026-0009", SeverityRating::Medium);
    unevaluated.match_confidence = MatchConfidence::Unevaluated;
    let mut evaluated = vuln_match("libpq", "CVE-2026-0010", SeverityRating::Low);
    evaluated.match_confidence = MatchConfidence::Evaluated;
    let report = AuditReport {
        matches: vec![unbounded, unevaluated, evaluated],
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
            "CVE-2022-25852  HIGH      no known fixed version  confidence: no version limits\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "CVE-2026-0009  MEDIUM    fixed in: 3.1.4  confidence: version not checked\n"
        ),
        "{text}"
    );
}
