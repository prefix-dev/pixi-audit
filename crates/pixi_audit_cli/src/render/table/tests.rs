use pixi_audit::{
    AuditReport, AuditSummary, EpssScore, Finding, IgnoreReason, KnownExploited,
    MatchApplicability, PackageEcosystem, PackageName, RansomwareCampaignUse, RiskScore,
    SeverityBand, UncheckedPackage, UpstreamFix, UpstreamOrigin,
};

use super::{Field, TableLayout, render_table, render_table_after_fix, render_table_explained};

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

fn pypi_finding(id: &str) -> Finding {
    Finding {
        package: PackageName::pypi("requests").unwrap(),
        version: "2.32.0".to_string(),
        ecosystem: PackageEcosystem::Pypi,
        environments: vec!["default".to_string()],
        id: id.to_string(),
        aliases: vec!["CVE-2026-9".to_string()],
        severity: SeverityBand::Unknown,
        cvss_base_score: None,
        fixed_versions: vec![],
        upstream_fixes: vec![],
        applicability: MatchApplicability::Unspecified,
        matched_identity: None,
        summary: Some("Leaks credentials".to_string()),
        url: None,
        epss: vec![],
        known_exploited: vec![],
        risk: RiskScore::NONE,
        ignore_reason: None,
    }
}

/// Attaches an EPSS record and, optionally, a KEV entry, and recomputes
/// the risk score.
fn with_threat_data(mut finding: Finding, epss: f64, percentile: f64, kev: bool) -> Finding {
    finding.epss = vec![EpssScore {
        cve: finding.id.clone(),
        epss,
        percentile,
        date: "2026-09-01".to_string(),
    }];
    if kev {
        finding.known_exploited = vec![KnownExploited {
            cve: finding.id.clone(),
            vendor_project: "OpenSSL".to_string(),
            product: "OpenSSL".to_string(),
            vulnerability_name: "OpenSSL overflow".to_string(),
            date_added: "2026-08-01".to_string(),
            required_action: "Apply updates".to_string(),
            due_date: "2026-08-22".to_string(),
            known_ransomware_campaign_use: RansomwareCampaignUse::Unknown,
            notes: String::new(),
        }];
    }
    finding.risk = RiskScore::compute(
        finding.severity,
        finding.cvss_base_score,
        &finding.epss,
        &finding.known_exploited,
    );
    finding
}

/// Row cells of every line mentioning one of `ids`, whitespace-split.
fn rows<'a>(text: &'a str, ids: &[&str]) -> Vec<Vec<&'a str>> {
    text.lines()
        .filter(|line| ids.iter().any(|id| line.contains(id)))
        .map(|line| line.split_whitespace().collect())
        .collect()
}

#[test]
fn threat_columns_show_scores_and_flag_kev_rows() {
    let listed = with_threat_data(
        finding("openssl", "CVE-2026-0001", SeverityBand::Critical),
        0.5,
        0.9,
        true,
    );
    let faint = with_threat_data(pypi_finding("GHSA-1"), 0.0004, 0.112, false);
    let report = AuditReport {
        vulnerabilities: vec![
            faint,
            finding("openssl", "CVE-2026-0002", SeverityBand::Medium),
            listed,
        ],
        summary: AuditSummary {
            audited: 3,
            vulnerable: 3,
            ..Default::default()
        },
        ..Default::default()
    };
    let layout = TableLayout {
        fields: vec![Field::Vulnerability, Field::Epss, Field::Risk, Field::Kev],
        ..TableLayout::default()
    };
    let text = render_table(&report, "pixi.lock", &layout);
    // The default order is by risk: critical + KEV (9.0 / 10 * 1.05),
    // then the faint PyPI one (5.0 / 10 * 0.0004), then the unscored one.
    // The listed row carries the marker on its risk cell and in the KEV
    // column.
    assert_eq!(
        rows(&text, &["CVE-2026-000", "GHSA-1"]),
        [
            vec![
                "CVE-2026-0001",
                "90th",
                "·",
                "50.0%",
                "94.5",
                "(kev)",
                "kev"
            ],
            vec!["GHSA-1", "11th", "·", "<", "0.1%", "<", "0.1"],
            vec!["CVE-2026-0002"],
        ]
    );
}

#[test]
fn sort_by_epss_and_kev_put_the_scored_rows_first() {
    let mut scored = with_threat_data(
        finding("openssl", "CVE-2026-0001", SeverityBand::Low),
        0.3,
        0.95,
        false,
    );
    scored.epss.insert(
        0,
        EpssScore {
            cve: "CVE-2026-0000".to_string(),
            epss: 0.001,
            percentile: 0.1,
            date: "2026-09-01".to_string(),
        },
    );
    let listed = with_threat_data(
        finding("openssl", "CVE-2026-0002", SeverityBand::Low),
        0.01,
        0.5,
        true,
    );
    let report = AuditReport {
        vulnerabilities: vec![
            finding("openssl", "CVE-2026-0003", SeverityBand::Critical),
            listed,
            scored,
        ],
        summary: AuditSummary {
            audited: 3,
            vulnerable: 3,
            ..Default::default()
        },
        ..Default::default()
    };
    let ids = |sort_by: Field| -> Vec<String> {
        let layout = TableLayout {
            fields: vec![Field::Vulnerability],
            sort_by,
        };
        rows(
            &render_table(&report, "pixi.lock", &layout),
            &["CVE-2026-000"],
        )
        .into_iter()
        .map(|cells| cells[0].to_string())
        .collect()
    };
    assert_eq!(
        ids(Field::Epss),
        ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
    );
    // KEV first; the rest by risk, and the unscored critical one last.
    assert_eq!(
        ids(Field::Kev),
        ["CVE-2026-0002", "CVE-2026-0001", "CVE-2026-0003"]
    );
    // Severity leads, then risk breaks the tie between the two lows.
    assert_eq!(
        ids(Field::Severity),
        ["CVE-2026-0003", "CVE-2026-0002", "CVE-2026-0001"]
    );
}

fn full_report() -> AuditReport {
    let mut second = finding("openssl", "CVE-2026-0002", SeverityBand::Medium);
    second.fixed_versions = vec![];
    second.upstream_fixes = vec![UpstreamFix {
        version: "3.2.0".to_string(),
        origin: UpstreamOrigin::Ecosystem {
            ecosystem: "PyPI".to_string(),
        },
    }];
    second.url = None;
    let mut ignored = finding("libxml2", "CVE-2026-0003", SeverityBand::Low);
    ignored.ignore_reason = Some(IgnoreReason::UntilFixed);
    AuditReport {
        vulnerabilities: vec![
            finding("openssl", "CVE-2026-0001", SeverityBand::Critical),
            second,
            pypi_finding("GHSA-1"),
        ],
        ignored: vec![ignored],
        unchecked: vec![UncheckedPackage {
            package: PackageName::conda("samtools").unwrap(),
            version: Some("1.2".to_string()),
            ecosystem: PackageEcosystem::Other("bioconda".to_string()),
            environments: vec!["default".to_string()],
        }],
        summary: AuditSummary {
            audited: 10,
            vulnerable: 3,
            ignored: 1,
            unchecked: 1,
        },
        unmatched_ignores: vec![],
        threat_data: Default::default(),
    }
}

#[test]
fn clean_report() {
    let report = AuditReport {
        summary: AuditSummary {
            audited: 5,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = render_table(&report, "pixi.lock", &TableLayout::default());
    assert_eq!(
        text,
        " ✔ Audited pixi.lock                 [5 packages audited]
 ✔ Scanned for vulnerabilities       [no vulnerability matches]
   ├── by severity: 0 critical, 0 high, 0 medium, 0 low, 0 unknown
   └── by status:   0 fixed, 0 not-fixed, 0 ignored

 ✔ No vulnerabilities found (5 audited, 0 ignored, 0 unchecked)

 Next steps
   • None. No vulnerabilities were found in checked packages.

 Add `--explain` for scoring and report definitions.
"
    );
}

#[test]
fn explained_table_keeps_actions_before_contextual_definitions() {
    let text = render_table_explained(&full_report(), "pixi.lock", &TableLayout::default());
    let actions = text.find("Next steps").unwrap();
    let explanation = text.find("How this report works").unwrap();
    assert!(actions < explanation, "{text}");
    assert!(
        text.contains(
            "How this report works\n\n   Counts\n     Package  One locked name, version, and source.\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "\n     Risk      A 0–100 score for ordering individual findings.\n       Formula   min(threat × severity × boost, 1) × 100.\n     Threat"
        ),
        "{text}"
    );
    for expected in [
        "A 0–100 score for ordering individual findings.",
        "A fixed release exists for the audited package source.",
        "Fix only upstream",
        "Audit sources list no fixed release.",
        "Excluded from active totals and the failure decision.",
        "The package source lacks vulnerability database coverage.",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }
    let compact = render_table(&full_report(), "pixi.lock", &TableLayout::default());
    assert!(!compact.contains("How this report works"));
    assert!(compact.contains("Add `--explain` for scoring and report definitions."));
}

#[test]
fn default_layout_sorts_by_severity_and_marks_kind_like_pixi_lock() {
    let text = render_table(&full_report(), "pixi.lock", &TableLayout::default());
    assert_eq!(
        text,
        " Unchecked (1) — no vulnerability database for these sources

          Name      Version  Source    Environments
 (conda)  samtools  1.2      bioconda  default

 ✔ Audited pixi.lock                 [10 packages audited, 1 unchecked]
 ✔ Scanned for vulnerabilities       [3 vulnerability matches]
   ├── by severity: 1 critical, 0 high, 1 medium, 0 low, 1 unknown
   └── by status:   1 fixed, 2 not-fixed, 1 ignored

          Name      Version  Fixed in     Vulnerability  Severity  EPSS  Risk  Environments
 (conda)  openssl   3.1.0    3.1.4        CVE-2026-0001  Critical              default, prod
 (conda)  openssl   3.1.0    PyPI: 3.2.0  CVE-2026-0002  Medium                default, prod
 (pypi)   requests  2.32.0                GHSA-1         Unknown               default

 Ignored (1)

          Name     Version  Fixed in  Vulnerability  Severity  EPSS  Risk  Environments   Ignored
 (conda)  libxml2  3.1.0    3.1.4     CVE-2026-0003  Low                   default, prod  until a fix is released

 ✖ 3 vulnerabilities in 2 package(s) (10 audited, 1 ignored, 1 unchecked)

 Assessment
   • Highest finding prioritization score:  n/a
   • CISA KEV matches:                      n/a — CISA KEV catalog not checked
   • Critical/high findings:                1
   • Fix available in audited ecosystem:    1 of 3 vulnerabilities across 1 audited package
   • Fix only upstream:                     1 vulnerability
   • No known fix:                          1 vulnerability

 Next steps
   • Re-run this audit with `--fix` to ask pixi to update 1 package name. Fixed releases in the audited ecosystem are available for 1 vulnerability.
   • 1 vulnerability has a fix only upstream. `--fix` cannot install it. Wait for an ecosystem build or change dependency source.
   • 1 vulnerability has no known fix. Remove, replace, or mitigate the affected dependencies. Use `pixi audit ignore <ID> --until-fixed` only after accepting the risk.
   • Review 1 unchecked package. Its source is not covered by the configured vulnerability databases.

 Add `--explain` for scoring and report definitions.
"
    );
}

#[test]
fn fields_select_and_order_columns() {
    let layout = TableLayout {
        fields: vec![
            Field::Vulnerability,
            Field::Aliases,
            Field::Summary,
            Field::Name,
        ],
        sort_by: Field::Severity,
    };
    let text = render_table(&full_report(), "pixi.lock", &layout);
    let table: Vec<&str> = text
        .lines()
        .skip_while(|line| !line.contains("Vulnerability"))
        .take(4)
        .collect();
    assert_eq!(
        table,
        [
            " Vulnerability  Aliases     Summary                     Name",
            " CVE-2026-0001                                 (conda)  openssl",
            " CVE-2026-0002                                 (conda)  openssl",
            " GHSA-1         CVE-2026-9  Leaks credentials  (pypi)   requests",
        ]
    );
}

#[test]
fn sort_by_name_keeps_severity_order_within_a_package() {
    let layout = TableLayout {
        fields: vec![Field::Name, Field::Vulnerability, Field::Severity],
        sort_by: Field::Name,
    };
    let text = render_table(&full_report(), "pixi.lock", &layout);
    let ids: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("CVE-2026-000") || line.contains("GHSA"))
        .map(|line| line.split_whitespace().nth(2).unwrap())
        .collect();
    // libxml2 is in the ignored table; openssl rows precede requests.
    assert_eq!(
        ids,
        ["CVE-2026-0001", "CVE-2026-0002", "GHSA-1", "CVE-2026-0003"]
    );
}

#[test]
fn colored_output_uses_single_letter_kind_markers() {
    use iocraft::prelude::{Color, ElementExt};

    use super::{GuidanceOptions, OutputStyle, build};
    let style = OutputStyle {
        color: true,
        hyperlinks: false,
    };
    let canvas = build(
        &full_report(),
        "pixi.lock",
        style,
        &TableLayout::default(),
        GuidanceOptions {
            explain: true,
            ..Default::default()
        },
    )
    .render(None);
    let plain = canvas.to_string();
    let row = plain
        .lines()
        .position(|line| line.contains("Package") && line.contains("One locked"))
        .unwrap();
    let column = plain.lines().nth(row).unwrap().find("Package").unwrap();
    assert_eq!(
        canvas
            .cell(column, row)
            .and_then(|cell| cell.text_style())
            .and_then(|style| style.color),
        Some(Color::AnsiValue(super::EXPLANATION_TERM_PALETTE_INDEX))
    );

    let mut out = Vec::new();
    canvas.write_ansi(&mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    // The marker fills its own padded column before the name.
    assert!(
        text.contains("C  \x1b[0mopenssl") || text.contains("C  \x1b[39mopenssl"),
        "{text}"
    );
    assert!(!text.contains("(conda)"), "{text}");
    let package_definition = text
        .lines()
        .find(|line| line.contains("Package") && line.contains("One locked"))
        .unwrap();
    assert!(
        package_definition.contains("\x1b[1m"),
        "{package_definition:?}"
    );
    // The second openssl row repeats the package, so its marker, name and
    // version are dimmed rather than recolored.
    let dim = "\x1b[2m";
    let openssl_rows: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("openssl"))
        .collect();
    assert_eq!(openssl_rows.len(), 2, "{text}");
    assert!(!openssl_rows[0].contains(dim), "{text}");
    assert!(openssl_rows[1].contains(dim), "{text}");
    // Secondary text is dimmed too, never recolored grey, and the status
    // tree stays dim through its colored counts.
    assert!(
        text.contains("\x1b[2m[10 packages audited, 1 unchecked]"),
        "{text}"
    );
    assert!(!text.contains("\x1b[38;5;8m"), "{text}");
    let status_line = text
        .lines()
        .find(|line| line.contains("by status:"))
        .unwrap();
    assert!(status_line.contains("\x1b[2m"), "{text}");
    assert!(!status_line.contains("\x1b[0m1 fixed"), "{text}");
}

#[test]
fn sort_by_fixed_in_puts_unfixed_last() {
    let layout = TableLayout {
        fields: vec![Field::Vulnerability, Field::FixedIn],
        sort_by: Field::FixedIn,
    };
    let mut report = full_report();
    report.vulnerabilities.reverse();
    let text = render_table(&report, "pixi.lock", &layout);
    let ids: Vec<&str> = text
        .lines()
        .skip_while(|line| !line.contains("Vulnerability"))
        .skip(1)
        .take(3)
        .map(|line| line.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(ids, ["CVE-2026-0001", "GHSA-1", "CVE-2026-0002"]);
}

/// A report with one match of each weak applicability.
fn weak_match_report() -> AuditReport {
    let mut unbounded = finding("libpq", "CVE-2022-25852", SeverityBand::High);
    unbounded.fixed_versions = vec![];
    unbounded.applicability = MatchApplicability::VersionUnbounded;
    let mut unevaluated = finding("libpq", "CVE-2026-0009", SeverityBand::Medium);
    unevaluated.applicability = MatchApplicability::Unevaluated;
    let mut evaluated = finding("pnpm", "CVE-2026-50014", SeverityBand::Low);
    evaluated.applicability = MatchApplicability::Evaluated;
    AuditReport {
        vulnerabilities: vec![unbounded, unevaluated, evaluated, pypi_finding("GHSA-1")],
        summary: AuditSummary {
            audited: 4,
            vulnerable: 4,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn weak_matches_are_flagged_and_counted() {
    let text = render_table(&weak_match_report(), "pixi.lock", &TableLayout::default());
    assert_eq!(
        text,
        " ✔ Audited pixi.lock                 [4 packages audited]
 ✔ Scanned for vulnerabilities       [4 vulnerability matches]
   ├── by severity: 0 critical, 1 high, 1 medium, 1 low, 1 unknown
   └── by status:   2 fixed, 2 not-fixed, 0 ignored, 1 unbounded, 1 unevaluated

          Name      Version  Fixed in  Vulnerability                Severity  EPSS  Risk  Environments
 (conda)  libpq     3.1.0              CVE-2022-25852 (unbounded)   High                  default, prod
 (conda)  libpq     3.1.0    3.1.4     CVE-2026-0009 (unevaluated)  Medium                default, prod
 (conda)  pnpm      3.1.0    3.1.4     CVE-2026-50014               Low                   default, prod
 (pypi)   requests  2.32.0             GHSA-1                       Unknown               default

 ✖ 4 vulnerabilities in 3 package(s) (4 audited, 0 ignored, 0 unchecked)

 Assessment
   • Highest finding prioritization score:  n/a
   • CISA KEV matches:                      n/a — CISA KEV catalog not checked
   • Critical/high findings:                1
   • Fix available in audited ecosystem:    2 of 4 vulnerabilities across 2 audited packages
   • Fix only upstream:                     0 vulnerabilities
   • No known fix:                          2 vulnerabilities

 Next steps
   • Re-run this audit with `--fix` to ask pixi to update 2 package names. Fixed releases in the audited ecosystem are available for 2 vulnerabilities.
   • 2 vulnerabilities have no known fix. Remove, replace, or mitigate the affected dependencies. Use `pixi audit ignore <ID> --until-fixed` only after accepting the risk.

 Add `--explain` for scoring and report definitions.
"
    );
}

#[test]
fn completed_fix_does_not_recommend_another_blind_attempt() {
    let text = render_table_after_fix(&full_report(), "pixi.lock", &TableLayout::default());
    assert!(text.contains(
        "`--fix` completed, but 1 vulnerability with a fix in the audited ecosystem remains. Review dependency constraints and pixi's solver output."
    ));
    assert!(!text.contains("Re-run this audit with `--fix`"));
}

#[test]
fn match_column_replaces_the_marker_and_sorts_by_confidence() {
    let layout = TableLayout {
        fields: vec![Field::Vulnerability, Field::Match],
        sort_by: Field::Match,
    };
    let text = render_table(&weak_match_report(), "pixi.lock", &layout);
    let table: Vec<&str> = text
        .lines()
        .skip_while(|line| !line.contains("Vulnerability"))
        .take(5)
        .collect();
    assert_eq!(
        table,
        [
            " Vulnerability   Match",
            " CVE-2026-50014  evaluated",
            " CVE-2026-0009   unevaluated",
            " CVE-2022-25852  unbounded",
            " GHSA-1",
        ]
    );
}
