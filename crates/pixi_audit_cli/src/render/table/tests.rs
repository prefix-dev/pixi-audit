use pixi_audit::{
    AuditReport, AuditSummary, Finding, IgnoreReason, MatchApplicability, PackageEcosystem,
    PackageName, SeverityBand, UncheckedPackage, UpstreamFix, UpstreamOrigin,
};

use super::{Field, TableLayout, render_table};

fn finding(package: &str, id: &str, severity: SeverityBand) -> Finding {
    Finding {
        package: PackageName::conda(package).unwrap(),
        version: "3.1.0".to_string(),
        ecosystem: PackageEcosystem::CondaForge,
        environments: vec!["default".to_string(), "prod".to_string()],
        id: id.to_string(),
        aliases: vec![],
        severity,
        fixed_versions: vec!["3.1.4".to_string()],
        upstream_fixes: vec![],
        applicability: MatchApplicability::Unspecified,
        matched_identity: None,
        summary: None,
        url: Some(format!("https://osv.dev/{id}")),
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
        fixed_versions: vec![],
        upstream_fixes: vec![],
        applicability: MatchApplicability::Unspecified,
        matched_identity: None,
        summary: Some("Leaks credentials".to_string()),
        url: None,
        ignore_reason: None,
    }
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
"
    );
}

#[test]
fn default_layout_sorts_by_severity_and_marks_kind_like_pixi_lock() {
    let text = render_table(&full_report(), "pixi.lock", &TableLayout::default());
    assert_eq!(
        text,
        " ✔ Audited pixi.lock                 [10 packages audited, 1 unchecked]
 ✔ Scanned for vulnerabilities       [3 vulnerability matches]
   ├── by severity: 1 critical, 0 high, 1 medium, 0 low, 1 unknown
   └── by status:   1 fixed, 2 not-fixed, 1 ignored

 Name             Version  Fixed in     Vulnerability  Severity  Environments
 (conda) openssl  3.1.0    3.1.4        CVE-2026-0001  Critical  default, prod
 (conda) openssl  3.1.0    PyPI: 3.2.0  CVE-2026-0002  Medium    default, prod
 (pypi) requests  2.32.0                GHSA-1         Unknown   default

 Ignored (1)

 Name             Version  Fixed in  Vulnerability  Severity  Environments   Ignored
 (conda) libxml2  3.1.0    3.1.4     CVE-2026-0003  Low       default, prod  until a fix is released

 Unchecked (1) — no vulnerability database for these sources

 Name              Version  Source    Environments
 (conda) samtools  1.2      bioconda  default

 ✖ 3 vulnerabilities in 2 package(s) (10 audited, 1 ignored, 1 unchecked)
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
            " Vulnerability  Aliases     Summary            Name",
            " CVE-2026-0001                                 (conda) openssl",
            " CVE-2026-0002                                 (conda) openssl",
            " GHSA-1         CVE-2026-9  Leaks credentials  (pypi) requests",
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
    use iocraft::prelude::ElementExt;

    use super::{OutputStyle, build};
    let style = OutputStyle {
        color: true,
        hyperlinks: false,
    };
    let mut out = Vec::new();
    build(&full_report(), "pixi.lock", style, &TableLayout::default())
        .render(None)
        .write_ansi(&mut out)
        .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("C\x1b[39m openssl") || text.contains("C\x1b[0m openssl"),
        "{text}"
    );
    assert!(!text.contains("(conda)"), "{text}");
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

 Name             Version  Fixed in  Vulnerability                Severity  Environments
 (conda) libpq    3.1.0              CVE-2022-25852 (unbounded)   High      default, prod
 (conda) libpq    3.1.0    3.1.4     CVE-2026-0009 (unevaluated)  Medium    default, prod
 (conda) pnpm     3.1.0    3.1.4     CVE-2026-50014               Low       default, prod
 (pypi) requests  2.32.0             GHSA-1                       Unknown   default

 ✖ 4 vulnerabilities in 3 package(s) (4 audited, 0 ignored, 0 unchecked)
"
    );
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
