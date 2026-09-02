use pixi_audit::{
    AuditReport, AuditSummary, Finding, PackageEcosystem, PackageName, SeverityBand,
    UncheckedPackage,
};

use super::*;

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
        upstream_fixed_versions: vec![],
        summary: None,
        url: Some(format!("https://osv.dev/{id}")),
        ignore_reason: None,
    }
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
        "No vulnerabilities found (5 audited, 0 ignored, 0 unchecked)\n"
    );
}

#[test]
fn findings_are_grouped_per_package_with_fix_and_url() {
    let mut second = finding("openssl", "CVE-2026-0002", SeverityBand::Medium);
    second.fixed_versions = vec![];
    second.upstream_fixed_versions = vec!["3.2.0".to_string()];
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
    assert!(text.contains("CVE-2026-0002  MEDIUM    fix released upstream: 3.2.0"));
    assert!(
        text.contains("2 vulnerabilities in 1 package(s) (10 audited, 0 ignored, 0 unchecked)")
    );
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
    let text = render_human(&report, RenderOptions { hyperlinks: true });
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
    assert!(text.contains("Ignored 1 finding(s):"));
    assert!(text.contains("  CVE-2026-0001 (openssl 3.1.0)"));
    assert!(text.contains("1 package(s) could not be checked:"));
    assert!(text.contains("  samtools 1.19 (bioconda) — default"));
    assert!(text.contains("No vulnerabilities found (3 audited, 1 ignored, 1 unchecked)"));
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
