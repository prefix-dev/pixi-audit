use clap::CommandFactory;

use super::*;

#[test]
fn cli_definition_is_valid() {
    Cli::command().debug_assert();
}

#[test]
fn lockfile_is_now_optional() {
    assert!(Cli::try_parse_from(["pixi-audit"]).is_ok());
}

#[test]
fn repeatable_flags_accumulate() {
    let cli = Cli::try_parse_from([
        "pixi-audit",
        "pixi.lock",
        "--environment",
        "default",
        "--environment",
        "prod",
        "--platform",
        "linux-64",
        "--ignore",
        "CVE-2026-1234",
        "--json",
    ])
    .unwrap();
    assert_eq!(cli.lockfile, Some(PathBuf::from("pixi.lock")));
    assert_eq!(cli.environments, vec!["default", "prod"]);
    assert_eq!(cli.platforms, vec!["linux-64"]);
    assert_eq!(cli.ignore, vec!["CVE-2026-1234"]);
    assert!(cli.json);
}

#[test]
fn new_flags_parse() {
    let cli = Cli::try_parse_from([
        "pixi-audit",
        "pixi.lock",
        "--ignore-until-fixed",
        "CVE-1",
        "--severity",
        "high",
        "--fix",
    ])
    .unwrap();
    assert_eq!(cli.ignore_until_fixed, vec!["CVE-1"]);
    assert_eq!(cli.severity, Some(SeverityBand::High));
    assert!(cli.fix);
}

#[test]
fn invalid_severity_is_rejected_at_parse_time() {
    assert!(Cli::try_parse_from(["pixi-audit", "pixi.lock", "--severity", "severe"]).is_err());
}

#[test]
fn gate_applies_threshold_with_unknown_failsafe() {
    let finding = |severity| pixi_audit::Finding {
        package: pixi_audit::PackageName::conda("p").unwrap(),
        version: "1".into(),
        ecosystem: pixi_audit::PackageEcosystem::CondaForge,
        environments: vec![],
        id: "X".into(),
        aliases: vec![],
        severity,
        fixed_versions: vec![],
        upstream_fixes: vec![],
        applicability: pixi_audit::MatchApplicability::Unspecified,
        matched_identity: None,
        summary: None,
        url: None,
        ignore_reason: None,
    };
    let report = |severity| AuditReport {
        vulnerabilities: vec![finding(severity)],
        summary: pixi_audit::AuditSummary {
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    // No threshold: any vulnerability fails.
    assert_eq!(gate(&report(SeverityBand::Low), None), Gate::Fail);
    // Threshold high: medium passes with a note, high and critical fail.
    assert_eq!(
        gate(&report(SeverityBand::Medium), Some(SeverityBand::High)),
        Gate::BelowThreshold {
            band: SeverityBand::High,
            count: 1
        }
    );
    assert_eq!(
        gate(&report(SeverityBand::High), Some(SeverityBand::High)),
        Gate::Fail
    );
    assert_eq!(
        gate(&report(SeverityBand::Critical), Some(SeverityBand::High)),
        Gate::Fail
    );
    // Unknown always fails, even against critical.
    assert_eq!(
        gate(&report(SeverityBand::Unknown), Some(SeverityBand::Critical)),
        Gate::Fail
    );
    // Clean report never fails.
    assert_eq!(
        gate(&AuditReport::default(), Some(SeverityBand::Low)),
        Gate::Clean
    );
    assert_eq!(gate(&AuditReport::default(), None), Gate::Clean);
}
