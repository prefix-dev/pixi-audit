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
fn gate_exit_applies_threshold_with_unknown_failsafe() {
    let finding = |severity| pixi_audit::Finding {
        package: "p".into(),
        version: "1".into(),
        ecosystem: pixi_audit::PackageEcosystem::CondaForge,
        environments: vec![],
        id: "X".into(),
        aliases: vec![],
        severity,
        fixed_versions: vec![],
        upstream_fixed_versions: vec![],
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
    assert!(gate_exit(&report(SeverityBand::Low), None));
    // Threshold high: medium passes, high and critical fail.
    assert!(!gate_exit(
        &report(SeverityBand::Medium),
        Some(SeverityBand::High)
    ));
    assert!(gate_exit(
        &report(SeverityBand::High),
        Some(SeverityBand::High)
    ));
    assert!(gate_exit(
        &report(SeverityBand::Critical),
        Some(SeverityBand::High)
    ));
    // Unknown always fails, even against critical.
    assert!(gate_exit(
        &report(SeverityBand::Unknown),
        Some(SeverityBand::Critical)
    ));
    // Clean report never fails.
    assert!(!gate_exit(&AuditReport::default(), Some(SeverityBand::Low)));
    assert!(!gate_exit(&AuditReport::default(), None));
}
