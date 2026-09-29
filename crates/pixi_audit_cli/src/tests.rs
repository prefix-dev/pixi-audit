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
    assert_eq!(cli.sort_by, Field::Risk);
    assert_eq!(cli.fields, DEFAULT_FIELDS.to_vec());
    assert!(!cli.ignore_unfixed);
    assert!(
        Cli::try_parse_from(["pixi-audit", "--ignore-unfixed"])
            .unwrap()
            .ignore_unfixed
    );
}

#[test]
fn threat_fields_are_selectable() {
    let cli = Cli::try_parse_from([
        "pixi-audit",
        "--sort-by",
        "epss",
        "--fields",
        "vulnerability,risk,kev",
    ])
    .unwrap();
    assert_eq!(cli.sort_by, Field::Epss);
    assert_eq!(
        cli.fields,
        vec![Field::Vulnerability, Field::Risk, Field::Kev]
    );
}

#[test]
fn ignore_subcommand_parses() {
    let cli = Cli::try_parse_from([
        "pixi-audit",
        "ignore",
        "CVE-1",
        "cve-2",
        "--until-fixed",
        "--reason",
        "why",
        "--until",
        "2099-01-01",
    ])
    .unwrap();
    assert!(matches!(cli.command, Some(Command::Ignore(_))));
    let Some(Command::Ignore(args)) = cli.command else {
        return;
    };
    assert_eq!(args.ids, ["CVE-1", "cve-2"]);
    assert!(args.until_fixed);
    assert_eq!(args.reason.as_deref(), Some("why"));
    assert_eq!(args.until, Some(jiff::civil::date(2099, 1, 1)));

    assert!(Cli::try_parse_from(["pixi-audit", "ignore"]).is_err());
    assert!(Cli::try_parse_from(["pixi-audit", "ignore", "CVE-1", "--until", "tomorrow"]).is_err());
    // A plain audit still parses without a subcommand.
    assert!(
        Cli::try_parse_from(["pixi-audit", "pixi.lock"])
            .unwrap()
            .command
            .is_none()
    );
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
        cvss_base_score: None,
        epss: vec![],
        known_exploited: vec![],
        risk: pixi_audit::RiskScore::NONE,
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
    assert_eq!(gate(&report(SeverityBand::Low), None, &[]), Gate::Fail);
    // Threshold high: medium passes with a note, high and critical fail.
    assert_eq!(
        gate(&report(SeverityBand::Medium), Some(SeverityBand::High), &[]),
        Gate::BelowThreshold {
            band: SeverityBand::High,
            count: 1
        }
    );
    assert_eq!(
        gate(&report(SeverityBand::High), Some(SeverityBand::High), &[]),
        Gate::Fail
    );
    assert_eq!(
        gate(
            &report(SeverityBand::Critical),
            Some(SeverityBand::High),
            &[]
        ),
        Gate::Fail
    );
    // Unknown always fails, even against critical.
    assert_eq!(
        gate(
            &report(SeverityBand::Unknown),
            Some(SeverityBand::Critical),
            &[]
        ),
        Gate::Fail
    );
    // Clean report never fails.
    assert_eq!(
        gate(&AuditReport::default(), Some(SeverityBand::Low), &[]),
        Gate::Clean
    );
    assert_eq!(gate(&AuditReport::default(), None, &[]), Gate::Clean);
}

#[test]
fn warn_only_conda_keeps_pypi_blocking() {
    let cli = Cli::try_parse_from(["pixi-audit", "--warn-only", "conda-forge"]).unwrap();
    assert_eq!(cli.warn_only, [WarnOnlyEcosystem::CondaForge]);

    let mut conda = AuditReport::default();
    conda.vulnerabilities.push(pixi_audit::Finding {
        package: pixi_audit::PackageName::conda("openssl").unwrap(),
        version: "3.1.0".into(),
        ecosystem: pixi_audit::PackageEcosystem::CondaForge,
        environments: vec![],
        id: "CVE-1".into(),
        aliases: vec![],
        severity: SeverityBand::Critical,
        fixed_versions: vec![],
        upstream_fixes: vec![],
        applicability: pixi_audit::MatchApplicability::VersionUnbounded,
        matched_identity: None,
        summary: None,
        url: None,
        cvss_base_score: None,
        epss: vec![],
        known_exploited: vec![],
        risk: pixi_audit::RiskScore::NONE,
        ignore_reason: None,
    });
    assert_eq!(gate(&conda, None, &cli.warn_only), Gate::Clean);
    assert_eq!(gate(&conda, None, &[]), Gate::Fail);
    let mut pypi = conda.vulnerabilities[0].clone();
    pypi.package = pixi_audit::PackageName::pypi("openssl").unwrap();
    pypi.ecosystem = pixi_audit::PackageEcosystem::Pypi;
    conda.vulnerabilities.push(pypi);
    assert_eq!(gate(&conda, None, &cli.warn_only), Gate::Fail);
    let both = Cli::try_parse_from([
        "pixi-audit",
        "--warn-only",
        "conda-forge",
        "--warn-only",
        "pypi",
    ])
    .unwrap();
    assert_eq!(gate(&conda, None, &both.warn_only), Gate::Clean);
}
