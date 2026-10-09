use clap::CommandFactory;

use super::*;

#[test]
fn cli_definition_is_valid() {
    Cli::command().debug_assert();
}

#[test]
fn lock_file_is_now_optional() {
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
    assert_eq!(cli.lock_file, Some(PathBuf::from("pixi.lock")));
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
        "--fail-on",
        "high",
        "--fix",
    ])
    .unwrap();
    assert_eq!(cli.ignore_until_fixed, vec!["CVE-1"]);
    assert_eq!(cli.fail_on, Some(SeverityRating::High));
    assert!(cli.fix);
    assert_eq!(cli.sort_by, Column::Risk);
    assert_eq!(cli.columns, DEFAULT_COLUMNS.to_vec());
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
        "--columns",
        "vulnerability,risk,kev",
    ])
    .unwrap();
    assert_eq!(cli.sort_by, Column::Epss);
    assert_eq!(
        cli.columns,
        vec![Column::Vulnerability, Column::Risk, Column::Kev]
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
        "--expired-at",
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
    assert_eq!(args.expired_at, Some(jiff::civil::date(2099, 1, 1)));

    assert!(Cli::try_parse_from(["pixi-audit", "ignore"]).is_err());
    assert!(
        Cli::try_parse_from(["pixi-audit", "ignore", "CVE-1", "--expired-at", "tomorrow"]).is_err()
    );
    // A plain audit still parses without a subcommand.
    assert!(
        Cli::try_parse_from(["pixi-audit", "pixi.lock"])
            .unwrap()
            .command
            .is_none()
    );
}

#[test]
fn invalid_fail_on_is_rejected_at_parse_time() {
    assert!(Cli::try_parse_from(["pixi-audit", "pixi.lock", "--fail-on", "severe"]).is_err());
}

#[test]
fn exit_status_applies_threshold_with_unknown_failsafe() {
    let vuln_match = |severity| pixi_audit::Match {
        package: pixi_audit::PackageId {
            name: pixi_audit::PackageName::conda("p").unwrap(),
            version: "1".into(),
            ecosystem: pixi_audit::PackageEcosystem::CondaForge,
        },
        environments: vec![],
        id: "X".into(),
        aliases: vec![],
        severity,
        fixed_versions: vec![],
        other_ecosystem_fixes: vec![],
        upstream_releases: vec![],
        match_confidence: pixi_audit::MatchConfidence::Unspecified,
        matched_identity: None,
        summary: None,
        url: None,
        cvss_base_score: None,
        epss: vec![],
        kev: vec![],
        risk: pixi_audit::RiskScore::NONE,
        ignore_mode: None,
    };
    let report = |severity| AuditReport {
        matches: vec![vuln_match(severity)],
        summary: pixi_audit::AuditSummary {
            vulnerable: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    // No threshold: any vulnerability fails.
    assert_eq!(
        exit_status(&report(SeverityRating::Low), None, &[]),
        ExitStatus::Fail
    );
    // Threshold high: medium passes with a note, high and critical fail.
    assert_eq!(
        exit_status(
            &report(SeverityRating::Medium),
            Some(SeverityRating::High),
            &[]
        ),
        ExitStatus::BelowThreshold {
            rating: SeverityRating::High,
            count: 1
        }
    );
    assert_eq!(
        exit_status(
            &report(SeverityRating::High),
            Some(SeverityRating::High),
            &[]
        ),
        ExitStatus::Fail
    );
    assert_eq!(
        exit_status(
            &report(SeverityRating::Critical),
            Some(SeverityRating::High),
            &[]
        ),
        ExitStatus::Fail
    );
    // Unknown always fails, even against critical.
    assert_eq!(
        exit_status(
            &report(SeverityRating::Unknown),
            Some(SeverityRating::Critical),
            &[]
        ),
        ExitStatus::Fail
    );
    // Clean report never fails.
    assert_eq!(
        exit_status(&AuditReport::default(), Some(SeverityRating::Low), &[]),
        ExitStatus::Clean
    );
    assert_eq!(
        exit_status(&AuditReport::default(), None, &[]),
        ExitStatus::Clean
    );
}

#[test]
fn warn_only_conda_keeps_pypi_blocking() {
    let cli = Cli::try_parse_from(["pixi-audit", "--warn-only-ecosystem", "conda-forge"]).unwrap();
    assert_eq!(cli.warn_only_ecosystem, [WarnOnlyEcosystem::CondaForge]);

    let mut conda = AuditReport::default();
    conda.matches.push(pixi_audit::Match {
        package: pixi_audit::PackageId {
            name: pixi_audit::PackageName::conda("openssl").unwrap(),
            version: "3.1.0".into(),
            ecosystem: pixi_audit::PackageEcosystem::CondaForge,
        },
        environments: vec![],
        id: "CVE-1".into(),
        aliases: vec![],
        severity: SeverityRating::Critical,
        fixed_versions: vec![],
        other_ecosystem_fixes: vec![],
        upstream_releases: vec![],
        match_confidence: pixi_audit::MatchConfidence::VersionUnbounded,
        matched_identity: None,
        summary: None,
        url: None,
        cvss_base_score: None,
        epss: vec![],
        kev: vec![],
        risk: pixi_audit::RiskScore::NONE,
        ignore_mode: None,
    });
    assert_eq!(
        exit_status(&conda, None, &cli.warn_only_ecosystem),
        ExitStatus::Clean
    );
    assert_eq!(exit_status(&conda, None, &[]), ExitStatus::Fail);
    let mut pypi = conda.matches[0].clone();
    pypi.package.name = pixi_audit::PackageName::pypi("openssl").unwrap();
    pypi.package.ecosystem = pixi_audit::PackageEcosystem::Pypi;
    conda.matches.push(pypi);
    assert_eq!(
        exit_status(&conda, None, &cli.warn_only_ecosystem),
        ExitStatus::Fail
    );
    let both = Cli::try_parse_from([
        "pixi-audit",
        "--warn-only-ecosystem",
        "conda-forge",
        "--warn-only-ecosystem",
        "pypi",
    ])
    .unwrap();
    assert_eq!(
        exit_status(&conda, None, &both.warn_only_ecosystem),
        ExitStatus::Clean
    );
}
