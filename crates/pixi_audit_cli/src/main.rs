use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use miette::{Context, IntoDiagnostic};
use pixi_audit::{
    AuditReport, BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL, SeverityBand, audit_lock_file,
};

mod config;
mod render;

const EXIT_VULNERABLE: u8 = 1;
const EXIT_ERROR: u8 = 2;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Audit a pixi.lock file for known vulnerabilities.
///
/// Exit codes: 0 = no vulnerabilities, 1 = vulnerabilities found,
/// 2 = execution error.
#[derive(Debug, Parser)]
#[command(name = "pixi-audit", version)]
struct Cli {
    /// Path to the pixi.lock file to audit. When omitted, searches the
    /// current directory and its parents for a pixi workspace.
    lockfile: Option<PathBuf>,

    /// Audit only this environment (repeatable)
    #[arg(long = "environment", value_name = "ENV")]
    environments: Vec<String>,

    /// Audit only this platform (repeatable)
    #[arg(long = "platform", value_name = "PLATFORM")]
    platforms: Vec<String>,

    /// Vulnerability id or alias to ignore, case-insensitive (repeatable).
    /// Ignored findings still appear in the report's ignored section.
    #[arg(long = "ignore", value_name = "ID")]
    ignore: Vec<String>,

    /// Vulnerability id or alias to ignore only while no fixed release is
    /// known (repeatable, case-insensitive). Resurfaces once a fix exists.
    #[arg(long = "ignore-until-fixed", value_name = "ID")]
    ignore_until_fixed: Vec<String>,

    /// Fail (exit 1) only for findings at or above this severity band.
    /// Findings with unknown severity always fail. Overrides the config
    /// file's `severity`.
    #[arg(long, value_name = "BAND", value_parser = config::parse_band)]
    severity: Option<SeverityBand>,

    /// Re-lock vulnerable packages via `pixi update`, then re-audit
    #[arg(long)]
    fix: bool,

    /// Emit the report as pretty-printed JSON on stdout
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match run(cli).await {
        Ok(RunOutcome { report, threshold }) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("report serializes")
                );
            } else {
                print!("{}", render::render_human(&report));
            }
            if gate_exit(&report, threshold) {
                eprintln!("error: audit found vulnerabilities");
                ExitCode::from(EXIT_VULNERABLE)
            } else {
                if report.summary.vulnerable > 0 {
                    let band = threshold.expect("vulnerabilities below a threshold imply one");
                    eprintln!(
                        "note: {} vulnerabilities found below the '{band}' severity threshold",
                        report.summary.vulnerable
                    );
                }
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("{error:?}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

/// The lockfile to audit and the workspace manifest that governs it.
struct ResolvedTargets {
    lockfile: PathBuf,
    /// `None` when an explicit lockfile has no manifest beside it.
    manifest: Option<PathBuf>,
}

/// An explicit lockfile is used as-is (manifest = its sibling, if any).
/// Otherwise the workspace is discovered by walking up from the cwd.
fn resolve_targets(cli_lockfile: Option<PathBuf>) -> miette::Result<ResolvedTargets> {
    match cli_lockfile {
        Some(lockfile) => {
            let manifest = lockfile
                .canonicalize()
                .ok()
                .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
                .and_then(|dir| config::find_manifest_in(&dir));
            Ok(ResolvedTargets { lockfile, manifest })
        }
        None => {
            let cwd = std::env::current_dir()
                .into_diagnostic()
                .wrap_err("cannot determine the current directory")?;
            let manifest = config::discover_workspace(&cwd).ok_or_else(|| {
                miette::miette!(
                    "no pixi workspace found; pass a lockfile path or run inside a pixi workspace"
                )
            })?;
            let root = manifest.parent().expect("manifest has a directory");
            let lockfile = root.join("pixi.lock");
            if !lockfile.is_file() {
                return Err(miette::miette!(
                    "workspace at '{}' has no pixi.lock; run `pixi lock` first",
                    root.display()
                ));
            }
            Ok(ResolvedTargets {
                lockfile,
                manifest: Some(manifest),
            })
        }
    }
}

/// Whether the report should fail the audit (exit 1) under `threshold`.
/// Unknown severity always fails: an unscored advisory must not slip
/// under a threshold.
fn gate_exit(report: &AuditReport, threshold: Option<SeverityBand>) -> bool {
    report
        .vulnerabilities
        .iter()
        .any(|finding| match threshold {
            None => true,
            Some(band) => finding.severity == SeverityBand::Unknown || finding.severity >= band,
        })
}

struct RunOutcome {
    report: AuditReport,
    threshold: Option<SeverityBand>,
}

async fn run(cli: Cli) -> miette::Result<RunOutcome> {
    let targets = resolve_targets(cli.lockfile.clone())?;
    let config = match &targets.manifest {
        Some(manifest) => config::load_config(manifest)?,
        None => config::AuditConfig::default(),
    };

    // Union config + CLI ignore lists; CLI severity overrides config.
    let mut ignore = config.ignore;
    ignore.extend(cli.ignore.iter().cloned());
    let mut ignore_until_fixed = config.ignore_until_fixed;
    ignore_until_fixed.extend(cli.ignore_until_fixed.iter().cloned());
    let threshold = cli.severity.or(config.severity);

    let lock_file = pixi_audit::rattler_lock::LockFile::from_path(&targets.lockfile)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read lock file '{}'", targets.lockfile.display()))?;

    let base_url = std::env::var(BASE_URL_ENV_VAR).unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
    let base_url = url::Url::parse(&base_url)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {BASE_URL_ENV_VAR} value '{base_url}'"))?;

    eprintln!(
        "Auditing {} against {base_url} ...",
        targets.lockfile.display()
    );

    let http_client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .into_diagnostic()
        .wrap_err("failed to construct the HTTP client")?;
    let http = reqwest_middleware::ClientBuilder::new(http_client).build();
    let client = BasiliskClient::new(http, base_url);

    let ignore_spec = pixi_audit::IgnoreSpec {
        ignore: &ignore,
        ignore_until_fixed: &ignore_until_fixed,
    };
    let report = audit_lock_file(
        &client,
        &lock_file,
        &cli.environments,
        &cli.platforms,
        ignore_spec,
    )
    .await
    .map_err(miette::Report::new)?;

    Ok(RunOutcome { report, threshold })
}

#[cfg(test)]
mod tests {
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
            ecosystem: "conda-forge".into(),
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
}
