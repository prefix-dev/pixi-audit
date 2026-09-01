use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use miette::{Context, IntoDiagnostic};
use pixi_audit::{
    AuditReport, BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL, DEFAULT_PYPI_BASE_URL,
    PYPI_BASE_URL_ENV_VAR, PypiAuditClient, SeverityBand, audit_lock_file,
};

mod config;
mod fix;
mod render;
mod workspace;

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

    /// Fail (exit 1) only for conda findings at or above this severity band.
    /// Severity filtering does not apply to PyPI findings. Overrides the
    /// config file's `severity`.
    #[arg(long, value_name = "BAND", value_parser = config::parse_band)]
    severity: Option<SeverityBand>,

    /// Raise direct dependency constraints to known fixed versions, run
    /// `pixi update`, then re-audit
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
    let targets = workspace::resolve_targets(cli.lockfile.clone())?;
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
    let pypi_base_url =
        std::env::var(PYPI_BASE_URL_ENV_VAR).unwrap_or_else(|_| DEFAULT_PYPI_BASE_URL.to_string());
    let pypi_base_url = url::Url::parse(&pypi_base_url)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {PYPI_BASE_URL_ENV_VAR} value '{pypi_base_url}'"))?;

    eprintln!(
        "Auditing {} against {base_url} and {pypi_base_url} ...",
        targets.lockfile.display()
    );

    let http_client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .into_diagnostic()
        .wrap_err("failed to construct the HTTP client")?;
    let http = reqwest_middleware::ClientBuilder::new(http_client).build();
    let client = BasiliskClient::new(http, base_url);
    let pypi_client = PypiAuditClient::new(pypi_base_url).map_err(miette::Report::new)?;

    let ignore_spec = pixi_audit::IgnoreSpec {
        ignore: &ignore,
        ignore_until_fixed: &ignore_until_fixed,
    };
    let report = audit_lock_file(
        &client,
        &pypi_client,
        &lock_file,
        &cli.environments,
        &cli.platforms,
        ignore_spec,
    )
    .await
    .map_err(miette::Report::new)?;

    if !cli.fix {
        return Ok(RunOutcome { report, threshold });
    }

    let names = fix::vulnerable_package_names(&report);
    if names.is_empty() {
        return Ok(RunOutcome { report, threshold });
    }
    let manifest = targets.manifest.as_deref().ok_or_else(|| {
        miette::miette!(
            "--fix requires a pixi workspace (no pixi.toml/pyproject.toml next to '{}')",
            targets.lockfile.display()
        )
    })?;
    let bumped = fix::bump_manifest_constraints(manifest, &report)?;
    if bumped > 0 {
        eprintln!(
            "fixed: raised {bumped} manifest constraint{} to known fixed versions",
            if bumped == 1 { "" } else { "s" }
        );
    }
    fix::run_pixi_update(manifest, &names)?;

    let lock_file = pixi_audit::rattler_lock::LockFile::from_path(&targets.lockfile)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to re-read lock file '{}' after pixi update",
                targets.lockfile.display()
            )
        })?;
    let after = audit_lock_file(
        &client,
        &pypi_client,
        &lock_file,
        &cli.environments,
        &cli.platforms,
        ignore_spec,
    )
    .await
    .map_err(miette::Report::new)?;

    let before_count = report.summary.vulnerable;
    let resolved = before_count.saturating_sub(after.summary.vulnerable);
    eprintln!("fixed: resolved {resolved} of {before_count} vulnerabilities via pixi update");

    Ok(RunOutcome {
        report: after,
        threshold,
    })
}

#[cfg(test)]
mod tests;
