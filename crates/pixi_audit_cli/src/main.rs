use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use miette::{Context, IntoDiagnostic};
use pixi_audit::{
    AuditReport, BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL, audit_lock_file,
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
    /// Path to the pixi.lock file to audit
    lockfile: PathBuf,

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

    /// Emit the report as pretty-printed JSON on stdout
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    // TODO(task 3): remove once discover_workspace/load_config/parse_band/
    // find_manifest_in gain real call sites.
    let _ = (
        config::discover_workspace,
        config::load_config,
        config::parse_band,
        config::find_manifest_in,
    );

    let cli = Cli::parse();
    let json = cli.json;
    match run(cli).await {
        Ok(report) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("report serializes")
                );
            } else {
                print!("{}", render::render_human(&report));
            }
            if report.summary.vulnerable > 0 {
                eprintln!("error: audit found vulnerabilities");
                ExitCode::from(EXIT_VULNERABLE)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("{error:?}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

async fn run(cli: Cli) -> miette::Result<AuditReport> {
    let lock_file = pixi_audit::rattler_lock::LockFile::from_path(&cli.lockfile)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read lock file '{}'", cli.lockfile.display()))?;

    let base_url = std::env::var(BASE_URL_ENV_VAR).unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
    let base_url = url::Url::parse(&base_url)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {BASE_URL_ENV_VAR} value '{base_url}'"))?;

    eprintln!("Auditing {} against {base_url} ...", cli.lockfile.display());

    let http_client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .into_diagnostic()
        .wrap_err("failed to construct the HTTP client")?;
    let http = reqwest_middleware::ClientBuilder::new(http_client).build();
    let client = BasiliskClient::new(http, base_url);

    audit_lock_file(
        &client,
        &lock_file,
        &cli.environments,
        &cli.platforms,
        pixi_audit::IgnoreSpec {
            ignore: &cli.ignore,
            ignore_until_fixed: &[],
        },
    )
    .await
    .map_err(miette::Report::new)
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
    fn lockfile_is_required() {
        assert!(Cli::try_parse_from(["pixi-audit"]).is_err());
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
        assert_eq!(cli.lockfile, PathBuf::from("pixi.lock"));
        assert_eq!(cli.environments, vec!["default", "prod"]);
        assert_eq!(cli.platforms, vec!["linux-64"]);
        assert_eq!(cli.ignore, vec!["CVE-2026-1234"]);
        assert!(cli.json);
    }
}
