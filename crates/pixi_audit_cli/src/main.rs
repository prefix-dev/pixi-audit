use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
use miette::{Context, IntoDiagnostic};
use pixi_audit::{
    AuditReport, BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL, DEFAULT_EPSS_BASE_URL,
    DEFAULT_KEV_URL, DEFAULT_PYPI_BASE_URL, EPSS_BASE_URL_ENV_VAR, EpssClient, IgnoreSpec,
    KEV_URL_ENV_VAR, KevClient, PYPI_BASE_URL_ENV_VAR, PypiAuditClient, SeverityBand,
    ThreatDataStatus, ThreatSourceStatus, ThreatSources, audit_lock_file, rattler_lock::LockFile,
};
use render::table::{DEFAULT_FIELDS, Field, OutputStyle, TableLayout};
use reqwest_middleware::ClientWithMiddleware;
use url::Url;

mod annotations;
mod config;
mod fix;
mod ignore;
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
    #[command(subcommand)]
    command: Option<Command>,

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

    /// Ignore every finding that has no fixed release yet. Each returns
    /// once a fix is published. Same as the config file's `ignore-unfixed`.
    #[arg(long)]
    ignore_unfixed: bool,

    /// Fail (exit 1) only for conda findings at or above this severity band.
    /// Severity filtering does not apply to PyPI findings. Overrides the
    /// config file's `severity`.
    #[arg(long, value_name = "BAND", value_parser = config::parse_band)]
    severity: Option<SeverityBand>,

    /// Raise direct dependency constraints to known fixed versions, run
    /// `pixi update`, then re-audit
    #[arg(long)]
    fix: bool,

    /// Emit the report as pretty-printed JSON on stdout (same as
    /// `--format json`)
    #[arg(long)]
    json: bool,

    /// Report format on stdout
    #[arg(long, value_enum, default_value_t = Format::Table)]
    format: Format,

    /// Column to sort table rows by. Risk, severity, EPSS, and KEV sort
    /// highest first; other columns ascend. Only affects `--format table`.
    #[arg(long, value_enum, default_value = "risk", value_name = "FIELD")]
    sort_by: Field,

    /// Columns to show in the table, and their order (comma-separated).
    /// Only affects `--format table`.
    #[arg(long, value_enum, value_delimiter = ',', default_values_t = DEFAULT_FIELDS, value_name = "FIELDS")]
    fields: Vec<Field>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Record ignore rules in the workspace manifest
    Ignore(ignore::IgnoreArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
enum Format {
    /// A status summary and one row per finding. Colors and hyperlinks
    /// only on a terminal; plain, unclipped text when piped or in CI.
    #[default]
    Table,
    /// Findings grouped per package, one line each
    Grouped,
    /// Pretty-printed JSON
    Json,
    /// SARIF 2.1.0, for GitHub code scanning and similar dashboards
    Sarif,
}

#[tokio::main]
async fn main() -> ExitCode {
    let mut cli = Cli::parse();
    if let Some(Command::Ignore(args)) = cli.command.take() {
        return match ignore::run(args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error:?}");
                ExitCode::from(EXIT_ERROR)
            }
        };
    }
    let format = if cli.json { Format::Json } else { cli.format };
    let layout = TableLayout {
        fields: cli.fields.clone(),
        sort_by: cli.sort_by,
    };
    let RunOutcome {
        report,
        threshold,
        lockfile,
    } = match run(cli).await {
        Ok(outcome) => outcome,
        Err(error) => {
            eprintln!("{error:?}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    match format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("report serializes")
        ),
        Format::Sarif => {
            // Only the package lines are looked up in the text; a lock
            // file that cannot be re-read just loses those.
            let contents = std::fs::read_to_string(&lockfile).unwrap_or_default();
            let log = render::sarif::SarifLog::from_report(
                &report,
                &render::sarif::LockfileSource {
                    path: &lockfile,
                    contents: &contents,
                },
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&log).expect("SARIF log serializes")
            );
        }
        Format::Grouped => print!(
            "{}",
            render::render_human(&report, render::RenderOptions::detect_stdout())
        ),
        Format::Table => render::table::write_table(
            &report,
            &lockfile.display().to_string(),
            OutputStyle::detect_stdout(),
            &layout,
            std::io::stdout().lock(),
        )
        .expect("write report to stdout"),
    }

    for id in &report.unmatched_ignores {
        eprintln!("warning: ignore rule '{id}' matched no finding");
    }

    let gate = gate(&report, threshold);
    if annotations::on_github_actions() {
        let level = match gate {
            Gate::Fail => annotations::Level::Error,
            Gate::BelowThreshold { .. } | Gate::Clean => annotations::Level::Warning,
        };
        eprint!("{}", annotations::github_annotations(&report, level));
    }

    match gate {
        Gate::Fail => {
            eprintln!("error: audit found vulnerabilities");
            ExitCode::from(EXIT_VULNERABLE)
        }
        Gate::BelowThreshold { band, count } => {
            eprintln!("note: {count} vulnerabilities found below the '{band}' severity threshold");
            ExitCode::SUCCESS
        }
        Gate::Clean => ExitCode::SUCCESS,
    }
}

/// What the report means for the exit code.
#[derive(Debug, PartialEq, Eq)]
enum Gate {
    /// At least one finding at or above the threshold, or with unknown
    /// severity: an unscored advisory must never slip under a threshold.
    Fail,
    /// Findings exist, but every one sits below `band`.
    BelowThreshold { band: SeverityBand, count: usize },
    /// No findings at all.
    Clean,
}

fn gate(report: &AuditReport, threshold: Option<SeverityBand>) -> Gate {
    let findings = &report.vulnerabilities;
    if findings.is_empty() {
        return Gate::Clean;
    }
    let Some(band) = threshold else {
        return Gate::Fail;
    };
    let fails = findings
        .iter()
        .any(|finding| finding.severity == SeverityBand::Unknown || finding.severity >= band);
    if fails {
        Gate::Fail
    } else {
        Gate::BelowThreshold {
            band,
            count: findings.len(),
        }
    }
}

struct RunOutcome {
    report: AuditReport,
    threshold: Option<SeverityBand>,
    lockfile: PathBuf,
}

/// Everything needed to audit the lock file, kept together so a `--fix`
/// run re-reads and re-audits it with identical settings.
struct Auditor<'a> {
    client: BasiliskClient,
    pypi_client: PypiAuditClient,
    epss_client: EpssClient,
    kev_client: KevClient,
    lockfile: &'a Path,
    environments: &'a [String],
    platforms: &'a [String],
    ignore: IgnoreSpec<'a>,
}

impl Auditor<'_> {
    async fn audit(&self) -> miette::Result<AuditReport> {
        let lock_file = LockFile::from_path(self.lockfile)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read lock file '{}'", self.lockfile.display()))?;
        audit_lock_file(
            &self.client,
            &self.pypi_client,
            &lock_file,
            self.environments,
            self.platforms,
            self.ignore,
            ThreatSources {
                epss: Some(&self.epss_client),
                kev: Some(&self.kev_client),
            },
        )
        .await
        .into_diagnostic()
    }
}

/// The base URL from `var`, or `default` when it is unset.
fn base_url_from_env(var: &str, default: &str) -> miette::Result<Url> {
    let raw = std::env::var(var).unwrap_or_else(|_| default.to_string());
    Url::parse(&raw)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid {var} value '{raw}'"))
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
    let ignore_unfixed = cli.ignore_unfixed || config.ignore_unfixed;

    let base_url = base_url_from_env(BASE_URL_ENV_VAR, DEFAULT_BASE_URL)?;
    let pypi_base_url = base_url_from_env(PYPI_BASE_URL_ENV_VAR, DEFAULT_PYPI_BASE_URL)?;
    let epss_base_url = base_url_from_env(EPSS_BASE_URL_ENV_VAR, DEFAULT_EPSS_BASE_URL)?;
    let kev_url = base_url_from_env(KEV_URL_ENV_VAR, DEFAULT_KEV_URL)?;
    eprintln!(
        "Auditing {} against {base_url} and {pypi_base_url} ...",
        targets.lockfile.display()
    );

    let http_client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .into_diagnostic()
        .wrap_err("failed to construct the HTTP client")?;
    let http = reqwest_middleware::ClientBuilder::new(http_client.clone()).build();
    let threat_http = threat_http_client(http_client);
    let auditor = Auditor {
        client: BasiliskClient::new(http.clone(), base_url),
        pypi_client: PypiAuditClient::new(http, pypi_base_url),
        epss_client: EpssClient::new(threat_http.clone(), epss_base_url),
        kev_client: KevClient::new(threat_http, kev_url),
        lockfile: &targets.lockfile,
        environments: &cli.environments,
        platforms: &cli.platforms,
        ignore: IgnoreSpec {
            ignore: &ignore,
            ignore_until_fixed: &ignore_until_fixed,
            package_rules: &config.package_rules,
            ignore_unfixed,
        },
    };

    let report = auditor.audit().await?;
    warn_unavailable_threat_data(&report.threat_data);
    let report = if cli.fix {
        fix::apply(&targets, report, || auditor.audit()).await?
    } else {
        report
    };
    Ok(RunOutcome {
        report,
        threshold,
        lockfile: targets.lockfile,
    })
}

/// HTTP client for the threat-data feeds. Responses are cached on disk so
/// the KEV catalog is revalidated rather than downloaded on every run.
fn threat_http_client(client: reqwest::Client) -> ClientWithMiddleware {
    let mut builder = reqwest_middleware::ClientBuilder::new(client);
    if let Some(path) = http_cache_dir() {
        builder = builder.with(Cache(HttpCache {
            mode: CacheMode::Default,
            manager: CACacheManager::new(path, false),
            options: HttpCacheOptions::default(),
        }));
    }
    builder.build()
}

/// `pixi-audit/http-cache` inside pixi's cache directory: `PIXI_CACHE_DIR`,
/// else `RATTLER_CACHE_DIR`, else `rattler/cache` in the platform's cache
/// directory.
fn http_cache_dir() -> Option<PathBuf> {
    let root = std::env::var_os("PIXI_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("RATTLER_CACHE_DIR").map(PathBuf::from))
        .or_else(|| dirs::cache_dir().map(|dir| dir.join("rattler").join("cache")))?;
    Some(root.join("pixi-audit").join("http-cache"))
}

fn warn_unavailable_threat_data(status: &ThreatDataStatus) {
    for (name, source) in [("EPSS scores", &status.epss), ("KEV catalog", &status.kev)] {
        match source {
            ThreatSourceStatus::Failed { error } => {
                eprintln!("warning: {name} unavailable, findings are ranked without them: {error}");
            }
            ThreatSourceStatus::Disabled | ThreatSourceStatus::Loaded { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests;
