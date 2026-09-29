use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
use iocraft::prelude::*;
use miette::{Context, IntoDiagnostic};
use pixi_audit::{
    AuditReport, BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL, DEFAULT_EPSS_BASE_URL,
    DEFAULT_KEV_URL, DEFAULT_PYPI_BASE_URL, EPSS_BASE_URL_ENV_VAR, EpssClient, Finding, IgnoreSpec,
    KEV_URL_ENV_VAR, KevClient, PYPI_BASE_URL_ENV_VAR, PackageEcosystem, PypiAuditClient,
    SeverityBand, ThreatDataStatus, ThreatSourceStatus, ThreatSources, audit_lock_file,
    rattler_lock::LockFile,
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

const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_INTERVAL: Duration = Duration::from_millis(80);

#[derive(Default, Props)]
struct AuditSpinnerProps {
    message: String,
}

#[component]
fn AuditSpinner(mut hooks: Hooks, props: &AuditSpinnerProps) -> impl Into<AnyElement<'static>> {
    let mut frame = hooks.use_state(|| 0);
    hooks.use_future(async move {
        let mut interval = tokio::time::interval(SPINNER_INTERVAL);
        loop {
            interval.tick().await;
            frame.set((frame.get() + 1) % SPINNER_FRAMES.len());
        }
    });

    element! {
        Text(content: format!("{} {}", SPINNER_FRAMES[frame.get()], props.message))
    }
}

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

    /// Fail (exit 1) only for findings at or above this severity band.
    /// Unknown severity still fails. Overrides the manifest setting.
    #[arg(long, value_name = "BAND", value_parser = config::parse_band)]
    severity: Option<SeverityBand>,

    /// Report findings from these ecosystems without failing the audit (repeatable).
    /// All ecosystems can fail the audit when omitted.
    #[arg(long, value_enum, value_name = "ECOSYSTEM")]
    warn_only: Vec<WarnOnlyEcosystem>,

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

    /// Explain the terms and scoring used in human-readable reports
    #[arg(long)]
    explain: bool,

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum WarnOnlyEcosystem {
    CondaForge,
    Pypi,
}

impl WarnOnlyEcosystem {
    fn matches(self, ecosystem: &PackageEcosystem) -> bool {
        matches!(
            (self, ecosystem),
            (Self::CondaForge, PackageEcosystem::CondaForge) | (Self::Pypi, PackageEcosystem::Pypi)
        )
    }
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
    if cli.explain && matches!(format, Format::Json | Format::Sarif) {
        eprintln!(
            "error: `--explain` is available only with `--format table` or `--format grouped`"
        );
        return ExitCode::from(EXIT_ERROR);
    }
    let explain = cli.explain;
    let fix_attempted = cli.fix;
    let layout = TableLayout {
        fields: cli.fields.clone(),
        sort_by: cli.sort_by,
    };
    let RunOutcome {
        report,
        threshold,
        warn_only,
        lockfile,
        manifest_available,
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
            render::render_human(
                &report,
                render::RenderOptions {
                    fix_attempted,
                    explain,
                    manifest_available,
                    ..render::RenderOptions::detect_stdout()
                },
            )
        ),
        Format::Table => render::table::write_table(
            &report,
            &lockfile.display().to_string(),
            OutputStyle::detect_stdout(),
            &layout,
            render::GuidanceOptions {
                fix_attempted,
                manifest_available,
                explain,
            },
            std::io::stdout().lock(),
        )
        .expect("write report to stdout"),
    }

    for id in &report.unmatched_ignores {
        eprintln!("warning: ignore rule '{id}' matched no finding");
    }

    let gate = gate(&report, threshold, &warn_only);
    if annotations::on_github_actions() {
        eprint!(
            "{}",
            annotations::github_annotations(&report, |finding| {
                if eligible(finding, &warn_only) && meets_severity_threshold(finding, threshold) {
                    annotations::Level::Error
                } else {
                    annotations::Level::Warning
                }
            })
        );
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
    /// At least one non-warning-only finding at or above the threshold,
    /// or with unknown severity: unscored advisories never slip under a threshold.
    Fail,
    /// Non-warning-only findings exist, but every one sits below `band`.
    BelowThreshold { band: SeverityBand, count: usize },
    /// No findings eligible to fail the audit; warning-only findings may exist.
    Clean,
}

fn eligible(finding: &Finding, warn_only: &[WarnOnlyEcosystem]) -> bool {
    !warn_only
        .iter()
        .any(|ecosystem| ecosystem.matches(&finding.ecosystem))
}

fn meets_severity_threshold(finding: &Finding, threshold: Option<SeverityBand>) -> bool {
    threshold
        .is_none_or(|band| finding.severity == SeverityBand::Unknown || finding.severity >= band)
}

fn gate(
    report: &AuditReport,
    threshold: Option<SeverityBand>,
    warn_only: &[WarnOnlyEcosystem],
) -> Gate {
    let mut count = 0;
    for finding in report
        .vulnerabilities
        .iter()
        .filter(|finding| eligible(finding, warn_only))
    {
        count += 1;
        if meets_severity_threshold(finding, threshold) {
            return Gate::Fail;
        }
    }
    if let Some(band) = threshold.filter(|_| count > 0) {
        Gate::BelowThreshold { band, count }
    } else {
        Gate::Clean
    }
}

struct RunOutcome {
    report: AuditReport,
    threshold: Option<SeverityBand>,
    warn_only: Vec<WarnOnlyEcosystem>,
    lockfile: PathBuf,
    manifest_available: bool,
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

async fn audit_with_progress(
    auditor: &Auditor<'_>,
    message: String,
) -> miette::Result<AuditReport> {
    if !std::io::stdout().is_terminal() || !std::io::stderr().is_terminal() {
        eprintln!("{message}");
        return auditor.audit().await;
    }

    let mut spinner = element!(AuditSpinner(message));
    let audit = auditor.audit();
    tokio::pin!(audit);
    let report = {
        let render = spinner.render_loop();
        tokio::pin!(render);
        tokio::select! {
            biased;
            _ = &mut render => audit.await,
            report = &mut audit => report,
        }
    };
    let _ = console::Term::stdout().clear_last_lines(1);
    report
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
    let audit_message = format!(
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

    let report = audit_with_progress(&auditor, audit_message).await?;
    warn_unavailable_threat_data(&report.threat_data);
    let report = if cli.fix {
        fix::apply(&targets, report, || auditor.audit()).await?
    } else {
        report
    };
    Ok(RunOutcome {
        report,
        threshold,
        warn_only: cli.warn_only,
        manifest_available: targets.manifest.is_some(),
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
