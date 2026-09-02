//! Audits a `pixi.lock` file against the basilisk vulnerability database and
//! prints the report as JSON.
//!
//! ```shell
//! cargo run -p pixi_audit --example audit_lockfile -- \
//!   crates/pixi_audit/examples/pixi.lock | jq .summary
//! ```
//!
//! Progress goes to stderr, the report to stdout, so the output pipes
//! cleanly. Set `PIXI_AUDIT_BASE_URL` to audit against a different (e.g.
//! self-hosted) OSV-compatible instance.

use std::path::Path;
use std::time::Duration;

use pixi_audit::{
    BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL, DEFAULT_EPSS_BASE_URL, DEFAULT_KEV_URL,
    DEFAULT_PYPI_BASE_URL, EPSS_BASE_URL_ENV_VAR, EpssClient, KEV_URL_ENV_VAR, KevClient,
    PYPI_BASE_URL_ENV_VAR, PypiAuditClient, ThreatSources, audit_lock_file,
};

fn env_url(variable: &str, default: &str) -> Result<url::Url, url::ParseError> {
    url::Url::parse(&std::env::var(variable).unwrap_or_else(|_| default.to_string()))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "pixi.lock".to_string());
    let lock_file = pixi_audit::rattler_lock::LockFile::from_path(Path::new(&path))?;

    let base_url = env_url(BASE_URL_ENV_VAR, DEFAULT_BASE_URL)?;
    let pypi_base_url = env_url(PYPI_BASE_URL_ENV_VAR, DEFAULT_PYPI_BASE_URL)?;
    eprintln!("Auditing {path} against {base_url} and {pypi_base_url} ...");
    // The clients apply no timeout of their own; configure one here.
    let reqwest = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let http = reqwest_middleware::ClientBuilder::new(reqwest).build();
    let client = BasiliskClient::new(http.clone(), base_url);
    let pypi_client = PypiAuditClient::new(http.clone(), pypi_base_url);
    let epss_client = EpssClient::new(
        http.clone(),
        env_url(EPSS_BASE_URL_ENV_VAR, DEFAULT_EPSS_BASE_URL)?,
    );
    let kev_client = KevClient::new(http, env_url(KEV_URL_ENV_VAR, DEFAULT_KEV_URL)?);

    let report = audit_lock_file(
        &client,
        &pypi_client,
        &lock_file,
        &[],
        &[],
        pixi_audit::IgnoreSpec::default(),
        ThreatSources {
            epss: Some(&epss_client),
            kev: Some(&kev_client),
        },
    )
    .await?;

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
