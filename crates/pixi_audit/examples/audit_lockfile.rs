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

use pixi_audit::{BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL, audit_lock_file};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "pixi.lock".to_string());
    let lock_file = pixi_audit::rattler_lock::LockFile::from_path(Path::new(&path))?;

    let base_url = url::Url::parse(
        &std::env::var(BASE_URL_ENV_VAR).unwrap_or_else(|_| DEFAULT_BASE_URL.to_string()),
    )?;
    eprintln!("Auditing {path} against {base_url} ...");
    let http = reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build();
    let client = BasiliskClient::new(http, base_url);

    let report = audit_lock_file(
        &client,
        &lock_file,
        &[],
        &[],
        pixi_audit::IgnoreSpec::default(),
    )
    .await?;

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
