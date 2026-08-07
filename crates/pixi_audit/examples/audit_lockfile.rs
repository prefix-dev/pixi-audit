//! Audits a `pixi.lock` file against an anonymous, OSV-compatible custom
//! service and prints the report as JSON.
//!
//! This library example deliberately does not obtain credentials or launch
//! Pixi. Set `PIXI_AUDIT_BASE_URL` to a custom service that accepts anonymous
//! requests. Use the `pixi-audit` CLI for the authenticated production service.

use std::path::Path;

use pixi_audit::{BASE_URL_ENV_VAR, BasiliskClient, audit_lock_file};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "pixi.lock".to_string());
    let lock_file = pixi_audit::rattler_lock::LockFile::from_path(Path::new(&path))?;

    let configured_base_url = std::env::var(BASE_URL_ENV_VAR).map_err(|_| {
        format!("{BASE_URL_ENV_VAR} must name a custom service that accepts anonymous requests")
    })?;
    let base_url = url::Url::parse(&configured_base_url)?;
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
