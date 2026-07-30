//! `--fix`: re-lock vulnerable packages via `pixi update`, then re-audit.

use std::path::Path;
use std::process::Command;

use miette::{IntoDiagnostic, WrapErr, miette};
use pixi_audit::AuditReport;

/// Distinct package names among the report's non-ignored findings, in
/// first-appearance order.
pub fn vulnerable_package_names(report: &AuditReport) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for finding in &report.vulnerabilities {
        if !names.contains(&finding.package) {
            names.push(finding.package.clone());
        }
    }
    names
}

/// Runs `pixi update --manifest-path <manifest> <names...>`. pixi's output
/// is relayed to our stderr so stdout stays reserved for the report.
pub fn run_pixi_update(manifest: &Path, names: &[String]) -> miette::Result<()> {
    let output = Command::new("pixi")
        .arg("update")
        .arg("--manifest-path")
        .arg(manifest)
        .args(names)
        .output()
        .into_diagnostic()
        .wrap_err("failed to run `pixi update` (is pixi on PATH?)")?;
    eprint!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(miette!("`pixi update` failed with {}", output.status));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use pixi_audit::{AuditReport, AuditSummary, Finding, SeverityBand};

    use super::*;

    fn finding(package: &str, id: &str) -> Finding {
        Finding {
            package: package.to_string(),
            version: "1.0".to_string(),
            ecosystem: "conda-forge".to_string(),
            environments: vec![],
            id: id.to_string(),
            aliases: vec![],
            severity: SeverityBand::High,
            fixed_versions: vec![],
            upstream_fixed_versions: vec![],
            summary: None,
            url: None,
            ignore_reason: None,
        }
    }

    #[test]
    fn vulnerable_package_names_dedupes_and_skips_ignored() {
        let report = AuditReport {
            vulnerabilities: vec![
                finding("openssl", "CVE-1"),
                finding("openssl", "CVE-2"),
                finding("pillow", "CVE-3"),
            ],
            ignored: vec![finding("zlib", "CVE-4")],
            summary: AuditSummary::default(),
            ..Default::default()
        };
        assert_eq!(vulnerable_package_names(&report), vec!["openssl", "pillow"]);
    }

    #[test]
    fn empty_report_yields_no_names() {
        assert!(vulnerable_package_names(&AuditReport::default()).is_empty());
    }

    #[test]
    fn missing_pixi_binary_is_an_error() {
        // A PATH with no `pixi` in it.
        let dir = tempfile::tempdir().unwrap();
        let old_path = std::env::var_os("PATH");
        unsafe { std::env::set_var("PATH", dir.path()) };
        let result = run_pixi_update(std::path::Path::new("pixi.toml"), &["openssl".to_string()]);
        match old_path {
            Some(p) => unsafe { std::env::set_var("PATH", p) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        assert!(result.is_err());
    }
}
