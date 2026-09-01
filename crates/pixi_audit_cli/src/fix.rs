//! `--fix`: raise direct dependency constraints to known fixed versions,
//! re-lock vulnerable packages via `pixi update`, then re-audit.

use std::path::Path;
use std::process::Command;

use miette::{IntoDiagnostic, WrapErr, miette};
use pixi_audit::AuditReport;
use toml_edit::{DocumentMut, Item, TableLike};

mod constraint;

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

/// Raise matching direct dependency constraints in a Pixi manifest to the
/// lowest fixed version newer than each vulnerable locked version.
///
/// Existing upper bounds and build qualifiers are preserved. A requirement is
/// left unchanged when no known fix satisfies it. Registry string requirements
/// and inline/table requirements with a `version` field are updated; Git, path,
/// and URL dependencies without a version are left untouched. The original
/// TOML formatting and comments are retained by `toml_edit`.
pub fn bump_manifest_constraints(manifest: &Path, report: &AuditReport) -> miette::Result<usize> {
    let fixes = constraint::plan_fixed_versions(report);
    if fixes.is_empty() {
        return Ok(0);
    }

    let content = std::fs::read_to_string(manifest)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read manifest '{}'", manifest.display()))?;
    let mut document = content
        .parse::<DocumentMut>()
        .into_diagnostic()
        .wrap_err_with(|| format!("'{}' is not valid TOML", manifest.display()))?;

    let root: &mut dyn TableLike =
        if manifest.file_name().and_then(|name| name.to_str()) == Some("pyproject.toml") {
            document
                .get_mut("tool")
                .and_then(Item::as_table_like_mut)
                .and_then(|tool| tool.get_mut("pixi"))
                .and_then(Item::as_table_like_mut)
                .ok_or_else(|| miette!("'{}' has no [tool.pixi] table", manifest.display()))?
        } else {
            document.as_table_mut()
        };

    let changed = constraint::update_manifest_dependencies(root, &fixes);
    if changed > 0 {
        std::fs::write(manifest, document.to_string())
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to update manifest '{}'", manifest.display()))?;
    }
    Ok(changed)
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
mod tests;
