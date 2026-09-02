//! `--fix`: raise direct dependency constraints to known fixed versions,
//! re-lock vulnerable packages via `pixi update`, then re-audit.

use std::path::Path;
use std::process::Command;

use miette::{IntoDiagnostic, WrapErr, miette};
use pixi_audit::AuditReport;
use toml_edit::{DocumentMut, Item, TableLike};

use crate::workspace::ResolvedTargets;

mod constraint;

/// Runs the whole `--fix` flow on top of `before`, the report of the
/// current lock file: raises manifest constraints, runs `pixi update` for
/// the vulnerable packages, then calls `reaudit` for the report of the
/// updated lock file. Returns `before` untouched when there is nothing to
/// fix.
pub async fn apply(
    targets: &ResolvedTargets,
    before: AuditReport,
    reaudit: impl AsyncFn() -> miette::Result<AuditReport>,
) -> miette::Result<AuditReport> {
    let names = vulnerable_package_names(&before);
    if names.is_empty() {
        return Ok(before);
    }
    let manifest = targets.manifest.as_deref().ok_or_else(|| {
        miette!(
            "--fix requires a pixi workspace (no pixi.toml/pyproject.toml next to '{}')",
            targets.lockfile.display()
        )
    })?;

    let bumped = bump_manifest_constraints(manifest, &before)?;
    if bumped > 0 {
        eprintln!(
            "fixed: raised {bumped} manifest constraint{} to known fixed versions",
            if bumped == 1 { "" } else { "s" }
        );
    }
    run_pixi_update(manifest, &names)?;

    let after = reaudit().await?;
    let before_count = before.summary.vulnerable;
    let resolved = before_count.saturating_sub(after.summary.vulnerable);
    eprintln!("fixed: resolved {resolved} of {before_count} vulnerabilities via pixi update");
    Ok(after)
}

/// Distinct package names among the report's non-ignored findings, in
/// first-appearance order.
fn vulnerable_package_names(report: &AuditReport) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for finding in &report.vulnerabilities {
        let name = finding.package.to_string();
        if !names.contains(&name) {
            names.push(name);
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
fn bump_manifest_constraints(manifest: &Path, report: &AuditReport) -> miette::Result<usize> {
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
fn run_pixi_update(manifest: &Path, names: &[String]) -> miette::Result<()> {
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
