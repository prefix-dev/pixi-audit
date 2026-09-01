//! `--fix`: raise direct dependency constraints to known fixed versions,
//! re-lock vulnerable packages via `pixi update`, then re-audit.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;

use miette::{IntoDiagnostic, WrapErr, miette};
use pixi_audit::AuditReport;
use rattler_conda_types::{
    NamelessMatchSpec, Version as CondaVersion, VersionSpec,
    version_spec::{LogicalOperator, RangeOperator},
};
use toml_edit::{DocumentMut, Formatted, Item, Table, Value};
use uv_pep440::{Version as PypiVersion, VersionSpecifier, VersionSpecifiers};

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
    let fixes = fixed_versions(report);
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

    let root = if manifest.file_name().and_then(|name| name.to_str()) == Some("pyproject.toml") {
        document
            .get_mut("tool")
            .and_then(Item::as_table_mut)
            .and_then(|tool| tool.get_mut("pixi"))
            .and_then(Item::as_table_mut)
            .ok_or_else(|| miette!("'{}' has no [tool.pixi] table", manifest.display()))?
    } else {
        document.as_table_mut()
    };

    let changed = update_dependency_tables(root, &fixes);
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

fn fixed_versions(report: &AuditReport) -> BTreeMap<(String, String), String> {
    let mut fixes = BTreeMap::new();
    for finding in &report.vulnerabilities {
        // OSV can publish fixed events for multiple release branches. Pick the
        // first fix newer than the locked version instead of forcing the
        // highest (and potentially incompatible) major release.
        let Some(fixed) = finding
            .fixed_versions
            .iter()
            .filter(|fixed| {
                compare_versions(fixed, &finding.version, &finding.ecosystem) == Ordering::Greater
            })
            .min_by(|left, right| compare_versions(left, right, &finding.ecosystem))
        else {
            continue;
        };
        let key = (
            normalize_name(&finding.package, &finding.ecosystem),
            finding.ecosystem.clone(),
        );
        // Multiple advisories for one package must all be resolved, so retain
        // the greatest of their minimum required fixes.
        fixes
            .entry(key)
            .and_modify(|current: &mut String| {
                if compare_versions(current, fixed, &finding.ecosystem) == Ordering::Less {
                    *current = fixed.clone();
                }
            })
            .or_insert_with(|| fixed.clone());
    }
    fixes
}

fn compare_versions(left: &str, right: &str, ecosystem: &str) -> Ordering {
    if ecosystem.eq_ignore_ascii_case("PyPI") {
        match (
            uv_pep440::Version::from_str(left),
            uv_pep440::Version::from_str(right),
        ) {
            (Ok(left), Ok(right)) => left.cmp(&right),
            _ => left.cmp(right),
        }
    } else {
        match (
            rattler_conda_types::Version::from_str(left),
            rattler_conda_types::Version::from_str(right),
        ) {
            (Ok(left), Ok(right)) => left.cmp(&right),
            _ => left.cmp(right),
        }
    }
}

fn normalize_name(name: &str, ecosystem: &str) -> String {
    let name = name.to_ascii_lowercase();
    if ecosystem.eq_ignore_ascii_case("PyPI") {
        name.replace(['_', '.'], "-")
    } else {
        name
    }
}

fn update_dependency_tables(
    table: &mut Table,
    fixes: &BTreeMap<(String, String), String>,
) -> usize {
    let mut changed = 0;
    for (key, item) in table.iter_mut() {
        let ecosystem = match key.get() {
            "pypi-dependencies" => Some("PyPI"),
            "dependencies" | "host-dependencies" | "build-dependencies" => Some("conda-forge"),
            _ => None,
        };
        if let Some(ecosystem) = ecosystem {
            if let Some(dependencies) = item.as_table_mut() {
                changed += update_dependencies(dependencies, ecosystem, fixes);
            }
            continue;
        }
        if let Some(child) = item.as_table_mut() {
            changed += update_dependency_tables(child, fixes);
        }
    }
    changed
}

fn update_dependencies(
    dependencies: &mut Table,
    ecosystem: &str,
    fixes: &BTreeMap<(String, String), String>,
) -> usize {
    let mut changed = 0;
    for (name, item) in dependencies.iter_mut() {
        let key = (normalize_name(name.get(), ecosystem), ecosystem.to_string());
        let Some(fixed) = fixes.get(&key) else {
            continue;
        };
        if set_constraint(item, fixed, ecosystem) {
            changed += 1;
        }
    }
    changed
}

fn set_constraint(item: &mut Item, fixed: &str, ecosystem: &str) -> bool {
    if let Some(value) = item.as_value_mut()
        && set_string_value(value, fixed, ecosystem)
    {
        return true;
    }
    if let Some(inline) = item.as_inline_table_mut()
        && let Some(version) = inline.get_mut("version")
        && set_string_value(version, fixed, ecosystem)
    {
        return true;
    }
    if let Some(table) = item.as_table_mut()
        && let Some(version) = table.get_mut("version").and_then(Item::as_value_mut)
        && set_string_value(version, fixed, ecosystem)
    {
        return true;
    }
    false
}

fn set_string_value(value: &mut Value, fixed: &str, ecosystem: &str) -> bool {
    let Value::String(version) = value else {
        return false;
    };
    let Some(constraint) = tighten_constraint(version.value(), fixed, ecosystem) else {
        return false;
    };
    if constraint == *version.value() {
        return false;
    }
    let decor = version.decor().clone();
    *version = Formatted::new(constraint);
    *version.decor_mut() = decor;
    true
}

fn tighten_constraint(current: &str, fixed: &str, ecosystem: &str) -> Option<String> {
    if ecosystem.eq_ignore_ascii_case("PyPI") {
        let current = match current.trim() {
            "" | "*" => VersionSpecifiers::empty(),
            current => VersionSpecifiers::from_str(current).ok()?,
        };
        let fixed = PypiVersion::from_str(fixed).ok()?;
        if !current.contains(&fixed) {
            return None;
        }
        let lower_bound = VersionSpecifier::greater_than_equal_version(fixed);
        Some(
            current
                .iter()
                .cloned()
                .chain(std::iter::once(lower_bound))
                .collect::<VersionSpecifiers>()
                .to_string(),
        )
    } else {
        let mut current = current.parse::<NamelessMatchSpec>().ok()?;
        let fixed = CondaVersion::from_str(fixed).ok()?;
        if current
            .version
            .as_ref()
            .is_some_and(|constraint| !constraint.matches(&fixed))
        {
            return None;
        }
        let lower_bound = VersionSpec::Range(RangeOperator::GreaterEquals, fixed);
        current.version = Some(match current.version.take() {
            None | Some(VersionSpec::Any) => lower_bound,
            Some(existing) => VersionSpec::Group(LogicalOperator::And, vec![existing, lower_bound]),
        });
        Some(current.to_string())
    }
}

#[cfg(test)]
mod tests {
    use pixi_audit::{AuditReport, AuditSummary, Finding, SeverityBand};

    use super::*;

    fn finding(package: &str, id: &str) -> Finding {
        finding_with_fix(package, id, "conda-forge", &[])
    }

    fn finding_with_fix(
        package: &str,
        id: &str,
        ecosystem: &str,
        fixed_versions: &[&str],
    ) -> Finding {
        Finding {
            package: package.to_string(),
            version: "1.0".to_string(),
            ecosystem: ecosystem.to_string(),
            environments: vec![],
            id: id.to_string(),
            aliases: vec![],
            severity: SeverityBand::High,
            fixed_versions: fixed_versions.iter().map(ToString::to_string).collect(),
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
    fn bumps_constraints_across_pixi_dependency_tables() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("pixi.toml");
        std::fs::write(
            &manifest,
            r#"[workspace]
name = "demo"

[tasks]
insta-review = {
    cmd = "cargo insta review",
    depends-on = ["test"],
}

[dependencies]
openssl = ">=1,<4" # keep this comment
zlib = { version = ">=1", channel = "conda-forge" }

[feature.test.pypi-dependencies]
requests = ">=2,<3"
urllib3 = { git = "https://example.com/urllib3" }

[target.linux-64.host-dependencies]
openssl = { version = ">=1", build = "*_0" }
"#,
        )
        .unwrap();
        let report = AuditReport {
            vulnerabilities: vec![
                finding_with_fix("openssl", "CVE-1", "conda-forge", &["3.1.1"]),
                finding_with_fix("requests", "PYSEC-1", "PyPI", &["2.9.0"]),
                finding_with_fix("requests", "PYSEC-2", "PyPI", &["2.10.0"]),
            ],
            ..Default::default()
        };

        assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 3);
        let content = std::fs::read_to_string(&manifest).unwrap();
        let value: toml::Value = toml::from_str(&content).unwrap();
        let openssl = value["dependencies"]["openssl"].as_str().unwrap();
        assert!(openssl.contains(">=3.1.1"), "constraint: {openssl}");
        assert!(openssl.contains("<4"), "constraint: {openssl}");
        assert_eq!(
            value["dependencies"]["zlib"]["version"].as_str(),
            Some(">=1")
        );
        let requests = value["feature"]["test"]["pypi-dependencies"]["requests"]
            .as_str()
            .unwrap();
        assert!(requests.contains(">=2.10.0"), "constraint: {requests}");
        assert!(requests.contains("<3"), "constraint: {requests}");
        assert_eq!(
            value["feature"]["test"]["pypi-dependencies"]["urllib3"]["git"].as_str(),
            Some("https://example.com/urllib3")
        );
        let target_openssl = value["target"]["linux-64"]["host-dependencies"]["openssl"]["version"]
            .as_str()
            .unwrap();
        assert!(
            target_openssl.contains(">=3.1.1"),
            "constraint: {target_openssl}"
        );
        assert!(content.contains("# keep this comment"));
        assert!(content.contains("insta-review = {"));
    }

    #[test]
    fn bumps_only_tool_pixi_in_pyproject() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("pyproject.toml");
        std::fs::write(
            &manifest,
            r#"[project]
dependencies = ["requests>=2"]

[tool.pixi.workspace]
name = "demo"

[tool.pixi.pypi-dependencies]
requests = { version = ">=2", extras = ["socks"] }
"#,
        )
        .unwrap();
        let report = AuditReport {
            vulnerabilities: vec![finding_with_fix("Requests", "PYSEC-1", "PyPI", &["2.33.0"])],
            ..Default::default()
        };

        assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 1);
        let content = std::fs::read_to_string(&manifest).unwrap();
        let value: toml::Value = toml::from_str(&content).unwrap();
        assert_eq!(
            value["project"]["dependencies"][0].as_str(),
            Some("requests>=2")
        );
        let requests = value["tool"]["pixi"]["pypi-dependencies"]["requests"]["version"]
            .as_str()
            .unwrap();
        assert!(requests.contains(">=2.33.0"), "constraint: {requests}");
        assert_eq!(
            value["tool"]["pixi"]["pypi-dependencies"]["requests"]["extras"][0].as_str(),
            Some("socks")
        );
    }

    #[test]
    fn chooses_lowest_fixed_release_branch() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("pixi.toml");
        std::fs::write(
            &manifest,
            r#"[workspace]
name = "demo"

[pypi-dependencies]
requests = ">=1,<2"
"#,
        )
        .unwrap();
        let report = AuditReport {
            vulnerabilities: vec![finding_with_fix(
                "requests",
                "PYSEC-1",
                "PyPI",
                &["2.1", "1.5"],
            )],
            ..Default::default()
        };

        assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 1);
        let content = std::fs::read_to_string(manifest).unwrap();
        assert!(content.contains(">=1.5"), "manifest: {content}");
        assert!(content.contains("<2"), "manifest: {content}");
        assert!(!content.contains(">=2.1"), "manifest: {content}");
    }

    #[test]
    fn leaves_constraint_unchanged_when_no_fix_satisfies_it() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("pixi.toml");
        let content = r#"[workspace]
name = "demo"

[pypi-dependencies]
requests = ">=1,<1.5"
"#;
        std::fs::write(&manifest, content).unwrap();
        let report = AuditReport {
            vulnerabilities: vec![finding_with_fix(
                "requests",
                "PYSEC-1",
                "PyPI",
                &["2.0", "1.5"],
            )],
            ..Default::default()
        };

        assert_eq!(bump_manifest_constraints(&manifest, &report).unwrap(), 0);
        assert_eq!(std::fs::read_to_string(manifest).unwrap(), content);
    }
}
