//! Plans fixed versions and applies them to dependency constraints.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::str::FromStr;

use pixi_audit::AuditReport;
use rattler_conda_types::{
    NamelessMatchSpec, Version as CondaVersion, VersionSpec,
    version_spec::{LogicalOperator, RangeOperator},
};
use toml_edit::{Formatted, Item, TableLike, Value};
use uv_pep440::{Version as PypiVersion, VersionSpecifier, VersionSpecifiers};

pub(super) fn plan_fixed_versions(report: &AuditReport) -> BTreeMap<(String, String), String> {
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

pub(super) fn update_manifest_dependencies(
    table: &mut dyn TableLike,
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
            if let Some(dependencies) = item.as_table_like_mut() {
                changed += update_dependencies(dependencies, ecosystem, fixes);
            }
            continue;
        }
        if let Some(child) = item.as_table_like_mut() {
            changed += update_manifest_dependencies(child, fixes);
        }
    }
    changed
}

fn update_dependencies(
    dependencies: &mut dyn TableLike,
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
