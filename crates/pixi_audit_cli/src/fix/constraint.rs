//! Plans fixed versions and applies them to dependency constraints.

use std::collections::BTreeMap;
use std::str::FromStr;

use pixi_audit::{AuditReport, PackageEcosystem};
use rattler_conda_types::{
    NamelessMatchSpec, Version as CondaVersion, VersionSpec,
    version_spec::{LogicalOperator, RangeOperator},
};
use toml_edit::{Item, TableLike, Value};
use uv_pep440::{Version as PypiVersion, VersionSpecifier, VersionSpecifiers};

/// A version parsed with its ecosystem's rules, so that comparisons are
/// never lexicographic ("10.0" must sort after "9.0").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum FixVersion {
    Conda(CondaVersion),
    Pypi(PypiVersion),
}

impl FixVersion {
    fn parse(ecosystem: &PackageEcosystem, version: &str) -> Option<Self> {
        match ecosystem {
            PackageEcosystem::Pypi => PypiVersion::from_str(version).ok().map(Self::Pypi),
            PackageEcosystem::CondaForge | PackageEcosystem::Other(_) => {
                CondaVersion::from_str(version).ok().map(Self::Conda)
            }
        }
    }
}

/// The minimum version each vulnerable package must be raised to, keyed by
/// normalized name and ecosystem.
pub(super) type FixPlan = BTreeMap<(String, PackageEcosystem), FixVersion>;

pub(super) fn plan_fixed_versions(report: &AuditReport) -> FixPlan {
    let mut fixes = FixPlan::new();
    for finding in &report.vulnerabilities {
        let Some(locked) = FixVersion::parse(&finding.ecosystem, &finding.version) else {
            continue;
        };
        // OSV can publish fixed events for multiple release branches. Pick the
        // first fix newer than the locked version instead of forcing the
        // highest (and potentially incompatible) major release. Versions that
        // do not parse are skipped rather than compared as text.
        let Some(fixed) = finding
            .fixed_versions
            .iter()
            .filter_map(|fixed| FixVersion::parse(&finding.ecosystem, fixed))
            .filter(|fixed| *fixed > locked)
            .min()
        else {
            continue;
        };
        let key = (
            normalize_name(&finding.package, &finding.ecosystem),
            finding.ecosystem.clone(),
        );
        // Multiple advisories for one package must all be resolved, so retain
        // the greatest of their minimum required fixes.
        let required = fixes.entry(key).or_insert_with(|| fixed.clone());
        if *required < fixed {
            *required = fixed;
        }
    }
    fixes
}

fn normalize_name(name: &str, ecosystem: &PackageEcosystem) -> String {
    let name = name.to_ascii_lowercase();
    if matches!(ecosystem, PackageEcosystem::Pypi) {
        name.replace(['_', '.'], "-")
    } else {
        name
    }
}

/// Walks every dependency table under `table`, at any nesting depth
/// (`[dependencies]`, `[feature.x.pypi-dependencies]`,
/// `[target.linux-64.host-dependencies]`, ...), and returns how many
/// constraints were changed.
pub(super) fn update_manifest_dependencies(table: &mut dyn TableLike, fixes: &FixPlan) -> usize {
    let mut changed = 0;
    for (key, item) in table.iter_mut() {
        let ecosystem = match key.get() {
            "pypi-dependencies" => Some(PackageEcosystem::Pypi),
            "dependencies" | "host-dependencies" | "build-dependencies" => {
                Some(PackageEcosystem::CondaForge)
            }
            _ => None,
        };
        let Some(child) = item.as_table_like_mut() else {
            continue;
        };
        changed += match ecosystem {
            Some(ecosystem) => update_dependencies(child, &ecosystem, fixes),
            None => update_manifest_dependencies(child, fixes),
        };
    }
    changed
}

fn update_dependencies(
    dependencies: &mut dyn TableLike,
    ecosystem: &PackageEcosystem,
    fixes: &FixPlan,
) -> usize {
    let mut changed = 0;
    for (name, item) in dependencies.iter_mut() {
        let key = (normalize_name(name.get(), ecosystem), ecosystem.clone());
        let Some(fixed) = fixes.get(&key) else {
            continue;
        };
        if set_constraint(item, fixed) {
            changed += 1;
        }
    }
    changed
}

/// Raises the constraint in a single dependency entry. A registry string
/// (`pkg = ">=1"`) is updated in place; an inline or full table is updated
/// through its `version` field. Git, path, and URL requirements have no
/// `version` and are left untouched.
fn set_constraint(item: &mut Item, fixed: &FixVersion) -> bool {
    let version = if item.is_str() {
        item.as_value_mut()
    } else {
        item.as_table_like_mut()
            .and_then(|table| table.get_mut("version"))
            .and_then(Item::as_value_mut)
    };
    version.is_some_and(|value| set_string_value(value, fixed))
}

fn set_string_value(value: &mut Value, fixed: &FixVersion) -> bool {
    let Value::String(version) = value else {
        return false;
    };
    let Some(constraint) = tighten_constraint(version.value(), fixed) else {
        return false;
    };
    if constraint == *version.value() {
        return false;
    }
    let decor = version.decor().clone();
    *version = toml_edit::Formatted::new(constraint);
    *version.decor_mut() = decor;
    true
}

/// Adds `>= fixed` to `current`, keeping its other bounds. Returns `None`
/// when `current` cannot be parsed or already excludes `fixed`, in which
/// case the requirement is left alone.
fn tighten_constraint(current: &str, fixed: &FixVersion) -> Option<String> {
    match fixed {
        FixVersion::Pypi(fixed) => {
            let current = match current.trim() {
                "" | "*" => VersionSpecifiers::empty(),
                current => VersionSpecifiers::from_str(current).ok()?,
            };
            if !current.contains(fixed) {
                return None;
            }
            let lower_bound = VersionSpecifier::greater_than_equal_version(fixed.clone());
            Some(
                current
                    .iter()
                    .cloned()
                    .chain(std::iter::once(lower_bound))
                    .collect::<VersionSpecifiers>()
                    .to_string(),
            )
        }
        FixVersion::Conda(fixed) => {
            let mut current = current.parse::<NamelessMatchSpec>().ok()?;
            if current
                .version
                .as_ref()
                .is_some_and(|constraint| !constraint.matches(fixed))
            {
                return None;
            }
            let lower_bound = VersionSpec::Range(RangeOperator::GreaterEquals, fixed.clone());
            current.version = Some(match current.version.take() {
                None | Some(VersionSpec::Any) => lower_bound,
                Some(existing) => {
                    VersionSpec::Group(LogicalOperator::And, vec![existing, lower_bound])
                }
            });
            Some(current.to_string())
        }
    }
}
