//! Plans fixed versions and applies them to dependency constraints.

use std::collections::BTreeMap;
use std::str::FromStr;

use pixi_audit::{AuditReport, PackageName};
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
    /// Parses `version` with the version scheme of `package`'s ecosystem.
    fn parse(package: &PackageName, version: &str) -> Option<Self> {
        match package {
            PackageName::Conda(_) => CondaVersion::from_str(version).ok().map(Self::Conda),
            PackageName::Pypi(_) => PypiVersion::from_str(version).ok().map(Self::Pypi),
        }
    }
}

/// The minimum version each vulnerable package must be raised to. The
/// name carries its ecosystem's normalization, so a manifest key spelled
/// `Ruamel.YAML` finds the plan entry for the locked `ruamel-yaml`.
pub(super) type FixPlan = BTreeMap<PackageName, FixVersion>;

pub(super) fn plan_fixed_versions(report: &AuditReport) -> FixPlan {
    let mut fixes = FixPlan::new();
    for finding in &report.vulnerabilities {
        let Some(locked) = FixVersion::parse(&finding.package.name, &finding.package.version)
        else {
            continue;
        };
        // OSV can publish fixed events for multiple release branches. Pick the
        // first fix newer than the locked version instead of forcing the
        // highest (and potentially incompatible) major release. Versions that
        // do not parse are skipped rather than compared as text.
        let Some(fixed) = finding
            .fixed_versions
            .iter()
            .filter_map(|fixed| FixVersion::parse(&finding.package.name, fixed))
            .filter(|fixed| *fixed > locked)
            .min()
        else {
            continue;
        };
        // Multiple advisories for one package must all be resolved, so retain
        // the greatest of their minimum required fixes.
        let required = fixes
            .entry(finding.package.name.clone())
            .or_insert_with(|| fixed.clone());
        if *required < fixed {
            *required = fixed;
        }
    }
    fixes
}

/// Parses a manifest dependency key with the normalization of the table it
/// sits in.
type NameParser = fn(&str) -> Result<PackageName, pixi_audit::InvalidPackageName>;

/// Which dependency table a manifest key opens, and therefore how the
/// package names inside it are normalized.
fn dependency_table_kind(key: &str) -> Option<NameParser> {
    match key {
        "pypi-dependencies" => Some(PackageName::pypi),
        "dependencies" | "host-dependencies" | "build-dependencies" => Some(PackageName::conda),
        _ => None,
    }
}

/// Walks every dependency table under `table`, at any nesting depth
/// (`[dependencies]`, `[feature.x.pypi-dependencies]`,
/// `[target.linux-64.host-dependencies]`, ...), and returns how many
/// constraints were changed.
pub(super) fn update_manifest_dependencies(table: &mut dyn TableLike, fixes: &FixPlan) -> usize {
    let mut changed = 0;
    for (key, item) in table.iter_mut() {
        let parse_name = dependency_table_kind(key.get());
        let Some(child) = item.as_table_like_mut() else {
            continue;
        };
        changed += match parse_name {
            Some(parse_name) => update_dependencies(child, parse_name, fixes),
            None => update_manifest_dependencies(child, fixes),
        };
    }
    changed
}

fn update_dependencies(
    dependencies: &mut dyn TableLike,
    parse_name: NameParser,
    fixes: &FixPlan,
) -> usize {
    let mut changed = 0;
    for (name, item) in dependencies.iter_mut() {
        // A key that is not a valid name in this table's ecosystem cannot
        // match any finding; pixi itself would reject it.
        let Ok(name) = parse_name(name.get()) else {
            continue;
        };
        let Some(fixed) = fixes.get(&name) else {
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

/// Adds `>= fixed` to `current`, keeping its other bounds. Lower bounds that
/// `>= fixed` already implies are dropped, so repeated `--fix` runs do not
/// pile up `>=` clauses. Returns `None` when `current` cannot be parsed or
/// already excludes `fixed`, in which case the requirement is left alone.
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
                    .filter(|specifier| !is_implied_lower_bound_pypi(specifier, fixed))
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
            let remaining = current
                .version
                .take()
                .and_then(|existing| without_implied_lower_bounds_conda(existing, fixed));
            current.version = Some(match remaining {
                None | Some(VersionSpec::Any) => lower_bound,
                Some(existing) => {
                    VersionSpec::Group(LogicalOperator::And, vec![existing, lower_bound])
                }
            });
            Some(current.to_string())
        }
    }
}

/// Whether `>= fixed` makes `specifier` redundant: a `>=` or `>` bound at
/// or below `fixed`.
fn is_implied_lower_bound_pypi(specifier: &VersionSpecifier, fixed: &PypiVersion) -> bool {
    match specifier.operator() {
        uv_pep440::Operator::GreaterThanEqual => specifier.version() <= fixed,
        uv_pep440::Operator::GreaterThan => specifier.version() < fixed,
        _ => false,
    }
}

/// Removes `>=`/`>` bounds that `>= fixed` implies from an `And` tree.
/// Returns `None` when nothing else is left. `Or` groups are kept intact:
/// dropping one alternative would change their meaning.
fn without_implied_lower_bounds_conda(
    spec: VersionSpec,
    fixed: &CondaVersion,
) -> Option<VersionSpec> {
    match spec {
        VersionSpec::Range(RangeOperator::GreaterEquals, version) if version <= *fixed => None,
        VersionSpec::Range(RangeOperator::Greater, version) if version < *fixed => None,
        VersionSpec::Group(LogicalOperator::And, items) => {
            let mut kept: Vec<VersionSpec> = items
                .into_iter()
                .filter_map(|item| without_implied_lower_bounds_conda(item, fixed))
                .collect();
            match kept.len() {
                0 => None,
                1 => kept.pop(),
                _ => Some(VersionSpec::Group(LogicalOperator::And, kept)),
            }
        }
        other => Some(other),
    }
}
