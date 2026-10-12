//! Plans fixed versions and applies them to dependency constraints.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::str::FromStr;

use pixi_audit::{AuditReport, PackageName, PackageVersion};
use rattler_conda_types::{
    NamelessMatchSpec, Version as CondaVersion, VersionSpec,
    version_spec::{LogicalOperator, RangeOperator},
};
use toml_edit::{Item, TableLike, Value};
use uv_pep440::{Version as PypiVersion, VersionSpecifier, VersionSpecifiers};

/// The minimum version each vulnerable package must be raised to, parsed
/// with its ecosystem's rules so comparisons are never lexicographic
/// ("10.0" must sort after "9.0"). The name carries its ecosystem's
/// normalization, so a manifest key spelled `Ruamel.YAML` finds the plan
/// entry for the locked `ruamel-yaml`.
#[derive(Debug, Default)]
pub(super) struct FixPlan(BTreeMap<PackageName, PackageVersion>);

impl FixPlan {
    pub(super) fn from_report(report: &AuditReport) -> Self {
        let mut plan = Self::default();
        for vuln_match in &report.matches {
            let Some(fixed) = vuln_match.lowest_fixed_version() else {
                continue;
            };
            // Multiple advisories for one package must all be resolved, so
            // retain the greatest of their minimum required fixes.
            match plan.0.entry(vuln_match.package.name.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(fixed);
                }
                Entry::Occupied(mut entry) => {
                    if *entry.get() < fixed {
                        entry.insert(fixed);
                    }
                }
            }
        }
        plan
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Walks every dependency table under `table`, at any nesting depth
    /// (`[dependencies]`, `[feature.x.pypi-dependencies]`,
    /// `[target.linux-64.host-dependencies]`, ...), and returns how many
    /// constraints were changed.
    pub(super) fn apply_to_manifest(&self, table: &mut dyn TableLike) -> usize {
        let mut changed = 0;
        for (key, item) in table.iter_mut() {
            let parse_name = dependency_table_kind(key.get());
            let Some(child) = item.as_table_like_mut() else {
                continue;
            };
            changed += match parse_name {
                Some(parse_name) => self.apply_to_dependencies(child, parse_name),
                None => self.apply_to_manifest(child),
            };
        }
        changed
    }

    fn apply_to_dependencies(
        &self,
        dependencies: &mut dyn TableLike,
        parse_name: NameParser,
    ) -> usize {
        let mut changed = 0;
        for (name, item) in dependencies.iter_mut() {
            // A key that is not a valid name in this table's ecosystem cannot
            // match any vulnerability; pixi itself would reject it.
            let Ok(name) = parse_name(name.get()) else {
                continue;
            };
            let Some(fixed) = self.0.get(&name) else {
                continue;
            };
            if set_constraint(item, fixed) {
                changed += 1;
            }
        }
        changed
    }
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

/// Raises the constraint in a single dependency entry. A registry string
/// (`pkg = ">=1"`) is updated in place; an inline or full table is updated
/// through its `version` field. Git, path, and URL requirements have no
/// `version` and are left untouched.
fn set_constraint(item: &mut Item, fixed: &PackageVersion) -> bool {
    let version = if item.is_str() {
        item.as_value_mut()
    } else {
        item.as_table_like_mut()
            .and_then(|table| table.get_mut("version"))
            .and_then(Item::as_value_mut)
    };
    version.is_some_and(|value| set_string_value(value, fixed))
}

fn set_string_value(value: &mut Value, fixed: &PackageVersion) -> bool {
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
fn tighten_constraint(current: &str, fixed: &PackageVersion) -> Option<String> {
    match fixed {
        PackageVersion::Pypi(fixed) => {
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
        PackageVersion::Conda(fixed) => {
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
