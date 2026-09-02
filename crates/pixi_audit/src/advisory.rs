//! OSV advisory interpretation, including Basilisk fix metadata.

use serde::Deserialize;

use crate::{
    report::{CondaPublication, PackageName, UpstreamFix, UpstreamOrigin},
    types::{OsvAffected, OsvVulnerability},
};

#[derive(Debug, Deserialize)]
struct BasiliskDatabaseSpecific {
    basilisk: BasiliskFixMetadata,
}

#[derive(Debug, Deserialize)]
struct BasiliskFixMetadata {
    fix_version: String,
    conda_publication: CondaPublication,
}

fn basilisk_fix_metadata(
    database_specific: Option<&serde_json::Value>,
) -> Option<BasiliskFixMetadata> {
    let metadata: BasiliskDatabaseSpecific =
        serde_json::from_value(database_specific?.clone()).ok()?;
    (!metadata.basilisk.fix_version.trim().is_empty()).then_some(metadata.basilisk)
}

/// Fixed versions for one package from an OSV document, split by origin.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct FixedVersions {
    /// Fixes released in the queried ecosystem.
    pub same_ecosystem: Vec<String>,
    /// Fixes known outside the queried ecosystem, with their origin.
    /// Informative only: those releases may not exist in the queried
    /// ecosystem yet.
    pub upstream: Vec<UpstreamFix>,
}

impl FixedVersions {
    fn push_same_ecosystem(&mut self, version: &str) {
        if !self
            .same_ecosystem
            .iter()
            .any(|existing| existing == version)
        {
            self.same_ecosystem.push(version.to_string());
        }
    }

    /// The first origin reported for a version wins.
    fn push_upstream(&mut self, version: &str, origin: UpstreamOrigin) {
        if !self
            .upstream
            .iter()
            .any(|existing| existing.version == version)
        {
            self.upstream.push(UpstreamFix {
                version: version.to_string(),
                origin,
            });
        }
    }
}

/// `fixed` events from the entry's release ranges (`ECOSYSTEM`/`SEMVER`).
/// Git ranges carry commit hashes, which are not installable versions.
fn release_fixed_events(affected: &OsvAffected) -> impl Iterator<Item = &str> {
    affected
        .ranges
        .iter()
        .filter(|range| {
            range.kind.as_deref().is_some_and(|kind| {
                kind.eq_ignore_ascii_case("ECOSYSTEM") || kind.eq_ignore_ascii_case("SEMVER")
            })
        })
        .flat_map(|range| range.events.iter())
        .filter_map(|event| event.fixed.as_deref())
}

/// Fixed versions for `package` from an OSV document, split by origin.
///
/// Standard OSV `fixed` events retain their generic behavior: entries in the
/// queried ecosystem (or entries naming no package) are same-ecosystem fixes,
/// while matching package entries in other ecosystems are upstream fixes.
/// Package names match under the ecosystem's own normalization, so an
/// advisory spelling `ruamel.yaml` matches a PyPI query for `ruamel-yaml`.
/// Basilisk's extension is more strict and is considered only for conda-forge
/// queries on entries that explicitly match both the package and ecosystem.
pub(crate) fn fixed_versions(
    doc: &OsvVulnerability,
    package: &PackageName,
    ecosystem: &str,
) -> FixedVersions {
    let mut fixes = FixedVersions::default();
    for affected in &doc.affected {
        let entry_name = affected.package.as_ref().and_then(|p| p.name.as_deref());
        let entry_ecosystem = affected
            .package
            .as_ref()
            .and_then(|p| p.ecosystem.as_deref());

        // An entry naming no package applies to the queried one.
        if !entry_name.is_none_or(|name| package.matches(name)) {
            continue;
        }
        let other_ecosystem =
            entry_ecosystem.filter(|entry| !entry.eq_ignore_ascii_case(ecosystem));
        let same_ecosystem = other_ecosystem.is_none();

        for fixed in release_fixed_events(affected) {
            match other_ecosystem {
                None => fixes.push_same_ecosystem(fixed),
                Some(other) => fixes.push_upstream(
                    fixed,
                    UpstreamOrigin::Ecosystem {
                        ecosystem: other.to_string(),
                    },
                ),
            }
        }

        let explicit_conda_forge_match = ecosystem.eq_ignore_ascii_case("conda-forge")
            && entry_name.is_some()
            && entry_ecosystem.is_some()
            && same_ecosystem;
        if explicit_conda_forge_match
            && let Some(metadata) = basilisk_fix_metadata(affected.database_specific.as_ref())
        {
            // A CPE-matched fix is the project's own release; only a
            // published conda-forge build makes it a fixed version here.
            match metadata.conda_publication {
                CondaPublication::Published => fixes.push_same_ecosystem(&metadata.fix_version),
                conda_publication => fixes.push_upstream(
                    &metadata.fix_version,
                    UpstreamOrigin::Project { conda_publication },
                ),
            }
        }
    }
    // A version already reported as fixed in the package's own ecosystem is
    // not additionally an "upstream" fix.
    let same_ecosystem = &fixes.same_ecosystem;
    fixes
        .upstream
        .retain(|fix| !same_ecosystem.contains(&fix.version));
    fixes
}

fn reference_url<'a>(doc: &'a OsvVulnerability, kind: &str) -> Option<&'a str> {
    doc.references
        .iter()
        .find(|reference| reference.kind.as_deref() == Some(kind))
        .map(|reference| reference.url.as_str())
}

/// The advisory link for a Basilisk document: the `ADVISORY` reference,
/// else the first reference of any kind.
pub(crate) fn advisory_url(doc: &OsvVulnerability) -> Option<String> {
    reference_url(doc, "ADVISORY")
        .or_else(|| {
            doc.references
                .first()
                .map(|reference| reference.url.as_str())
        })
        .map(str::to_string)
}

/// The advisory link for an OSV.dev document: the `ADVISORY` reference,
/// else the `WEB` reference, else the document's own osv.dev page.
pub(crate) fn pypi_advisory_url(doc: &OsvVulnerability) -> String {
    reference_url(doc, "ADVISORY")
        .or_else(|| reference_url(doc, "WEB"))
        .map(str::to_string)
        .unwrap_or_else(|| format!("https://osv.dev/vulnerability/{}", doc.id))
}

#[cfg(test)]
mod tests;
