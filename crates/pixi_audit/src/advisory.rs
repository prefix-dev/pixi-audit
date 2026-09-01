//! OSV advisory interpretation, including Basilisk fix metadata.

use serde::Deserialize;

use crate::types::OsvVulnerability;

#[derive(Debug, Deserialize)]
struct BasiliskDatabaseSpecific {
    basilisk: BasiliskFixMetadata,
}

#[derive(Debug, Deserialize)]
struct BasiliskFixMetadata {
    fix_version: String,
    conda_publication: CondaPublication,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CondaPublication {
    Published,
    NotPublished,
    Unknown,
}

fn basilisk_fix_metadata(
    database_specific: Option<&serde_json::Value>,
) -> Option<BasiliskFixMetadata> {
    let metadata: BasiliskDatabaseSpecific =
        serde_json::from_value(database_specific?.clone()).ok()?;
    (!metadata.basilisk.fix_version.trim().is_empty()).then_some(metadata.basilisk)
}

fn push_unique(versions: &mut Vec<String>, version: &str) {
    if !versions.iter().any(|existing| existing == version) {
        versions.push(version.to_string());
    }
}

/// Fixed versions for `package_name` from an OSV document, split by origin.
///
/// Standard OSV `fixed` events retain their generic behavior: entries in the
/// queried ecosystem (or entries naming no package) are same-ecosystem fixes,
/// while matching package entries in other ecosystems are upstream fixes.
/// Basilisk's extension is more strict and is considered only for conda-forge
/// queries on entries that explicitly match both the package and ecosystem.
pub(crate) fn fixed_versions(
    doc: &OsvVulnerability,
    package_name: &str,
    ecosystem: &str,
) -> (Vec<String>, Vec<String>) {
    let mut same_ecosystem = Vec::new();
    let mut upstream = Vec::new();
    for affected in &doc.affected {
        let name_matches = affected
            .package
            .as_ref()
            .and_then(|p| p.name.as_deref())
            .is_none_or(|name| name.eq_ignore_ascii_case(package_name));
        if !name_matches {
            continue;
        }
        let ecosystem_matches = affected
            .package
            .as_ref()
            .and_then(|p| p.ecosystem.as_deref())
            .is_none_or(|e| e.eq_ignore_ascii_case(ecosystem));
        let versions = if ecosystem_matches {
            &mut same_ecosystem
        } else {
            &mut upstream
        };
        for range in &affected.ranges {
            let is_release_range = range.kind.as_deref().is_some_and(|kind| {
                kind.eq_ignore_ascii_case("ECOSYSTEM") || kind.eq_ignore_ascii_case("SEMVER")
            });
            if !is_release_range {
                continue;
            }
            for event in &range.events {
                if let Some(fixed) = &event.fixed {
                    push_unique(versions, fixed);
                }
            }
        }

        let basilisk_target_matches = ecosystem.eq_ignore_ascii_case("conda-forge")
            && affected.package.as_ref().is_some_and(|package| {
                package
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(package_name))
                    && package.ecosystem.as_deref().is_some_and(|entry_ecosystem| {
                        entry_ecosystem.eq_ignore_ascii_case(ecosystem)
                    })
            });
        if basilisk_target_matches
            && let Some(metadata) = basilisk_fix_metadata(affected.database_specific.as_ref())
        {
            match metadata.conda_publication {
                CondaPublication::Published => {
                    push_unique(&mut same_ecosystem, &metadata.fix_version)
                }
                CondaPublication::NotPublished | CondaPublication::Unknown => {
                    push_unique(&mut upstream, &metadata.fix_version)
                }
            }
        }
    }
    // A version already reported as fixed in the package's own ecosystem is
    // not additionally an "upstream" fix.
    upstream.retain(|version| !same_ecosystem.contains(version));
    (same_ecosystem, upstream)
}

pub(crate) fn advisory_url(doc: &OsvVulnerability) -> Option<String> {
    doc.references
        .iter()
        .find(|reference| reference.kind.as_deref() == Some("ADVISORY"))
        .or_else(|| doc.references.first())
        .map(|reference| reference.url.clone())
}

pub(crate) fn pypi_advisory_url(doc: &OsvVulnerability) -> String {
    doc.references
        .iter()
        .find(|reference| reference.kind.as_deref() == Some("ADVISORY"))
        .or_else(|| {
            doc.references
                .iter()
                .find(|reference| reference.kind.as_deref() == Some("WEB"))
        })
        .map(|reference| reference.url.clone())
        .unwrap_or_else(|| format!("https://osv.dev/vulnerability/{}", doc.id))
}

#[cfg(test)]
mod tests;
