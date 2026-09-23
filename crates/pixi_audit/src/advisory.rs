//! OSV advisory interpretation, including Basilisk fix metadata.

use serde::Deserialize;

use crate::{
    report::{
        CondaPublication, MatchApplicability, MatchedIdentity, MatchedIdentityKind, PackageName,
        UpstreamFix, UpstreamOrigin,
    },
    types::{OsvAffected, OsvVulnerability},
};

#[derive(Debug, Deserialize)]
struct BasiliskFixMetadata {
    fix_version: String,
    conda_publication: CondaPublication,
}

/// The `basilisk` block of an affected entry's `database_specific`.
fn basilisk_block(database_specific: Option<&serde_json::Value>) -> Option<&serde_json::Value> {
    database_specific?.get("basilisk")
}

fn basilisk_fix_metadata(block: &serde_json::Value) -> Option<BasiliskFixMetadata> {
    let metadata: BasiliskFixMetadata = serde_json::from_value(block.clone()).ok()?;
    (!metadata.fix_version.trim().is_empty()).then_some(metadata)
}

/// How basilisk matched an advisory to the queried conda-forge package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BasiliskMatch {
    pub applicability: MatchApplicability,
    pub matched_identity: Option<MatchedIdentity>,
}

impl BasiliskMatch {
    /// Reads one match's fields. Each field is read on its own, so a value
    /// this version does not understand leaves that field unspecified
    /// instead of discarding the whole block.
    fn from_value(value: &serde_json::Value) -> Self {
        let field = |name: &str| value.get(name).cloned();
        Self {
            applicability: field("applicability")
                .and_then(|value| serde_json::from_value(value).ok())
                .unwrap_or(MatchApplicability::Unspecified),
            matched_identity: field("matched_identity")
                .and_then(|value| serde_json::from_value(value).ok()),
        }
    }

    /// Keep applicability and identity from the same match. A purl on a
    /// weaker match cannot establish the provenance of a stronger CPE match.
    fn from_block(block: &serde_json::Value) -> Self {
        let Some(matches) = block.get("matches").and_then(|m| m.as_array()) else {
            return Self::from_value(block);
        };
        matches
            .iter()
            .map(Self::from_value)
            .max_by_key(|m| {
                (
                    m.applicability,
                    m.matched_identity
                        .as_ref()
                        .is_some_and(|identity| identity.kind == MatchedIdentityKind::Purl),
                )
            })
            .unwrap_or_else(|| Self::from_value(block))
    }
}

/// Whether `affected` is a conda-forge entry that explicitly names the
/// queried package, which is where basilisk puts its metadata.
fn is_explicit_conda_forge_match(
    affected: &OsvAffected,
    package: &PackageName,
    ecosystem: &str,
) -> bool {
    ecosystem.eq_ignore_ascii_case("conda-forge")
        && affected.package.as_ref().is_some_and(|entry| {
            entry
                .name
                .as_deref()
                .is_some_and(|name| package.matches(name))
                && entry
                    .ecosystem
                    .as_deref()
                    .is_some_and(|entry| entry.eq_ignore_ascii_case(ecosystem))
        })
}

/// Basilisk's match metadata for `package`, from the first conda-forge
/// entry that names it and carries a `basilisk` block. `None` for other
/// ecosystems and for plain OSV documents.
pub(crate) fn basilisk_match(
    doc: &OsvVulnerability,
    package: &PackageName,
    ecosystem: &str,
) -> Option<BasiliskMatch> {
    doc.affected
        .iter()
        .filter(|affected| is_explicit_conda_forge_match(affected, package, ecosystem))
        .find_map(|affected| basilisk_block(affected.database_specific.as_ref()))
        .map(BasiliskMatch::from_block)
}

/// Which entries in other ecosystems may contribute upstream fixes.
#[derive(Debug, PartialEq, Eq)]
enum CrossEcosystemRule {
    /// Any entry naming the same package.
    ByName,
    /// Only entries whose purl is this one, as [`purl_key`] compares them.
    ByPurl(String),
    /// None: the match says nothing about other ecosystems.
    Nothing,
}

impl CrossEcosystemRule {
    /// A purl identity vouches for exactly that package elsewhere; a CPE
    /// vouches for nothing outside conda-forge. Without an identity the
    /// name is trusted only when basilisk evaluated the match, or when the
    /// document is plain OSV with no basilisk metadata at all.
    fn for_match(basilisk_match: Option<&BasiliskMatch>) -> Self {
        let Some(basilisk_match) = basilisk_match else {
            return Self::ByName;
        };
        match &basilisk_match.matched_identity {
            Some(MatchedIdentity {
                kind: MatchedIdentityKind::Purl,
                value,
            }) => Self::ByPurl(purl_key(value)),
            Some(MatchedIdentity {
                kind: MatchedIdentityKind::Cpe,
                ..
            }) => Self::Nothing,
            None if basilisk_match.applicability == MatchApplicability::Evaluated => Self::ByName,
            None => Self::Nothing,
        }
    }

    fn accepts(&self, affected: &OsvAffected, package: &PackageName) -> bool {
        let entry = affected.package.as_ref();
        match self {
            Self::ByName => entry
                .and_then(|entry| entry.name.as_deref())
                .is_none_or(|name| package.matches(name)),
            Self::ByPurl(key) => entry
                .and_then(|entry| entry.purl.as_deref())
                .is_some_and(|purl| purl_key(purl) == *key),
            Self::Nothing => false,
        }
    }
}

/// The part of a purl that identifies a package: `pkg:<type>/<namespace>/
/// <name>`, without the version, qualifiers, or subpath, case-folded.
fn purl_key(purl: &str) -> String {
    let purl = purl.split(['?', '#']).next().unwrap_or_default();
    let name_start = purl.rfind('/').map_or(0, |slash| slash + 1);
    let end = purl[name_start..]
        .find('@')
        .map_or(purl.len(), |at| name_start + at);
    purl[..end]
        .trim_end_matches('/')
        .replace("%40", "@")
        .to_lowercase()
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
/// queried ecosystem (or entries naming no package) are same-ecosystem fixes.
/// Package names match under the ecosystem's own normalization, so an
/// advisory spelling `ruamel.yaml` matches a PyPI query for `ruamel-yaml`.
///
/// Entries in other ecosystems are upstream fixes only when
/// [`CrossEcosystemRule`] admits them: a same-name entry for plain OSV
/// documents and for matches basilisk evaluated, the entry whose purl
/// basilisk matched through when it recorded one, and nothing for a CPE
/// match. Basilisk's own fix metadata is considered only for conda-forge
/// queries on entries that explicitly match both the package and ecosystem.
pub(crate) fn fixed_versions(
    doc: &OsvVulnerability,
    package: &PackageName,
    ecosystem: &str,
) -> FixedVersions {
    let rule = CrossEcosystemRule::for_match(basilisk_match(doc, package, ecosystem).as_ref());
    let mut fixes = FixedVersions::default();
    for affected in &doc.affected {
        let entry_name = affected.package.as_ref().and_then(|p| p.name.as_deref());
        let entry_ecosystem = affected
            .package
            .as_ref()
            .and_then(|p| p.ecosystem.as_deref());
        let other_ecosystem =
            entry_ecosystem.filter(|entry| !entry.eq_ignore_ascii_case(ecosystem));

        let accepted = match other_ecosystem {
            // An entry naming no package applies to the queried one.
            None => entry_name.is_none_or(|name| package.matches(name)),
            Some(_) => rule.accepts(affected, package),
        };
        if !accepted {
            continue;
        }

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

        if is_explicit_conda_forge_match(affected, package, ecosystem)
            && let Some(metadata) =
                basilisk_block(affected.database_specific.as_ref()).and_then(basilisk_fix_metadata)
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

/// The Basilisk explorer page for this advisory.
pub(crate) fn basilisk_advisory_url(doc: &OsvVulnerability) -> String {
    format!("https://basilisk.prefix.dev/advisories/{}", doc.id)
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
