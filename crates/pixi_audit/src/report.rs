//! Audit inputs and report types.

use std::str::FromStr;

use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::types::OsvSeverity;

// Keep the established `pixi_audit::report::audit` path while the engine
// lives in its own module.
pub use crate::audit::audit;

/// Where a locked package comes from, for vulnerability-query purposes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PackageEcosystem {
    /// A conda package from the conda-forge channel. The only ecosystem
    /// basilisk's query API answers for today.
    CondaForge,
    /// A PyPI package.
    Pypi,
    /// A conda package from another channel (e.g. bioconda), or a source
    /// package. The contained string is a human-readable origin.
    Other(String),
}

impl PackageEcosystem {
    /// Classifies a conda channel URL: conda-forge is the only ecosystem the
    /// vulnerability database can currently answer for; anything else is
    /// `Other` named after the channel. A label (`<channel>/label/<name>`)
    /// publishes builds of the same packages under the same versions, so it
    /// belongs to its channel's ecosystem.
    pub fn from_channel_url(channel_url: Option<&str>) -> Self {
        let Some(url) = channel_url else {
            return PackageEcosystem::Other("unknown".to_string());
        };
        let trimmed = url.trim_end_matches('/');
        let channel = trimmed
            .rsplit_once("/label/")
            .map_or(trimmed, |(channel, _label)| channel);
        if channel.ends_with("/conda-forge") {
            PackageEcosystem::CondaForge
        } else {
            let name = channel.rsplit('/').next().unwrap_or("unknown");
            PackageEcosystem::Other(name.to_string())
        }
    }

    /// The ecosystem string sent in OSV queries.
    pub fn osv_ecosystem(&self) -> &str {
        match self {
            PackageEcosystem::CondaForge => "conda-forge",
            PackageEcosystem::Pypi => "PyPI",
            PackageEcosystem::Other(origin) => origin,
        }
    }
}

/// Displays as the OSV ecosystem string (`conda-forge`, `PyPI`, or the
/// channel name). JSON output serializes the same string.
impl std::fmt::Display for PackageEcosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.osv_ecosystem())
    }
}

impl Serialize for PackageEcosystem {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// A package name that carries its ecosystem's normalization rules, so two
/// spellings compare equal exactly when the ecosystem says they do. Conda
/// names are lowercased; PyPI names follow PEP 503, under which
/// `Ruamel.YAML`, `ruamel_yaml`, and `ruamel-yaml` are one package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PackageName {
    Conda(rattler_conda_types::PackageName),
    Pypi(uv_normalize::PackageName),
}

#[derive(Debug, Clone, Error)]
pub enum InvalidPackageName {
    #[error("'{name}' is not a valid conda package name")]
    Conda {
        name: String,
        #[source]
        source: rattler_conda_types::InvalidPackageNameError,
    },
    #[error("'{name}' is not a valid PyPI package name")]
    Pypi {
        name: String,
        #[source]
        source: uv_normalize::InvalidNameError,
    },
}

impl PackageName {
    /// Parses a conda package name, lowercasing it.
    pub fn conda(name: &str) -> Result<Self, InvalidPackageName> {
        rattler_conda_types::PackageName::from_str(name)
            .map(Self::Conda)
            .map_err(|source| InvalidPackageName::Conda {
                name: name.to_string(),
                source,
            })
    }

    /// Parses a PyPI package name, normalizing it per PEP 503.
    pub fn pypi(name: &str) -> Result<Self, InvalidPackageName> {
        uv_normalize::PackageName::from_str(name)
            .map(Self::Pypi)
            .map_err(|source| InvalidPackageName::Pypi {
                name: name.to_string(),
                source,
            })
    }

    /// Parses `name` with the rules of `ecosystem`: PyPI names follow
    /// PEP 503, every other ecosystem is a conda channel.
    pub fn parse(ecosystem: &PackageEcosystem, name: &str) -> Result<Self, InvalidPackageName> {
        match ecosystem {
            PackageEcosystem::Pypi => Self::pypi(name),
            PackageEcosystem::CondaForge | PackageEcosystem::Other(_) => Self::conda(name),
        }
    }

    /// The normalized name, as sent in queries and written to reports.
    pub fn as_str(&self) -> &str {
        match self {
            PackageName::Conda(name) => name.as_normalized(),
            PackageName::Pypi(name) => name.as_str(),
        }
    }

    /// Whether `spelling`, as written in an advisory or a manifest, names
    /// this package under the ecosystem's normalization rules.
    pub fn matches(&self, spelling: &str) -> bool {
        match self {
            PackageName::Conda(name) => name.as_normalized().eq_ignore_ascii_case(spelling),
            PackageName::Pypi(name) => {
                uv_normalize::PackageName::from_str(spelling).is_ok_and(|other| other == *name)
            }
        }
    }
}

/// Displays as the normalized name. JSON output serializes the same string.
impl std::fmt::Display for PackageName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for PackageName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// A deduplicated locked package to audit.
#[derive(Debug, Clone)]
pub struct AuditPackage {
    pub name: PackageName,
    /// `None` when the version could not be determined (e.g. an unresolved
    /// conda source package). Such packages are never queried — a
    /// version-less OSV query matches every version ever affected — and are
    /// always reported as unchecked.
    pub version: Option<String>,
    pub ecosystem: PackageEcosystem,
    /// Environments (across all platforms) that contain this exact package.
    pub environments: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityBand {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityBand {
    /// Every band, least severe first.
    pub const ALL: [SeverityBand; 5] = [
        SeverityBand::Unknown,
        SeverityBand::Low,
        SeverityBand::Medium,
        SeverityBand::High,
        SeverityBand::Critical,
    ];

    /// The band's lowercase name, as used in JSON output and on the command
    /// line.
    pub fn name(self) -> &'static str {
        match self {
            SeverityBand::Critical => "critical",
            SeverityBand::High => "high",
            SeverityBand::Medium => "medium",
            SeverityBand::Low => "low",
            SeverityBand::Unknown => "unknown",
        }
    }

    /// The highest CVSS band across the document's severity entries.
    /// Understands the type labels basilisk emits: `CVSS_V3`/`CVSS_V3.0`/
    /// `CVSS_V3.1` (OSV and NVD sources), `CVSS_V4`, and `CVSS_V2.0`.
    /// Bands follow basilisk: critical >= 9.0, high >= 7.0, medium >= 4.0.
    pub fn from_severities(severities: &[OsvSeverity]) -> Self {
        severities
            .iter()
            .filter_map(|s| {
                if s.kind.starts_with("CVSS_V3") {
                    let base = s.score.parse::<cvss::v3::Base>().ok()?;
                    Some(Self::from_score(base.score().value()))
                } else if s.kind.starts_with("CVSS_V4") {
                    let vector = s.score.parse::<cvss::v4::Vector>().ok()?;
                    Some(Self::from_score(vector.score().value()))
                } else if s.kind.starts_with("CVSS_V2") {
                    // CVSS v2's qualitative scale has no critical band
                    // (high is 7.0-10.0), so cap the mapping there.
                    let score = crate::cvss_v2::base_score(&s.score)?;
                    Some(Self::from_score(score).min(SeverityBand::High))
                } else {
                    None
                }
            })
            .max()
            .unwrap_or(SeverityBand::Unknown)
    }

    fn from_score(score: f64) -> Self {
        match score {
            s if s >= 9.0 => SeverityBand::Critical,
            s if s >= 7.0 => SeverityBand::High,
            s if s >= 4.0 => SeverityBand::Medium,
            _ => SeverityBand::Low,
        }
    }
}

impl std::fmt::Display for SeverityBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("'{0}' is not a severity band")]
pub struct ParseSeverityBandError(String);

/// Parses the exact lowercase band names produced by [`SeverityBand::name`].
impl FromStr for SeverityBand {
    type Err = ParseSeverityBandError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|band| band.name() == s)
            .ok_or_else(|| ParseSeverityBandError(s.to_string()))
    }
}

/// Which suppression list put a finding into the ignored bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IgnoreReason {
    /// Listed in the unconditional ignore list.
    Always,
    /// Listed in the ignore-until-fixed list and no fix is known yet. The
    /// finding resurfaces once any fixed version (own ecosystem or
    /// upstream) is published.
    UntilFixed,
}

/// Suppression lists applied during an audit. Ids/aliases match
/// case-insensitively; `ignore` wins when an id appears in both lists.
#[derive(Debug, Default, Clone, Copy)]
pub struct IgnoreSpec<'a> {
    /// Always suppress these vulnerability ids/aliases.
    pub ignore: &'a [String],
    /// Suppress these only while no fixed release is known.
    pub ignore_until_fixed: &'a [String],
}

/// What basilisk knows about a conda-forge build of a fixed release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all(serialize = "kebab-case", deserialize = "snake_case"))]
pub enum CondaPublication {
    Published,
    NotPublished,
    Unknown,
}

/// Where a fix exists when it is not a release in the audited ecosystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "origin", rename_all = "kebab-case")]
pub enum UpstreamOrigin {
    /// The same package has a fixed release in another ecosystem, such as
    /// the PyPI release of a package audited from conda-forge.
    Ecosystem { ecosystem: String },
    /// The project itself released the fix. This comes from advisories
    /// matched by CPE, where no ecosystem is involved; `conda_publication`
    /// says whether basilisk could find a conda-forge build of it, and is
    /// never `Published` here since that counts as a fixed version.
    Project { conda_publication: CondaPublication },
}

/// A fix that exists somewhere other than the audited ecosystem.
/// Informative only: it may not be installable for the audited package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamFix {
    pub version: String,
    #[serde(flatten)]
    pub origin: UpstreamOrigin,
}

/// One (package, vulnerability) pair.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub package: PackageName,
    pub version: String,
    pub ecosystem: PackageEcosystem,
    pub environments: Vec<String>,
    pub id: String,
    pub aliases: Vec<String>,
    pub severity: SeverityBand,
    /// Fixed versions in the package's own ecosystem.
    pub fixed_versions: Vec<String>,
    /// Fixes known outside the package's own ecosystem, each with where it
    /// exists. Informative only; `--fix` cannot install these.
    pub upstream_fixes: Vec<UpstreamFix>,
    pub summary: Option<String>,
    pub url: Option<String>,
    /// Set only on findings in the ignored bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_reason: Option<IgnoreReason>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UncheckedPackage {
    pub package: PackageName,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub ecosystem: PackageEcosystem,
    pub environments: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditSummary {
    /// Packages in an ecosystem the database can answer for.
    pub audited: usize,
    pub vulnerable: usize,
    pub ignored: usize,
    pub unchecked: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditReport {
    pub vulnerabilities: Vec<Finding>,
    pub ignored: Vec<Finding>,
    pub unchecked: Vec<UncheckedPackage>,
    pub summary: AuditSummary,
    /// Ids from the ignore lists that matched no finding's id or alias, as
    /// written and without duplicates. Usually a suppression left behind
    /// after the package was upgraded.
    pub unmatched_ignores: Vec<String>,
}

#[cfg(test)]
mod tests;
