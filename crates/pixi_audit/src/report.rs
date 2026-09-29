//! Audit inputs and report types.

use std::cmp::Ordering;
use std::str::FromStr;

use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::{
    threat::{EpssScore, KnownExploited, RiskScore, ThreatDataStatus},
    types::OsvSeverity,
};

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

/// A parsed version carrying its ecosystem's comparison rules.
///
/// Versions from different ecosystems are incomparable. No total ordering is
/// defined: callers must handle `partial_cmp` returning `None`.
///
/// Parsing is explicit so callers can reuse a parsed value across comparisons.
/// This type does not change the string representation of versions in reports
/// or manifests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageVersion {
    Conda(rattler_conda_types::Version),
    Pypi(uv_pep440::Version),
}

/// Distinguishes malformed versions from ecosystems without comparison support.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParsePackageVersionError {
    #[error("'{version}' is not a valid {ecosystem} version")]
    InvalidVersion {
        ecosystem: PackageEcosystem,
        version: String,
    },
    #[error("version comparison is not supported for ecosystem '{0}'")]
    UnsupportedEcosystem(PackageEcosystem),
}

impl PackageVersion {
    /// Parses using the selected ecosystem, without falling back to another
    /// version format. Unsupported ecosystems return an explicit error.
    pub fn parse(
        ecosystem: &PackageEcosystem,
        value: &str,
    ) -> Result<Self, ParsePackageVersionError> {
        let invalid = || ParsePackageVersionError::InvalidVersion {
            ecosystem: ecosystem.clone(),
            version: value.to_string(),
        };
        match ecosystem {
            PackageEcosystem::CondaForge => value.parse().map(Self::Conda).map_err(|_| invalid()),
            PackageEcosystem::Pypi => value.parse().map(Self::Pypi).map_err(|_| invalid()),
            PackageEcosystem::Other(_) => Err(ParsePackageVersionError::UnsupportedEcosystem(
                ecosystem.clone(),
            )),
        }
    }
}

impl PartialOrd for PackageVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Conda(a), Self::Conda(b)) => Some(a.cmp(b)),
            (Self::Pypi(a), Self::Pypi(b)) => Some(a.cmp(b)),
            _ => None,
        }
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
            .filter_map(parse_base_score)
            .map(|(version, score)| match version {
                CvssVersion::V3 | CvssVersion::V4 => Self::from_score(score),
                // CVSS v2's qualitative scale has no critical band
                // (high is 7.0-10.0), so cap the mapping there.
                CvssVersion::V2 => Self::from_score(score).min(SeverityBand::High),
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

enum CvssVersion {
    V2,
    V3,
    V4,
}

/// The CVSS version and base score of one severity entry, when its vector
/// parses. Understands the type labels basilisk emits: `CVSS_V3`/
/// `CVSS_V3.0`/`CVSS_V3.1` (OSV and NVD sources), `CVSS_V4`, and `CVSS_V2.0`.
fn parse_base_score(severity: &OsvSeverity) -> Option<(CvssVersion, f64)> {
    if severity.kind.starts_with("CVSS_V3") {
        let base = severity.score.parse::<cvss::v3::Base>().ok()?;
        Some((CvssVersion::V3, base.score().value()))
    } else if severity.kind.starts_with("CVSS_V4") {
        let vector = severity.score.parse::<cvss::v4::Vector>().ok()?;
        Some((CvssVersion::V4, vector.score().value()))
    } else if severity.kind.starts_with("CVSS_V2") {
        let score = crate::cvss_v2::base_score(&severity.score)?;
        Some((CvssVersion::V2, score))
    } else {
        None
    }
}

/// The mean CVSS base score across the entries whose vectors parse, or
/// `None` when there is none. A zero score is not a valid base score and
/// is left out so it cannot drag the mean down.
pub fn mean_cvss_base_score(severities: &[OsvSeverity]) -> Option<f64> {
    let scores: Vec<f64> = severities
        .iter()
        .filter_map(parse_base_score)
        .map(|(_, score)| score)
        .filter(|score| *score > 0.0)
        .collect();
    if scores.is_empty() {
        None
    } else {
        Some(scores.iter().sum::<f64>() / scores.len() as f64)
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
    /// Rules scoped by package, ecosystem or installed version.
    pub package_rules: &'a [PackageIgnore],
    /// Suppress every finding for which no fixed release is known, as if
    /// each were listed in `ignore_until_fixed`.
    pub ignore_unfixed: bool,
}

/// Package, ecosystem and installed-version predicates shared by ignore rules.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgnoreScope {
    pub package: Option<String>,
    pub ecosystem: Option<String>,
    pub version: Option<String>,
    #[serde(rename = "max-affected-version")]
    pub max_affected_version: Option<String>,
}

impl IgnoreScope {
    pub fn is_empty(&self) -> bool {
        self.package.is_none()
            && self.ecosystem.is_none()
            && self.version.is_none()
            && self.max_affected_version.is_none()
    }

    pub fn validate(&self) -> Result<(), String> {
        let ecosystem = self.ecosystem.as_deref();
        if let Some(ecosystem) = ecosystem
            && !ecosystem.eq_ignore_ascii_case("conda-forge")
            && !ecosystem.eq_ignore_ascii_case("pypi")
        {
            return Err(format!(
                "unsupported ecosystem '{}' (expected conda-forge or PyPI)",
                ecosystem.to_ascii_lowercase()
            ));
        }
        for version in [
            self.version.as_deref(),
            self.max_affected_version.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let valid = match ecosystem {
                Some(value) if value.eq_ignore_ascii_case("conda-forge") => {
                    PackageVersion::parse(&PackageEcosystem::CondaForge, version).is_ok()
                }
                Some(_) => PackageVersion::parse(&PackageEcosystem::Pypi, version).is_ok(),
                None => {
                    PackageVersion::parse(&PackageEcosystem::CondaForge, version).is_ok()
                        || PackageVersion::parse(&PackageEcosystem::Pypi, version).is_ok()
                }
            };
            if !valid {
                return Err(format!(
                    "invalid version '{version}' for the selected ecosystem"
                ));
            }
        }
        Ok(())
    }

    pub fn matches(&self, finding: &Finding) -> bool {
        if !self
            .package
            .as_ref()
            .is_none_or(|package| finding.package.matches(package))
            || !self.ecosystem.as_ref().is_none_or(|ecosystem| {
                finding
                    .ecosystem
                    .osv_ecosystem()
                    .eq_ignore_ascii_case(ecosystem)
            })
        {
            return false;
        }
        if self.version.is_none() && self.max_affected_version.is_none() {
            return true;
        }
        let Ok(locked) = PackageVersion::parse(&finding.ecosystem, &finding.version) else {
            return false;
        };
        self.version.as_deref().is_none_or(|version| {
            PackageVersion::parse(&finding.ecosystem, version).is_ok_and(|bound| locked == bound)
        }) && self.max_affected_version.as_deref().is_none_or(|version| {
            PackageVersion::parse(&finding.ecosystem, version).is_ok_and(|bound| {
                matches!(
                    locked.partial_cmp(&bound),
                    Some(Ordering::Less | Ordering::Equal)
                )
            })
        })
    }
}

/// A suppression optionally scoped to package, ecosystem and locked version.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PackageIgnore {
    pub id: Option<String>,
    pub scope: IgnoreScope,
    /// Suppress only while no fixed release is known.
    pub until_fixed: bool,
}

impl PackageIgnore {
    pub fn applies_to(&self, finding: &Finding) -> bool {
        (self.id.is_some() || self.scope.package.is_some())
            && self.id.as_ref().is_none_or(|id| {
                std::iter::once(&finding.id)
                    .chain(&finding.aliases)
                    .any(|candidate| candidate.eq_ignore_ascii_case(id))
            })
            && self.scope.matches(finding)
    }
}

/// What basilisk knows about a conda-forge build of a fixed release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all(serialize = "kebab-case", deserialize = "snake_case"))]
pub enum CondaPublication {
    Published,
    NotPublished,
    Unknown,
}

/// How the advisory's version data matched the audited conda-forge package.
/// Orders matches by specificity so the maximum is the strongest one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all(serialize = "kebab-case", deserialize = "snake_case"))]
pub enum MatchApplicability {
    /// Basilisk recorded no applicability: PyPI findings, and documents
    /// whose conda-forge entry carries no basilisk metadata.
    #[serde(skip_deserializing)]
    Unspecified,
    /// The advisory names the vendor and product (a CPE match) but gives
    /// no version bounds basilisk could apply, so every version matches.
    VersionUnbounded,
    /// The package matched but the affected versions were not evaluated.
    Unevaluated,
    /// The installed version matches the advisory's affected version data.
    Evaluated,
}

/// The kind of identifier an advisory was matched to the package through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchedIdentityKind {
    /// A package URL, such as `pkg:npm/pnpm`: the advisory is about that
    /// exact package in that ecosystem.
    Purl,
    /// A CPE name from NVD: a vendor and product, with no ecosystem.
    Cpe,
}

/// The identifier basilisk matched an advisory to the conda-forge package
/// through. Fixes in other ecosystems are only trusted when they belong to
/// this identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedIdentity {
    pub kind: MatchedIdentityKind,
    pub value: String,
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
    /// Mean CVSS base score across the advisory's parsable severity entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_base_score: Option<f64>,
    /// Fixed versions in the package's own ecosystem.
    pub fixed_versions: Vec<String>,
    /// Fixes known outside the package's own ecosystem, each with where it
    /// exists. Informative only; `--fix` cannot install these.
    pub upstream_fixes: Vec<UpstreamFix>,
    /// How confidently basilisk matched the advisory to the package.
    /// `Unspecified` for PyPI findings and documents without metadata.
    pub applicability: MatchApplicability,
    /// The identifier basilisk matched the advisory through, when known.
    pub matched_identity: Option<MatchedIdentity>,
    pub summary: Option<String>,
    pub url: Option<String>,
    /// EPSS records for the finding's CVE ids, sorted by CVE.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub epss: Vec<EpssScore>,
    /// KEV catalog entries for the finding's CVE ids.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub known_exploited: Vec<KnownExploited>,
    pub risk: RiskScore,
    /// Set only on findings in the ignored bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_reason: Option<IgnoreReason>,
}

impl Finding {
    /// The finding's CVE ids: its own id and any CVE alias, deduplicated
    /// case-insensitively and upper-cased.
    pub fn cve_ids(&self) -> Vec<String> {
        let mut cves: Vec<String> = std::iter::once(&self.id)
            .chain(&self.aliases)
            .filter(|id| id.len() > 4 && id[..4].eq_ignore_ascii_case("CVE-"))
            .map(|id| id.to_ascii_uppercase())
            .collect();
        cves.sort();
        cves.dedup();
        cves
    }

    /// Where the finding's fix stands.
    pub fn fix_status(&self) -> FixStatus {
        if !self.fixed_versions.is_empty() {
            FixStatus::Available
        } else if !self.upstream_fixes.is_empty() {
            FixStatus::UpstreamOnly
        } else {
            FixStatus::Unfixed
        }
    }
}

/// Where a finding's fix stands, from [`Finding::fix_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixStatus {
    /// A fixed release exists in the package's own ecosystem.
    Available,
    /// Fixes exist only outside the package's own ecosystem, so they may
    /// not be installable for it.
    UpstreamOnly,
    /// No fix is known anywhere.
    Unfixed,
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
    /// Ignore ids and scoped rules that matched no finding. An expired
    /// package or version exception remains visible after an upgrade.
    pub unmatched_ignores: Vec<String>,
    pub threat_data: ThreatDataStatus,
}

impl AuditReport {
    /// Orders the vulnerable and ignored findings by `strategy`.
    pub fn sort(&mut self, strategy: SortStrategy) {
        self.vulnerabilities.sort_by(|a, b| strategy.compare(a, b));
        self.ignored.sort_by(|a, b| strategy.compare(a, b));
    }
}

/// How findings are ordered in a report. Every strategy is a total order:
/// after its primary key it falls through the remaining keys so equal
/// findings keep a stable, predictable order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortStrategy {
    /// Highest [`RiskScore`] first.
    #[default]
    Risk,
    /// Highest [`SeverityBand`] first.
    Severity,
    /// Highest EPSS percentile first.
    Epss,
    /// KEV-listed findings first.
    Kev,
    /// Package name, version, and ecosystem.
    Package,
    /// Vulnerability id.
    Vulnerability,
}

impl SortStrategy {
    pub const ALL: [SortStrategy; 6] = [
        SortStrategy::Risk,
        SortStrategy::Severity,
        SortStrategy::Epss,
        SortStrategy::Kev,
        SortStrategy::Package,
        SortStrategy::Vulnerability,
    ];

    pub fn name(self) -> &'static str {
        match self {
            SortStrategy::Risk => "risk",
            SortStrategy::Severity => "severity",
            SortStrategy::Epss => "epss",
            SortStrategy::Kev => "kev",
            SortStrategy::Package => "package",
            SortStrategy::Vulnerability => "vulnerability",
        }
    }

    pub fn compare(self, a: &Finding, b: &Finding) -> Ordering {
        type Key = fn(&Finding, &Finding) -> Ordering;
        let keys: &[Key] = match self {
            SortStrategy::Risk => &[by_risk, by_severity, by_epss_percentile, by_package, by_id],
            SortStrategy::Severity => {
                &[by_severity, by_risk, by_epss_percentile, by_package, by_id]
            }
            SortStrategy::Epss => &[by_epss_percentile, by_risk, by_severity, by_package, by_id],
            SortStrategy::Kev => &[
                by_kev,
                by_risk,
                by_severity,
                by_epss_percentile,
                by_package,
                by_id,
            ],
            SortStrategy::Package => &[by_package, by_id, by_risk, by_severity, by_epss_percentile],
            SortStrategy::Vulnerability => {
                &[by_id, by_risk, by_severity, by_epss_percentile, by_package]
            }
        };
        keys.iter()
            .map(|key| key(a, b))
            .find(|ordering| ordering.is_ne())
            .unwrap_or(Ordering::Equal)
    }
}

impl std::fmt::Display for SortStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for SortStrategy {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        SortStrategy::ALL
            .into_iter()
            .find(|strategy| strategy.name() == name)
            .ok_or_else(|| {
                let options: Vec<&str> = SortStrategy::ALL.iter().map(|s| s.name()).collect();
                format!(
                    "'{name}' is not a sort strategy (expected one of {})",
                    options.join(", ")
                )
            })
    }
}

fn by_risk(a: &Finding, b: &Finding) -> Ordering {
    b.risk.cmp(&a.risk)
}

fn by_severity(a: &Finding, b: &Finding) -> Ordering {
    b.severity.cmp(&a.severity)
}

fn by_epss_percentile(a: &Finding, b: &Finding) -> Ordering {
    let percentile = |finding: &Finding| {
        finding
            .epss
            .iter()
            .max_by(|left, right| left.epss.total_cmp(&right.epss))
            .map(|score| score.percentile)
            .unwrap_or(0.0)
    };
    percentile(b).total_cmp(&percentile(a))
}

fn by_kev(a: &Finding, b: &Finding) -> Ordering {
    b.known_exploited.len().cmp(&a.known_exploited.len())
}

/// By spelling, not by [`PackageName`]'s ecosystem-first derive.
fn by_package(a: &Finding, b: &Finding) -> Ordering {
    a.package
        .as_str()
        .cmp(b.package.as_str())
        .then_with(|| a.version.cmp(&b.version))
        .then_with(|| a.ecosystem.cmp(&b.ecosystem))
}

fn by_id(a: &Finding, b: &Finding) -> Ordering {
    a.id.cmp(&b.id)
}

#[cfg(test)]
mod tests;
