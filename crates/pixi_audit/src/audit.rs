//! Audit orchestration across the Basilisk and PyPI backends.

use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;

use futures::{StreamExt, TryStreamExt};

use crate::{
    advisory::{
        BasiliskMatch, FixedVersions, advisory_url, basilisk_match, fixed_versions,
        pypi_advisory_url,
    },
    client::{AuditError, BasiliskClient, PypiAuditClient},
    report::{
        AuditPackage, AuditReport, Finding, IgnoreReason, IgnoreSpec, MatchApplicability,
        PackageEcosystem, SeverityBand, UncheckedPackage,
    },
    types::{BatchResult, OsvQuery, OsvVulnerability, QueryPackage},
};

/// How many `GET /v1/vulns/{id}` requests to keep in flight.
const MAX_CONCURRENT_DETAIL_FETCHES: usize = 16;

/// The vulnerability database a package is checked against, together with
/// the policy for interpreting what that database returns.
///
/// The discriminants index [`Backend::ALL`] and the per-backend tables in
/// [`query_backends`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Backend {
    /// Basilisk, which answers for conda-forge packages.
    Basilisk = 0,
    /// OSV.dev, which answers for PyPI packages.
    Pypi = 1,
}

impl Backend {
    const ALL: [Backend; 2] = [Backend::Basilisk, Backend::Pypi];

    /// The backend that answers for `ecosystem`, if any.
    fn for_ecosystem(ecosystem: &PackageEcosystem) -> Option<Self> {
        match ecosystem {
            PackageEcosystem::CondaForge => Some(Backend::Basilisk),
            PackageEcosystem::Pypi => Some(Backend::Pypi),
            // No backend answers for other channels or source packages.
            PackageEcosystem::Other(_) => None,
        }
    }

    /// Basilisk's batch index can briefly reference an id whose document
    /// is not served yet, so a 404 degrades to an id-only finding with
    /// unknown severity. Any other failure, and any PyPI failure, aborts
    /// the audit: a security audit must never silently drop findings.
    fn tolerates_missing_document(self) -> bool {
        matches!(self, Backend::Basilisk)
    }

    fn severity(self, doc: &OsvVulnerability) -> SeverityBand {
        match self {
            Backend::Basilisk => SeverityBand::from_severities(&doc.severity),
            // OSV.dev severity entries are not interpreted yet, so PyPI
            // findings always fail a severity threshold.
            Backend::Pypi => SeverityBand::Unknown,
        }
    }

    fn summary(self, doc: &OsvVulnerability) -> Option<String> {
        match self {
            Backend::Basilisk => doc.summary.clone(),
            // OSV.dev summaries are hard-wrapped; fold them onto one line.
            Backend::Pypi => doc
                .summary
                .as_ref()
                .map(|summary| summary.split_whitespace().collect::<Vec<_>>().join(" ")),
        }
    }

    fn url(self, doc: &OsvVulnerability) -> Option<String> {
        match self {
            Backend::Basilisk => advisory_url(doc),
            Backend::Pypi => Some(pypi_advisory_url(doc)),
        }
    }

    fn fixed_versions(self, doc: &OsvVulnerability, package: &AuditPackage) -> FixedVersions {
        let mut fixes = fixed_versions(doc, &package.name, package.ecosystem.osv_ecosystem());
        if self == Backend::Pypi {
            // Only PEP 440 versions are actionable for a PyPI package, and
            // there is no "upstream" of PyPI to report.
            fixes
                .same_ecosystem
                .retain(|version| uv_pep440::Version::from_str(version).is_ok());
            fixes.upstream.clear();
        }
        fixes
    }

    /// How the database matched the advisory to the package. Only
    /// basilisk records this.
    fn basilisk_match(
        self,
        doc: &OsvVulnerability,
        package: &AuditPackage,
    ) -> Option<BasiliskMatch> {
        match self {
            Backend::Basilisk => {
                basilisk_match(doc, &package.name, package.ecosystem.osv_ecosystem())
            }
            Backend::Pypi => None,
        }
    }
}

/// The clients behind each [`Backend`].
struct Backends<'a> {
    basilisk: &'a BasiliskClient,
    pypi: &'a PypiAuditClient,
}

impl Backends<'_> {
    fn client(&self, backend: Backend) -> &BasiliskClient {
        match backend {
            Backend::Basilisk => self.basilisk,
            Backend::Pypi => self.pypi.osv_client(),
        }
    }
}

/// A package that will be queried, with the exact identity sent to its
/// backend. Only packages with a version in a supported ecosystem are
/// planned; everything else is reported as unchecked.
struct PlannedQuery<'a> {
    package: &'a AuditPackage,
    backend: Backend,
    /// The version as sent to the backend.
    query_version: String,
    /// The version as locked, reported on findings.
    version: String,
}

impl PlannedQuery<'_> {
    fn osv_query(&self) -> OsvQuery {
        OsvQuery {
            package: QueryPackage {
                name: Some(self.package.name.to_string()),
                ecosystem: Some(self.package.ecosystem.osv_ecosystem().to_string()),
                purl: None,
            },
            version: Some(self.query_version.clone()),
            page_token: None,
        }
    }
}

/// Decides whether and how `package` is queried. A version-less package is
/// never queried: a version-less OSV query matches every version ever
/// affected.
fn plan_query(package: &AuditPackage) -> Option<PlannedQuery<'_>> {
    let version = package.version.clone()?;
    let backend = Backend::for_ecosystem(&package.ecosystem)?;
    let query_version = match backend {
        Backend::Basilisk => version.clone(),
        // Only PEP 440 versions are safe to send to OSV; a PyPI entry whose
        // version does not parse remains explicitly unchecked.
        Backend::Pypi => uv_pep440::Version::from_str(&version).ok()?.to_string(),
    };
    Some(PlannedQuery {
        package,
        backend,
        query_version,
        version,
    })
}

/// Runs every planned query against its backend, both backends in
/// parallel. The result at position `i` belongs to `planned[i]`.
async fn query_backends(
    backends: &Backends<'_>,
    planned: &[PlannedQuery<'_>],
) -> Result<Vec<BatchResult>, AuditError> {
    let mut positions: [Vec<usize>; Backend::ALL.len()] = Default::default();
    let mut queries: [Vec<OsvQuery>; Backend::ALL.len()] = Default::default();
    for (position, query) in planned.iter().enumerate() {
        positions[query.backend as usize].push(position);
        queries[query.backend as usize].push(query.osv_query());
    }
    let batches = futures::future::try_join_all(Backend::ALL.iter().map(|&backend| {
        backends
            .client(backend)
            .query_batch(&queries[backend as usize])
    }))
    .await?;

    let mut results = vec![BatchResult::default(); planned.len()];
    for (positions, batch) in positions.iter().zip(batches) {
        for (&position, result) in positions.iter().zip(batch) {
            results[position] = result;
        }
    }
    Ok(results)
}

/// Fetches each distinct referenced vulnerability document once, keyed by
/// backend because the two databases have independent id spaces.
async fn fetch_documents(
    backends: &Backends<'_>,
    references: BTreeSet<(Backend, String)>,
) -> Result<HashMap<(Backend, String), OsvVulnerability>, AuditError> {
    futures::stream::iter(references)
        .map(|(backend, id)| async move {
            match backends.client(backend).get_vuln(&id).await {
                Ok(doc) => Ok(((backend, id), doc)),
                Err(AuditError::Status { status, .. })
                    if backend.tolerates_missing_document()
                        && status == reqwest::StatusCode::NOT_FOUND =>
                {
                    let doc = OsvVulnerability {
                        id: id.clone(),
                        ..Default::default()
                    };
                    Ok(((backend, id), doc))
                }
                Err(err) => Err(err),
            }
        })
        .buffer_unordered(MAX_CONCURRENT_DETAIL_FETCHES)
        .try_collect()
        .await
}

/// Audits `packages` against the vulnerability databases, applying `ignore`
/// (vulnerability ids or aliases, case-insensitive).
///
/// There is deliberately no partial-report mode: any request failure aborts
/// the audit as a whole. See [`Backend::tolerates_missing_document`] for the
/// one exception.
pub async fn audit(
    client: &BasiliskClient,
    pypi_client: &PypiAuditClient,
    packages: Vec<AuditPackage>,
    ignore: IgnoreSpec<'_>,
) -> Result<AuditReport, AuditError> {
    let backends = Backends {
        basilisk: client,
        pypi: pypi_client,
    };
    let mut report = AuditReport::default();
    let mut planned = Vec::with_capacity(packages.len());
    for package in &packages {
        match plan_query(package) {
            Some(query) => planned.push(query),
            None => report.unchecked.push(UncheckedPackage {
                package: package.name.clone(),
                version: package.version.clone(),
                ecosystem: package.ecosystem.clone(),
                environments: package.environments.clone(),
            }),
        }
    }
    let results = query_backends(&backends, &planned).await?;

    let references: BTreeSet<(Backend, String)> = planned
        .iter()
        .zip(&results)
        .flat_map(|(query, result)| {
            result
                .vulns
                .iter()
                .map(move |vuln| (query.backend, vuln.id.clone()))
        })
        .collect();
    let documents = fetch_documents(&backends, references).await?;

    let suppressions = Suppressions::from_spec(ignore);
    for (query, result) in planned.iter().zip(&results) {
        let package = query.package;
        for vuln in &result.vulns {
            let doc = documents
                .get(&(query.backend, vuln.id.clone()))
                .expect("references were collected from these same results");
            if doc.withdrawn.is_some() {
                continue;
            }
            let fixes = query.backend.fixed_versions(doc, package);
            let basilisk_match = query.backend.basilisk_match(doc, package);
            let finding = Finding {
                package: package.name.clone(),
                version: query.version.clone(),
                ecosystem: package.ecosystem.clone(),
                environments: package.environments.clone(),
                id: doc.id.clone(),
                aliases: doc.aliases.clone(),
                severity: query.backend.severity(doc),
                fixed_versions: fixes.same_ecosystem,
                upstream_fixes: fixes.upstream,
                applicability: basilisk_match
                    .as_ref()
                    .map_or(MatchApplicability::Unspecified, |m| m.applicability),
                matched_identity: basilisk_match.and_then(|m| m.matched_identity),
                summary: query.backend.summary(doc),
                url: query.backend.url(doc),
                ignore_reason: None,
            };
            record_finding(&mut report, finding, &suppressions);
        }
    }

    let order =
        |a: &Finding, b: &Finding| b.severity.cmp(&a.severity).then(a.package.cmp(&b.package));
    report.vulnerabilities.sort_by(order);
    report.ignored.sort_by(order);

    report.summary.audited = planned.len();
    report.summary.vulnerable = report.vulnerabilities.len();
    report.summary.ignored = report.ignored.len();
    report.summary.unchecked = report.unchecked.len();
    Ok(report)
}

/// Lowercased suppression lists, ready for case-insensitive matching.
struct Suppressions {
    ignore: BTreeSet<String>,
    until_fixed: BTreeSet<String>,
}

impl Suppressions {
    fn from_spec(spec: IgnoreSpec<'_>) -> Self {
        let lowercase = |ids: &[String]| ids.iter().map(|id| id.to_lowercase()).collect();
        Self {
            ignore: lowercase(spec.ignore),
            until_fixed: lowercase(spec.ignore_until_fixed),
        }
    }

    /// Why `finding` is suppressed, if it is. `ignore` wins over
    /// `until_fixed`, and `until_fixed` lapses once any fix is known.
    fn reason_for(&self, finding: &Finding) -> Option<IgnoreReason> {
        let listed_in = |set: &BTreeSet<String>| {
            set.contains(&finding.id.to_lowercase())
                || finding
                    .aliases
                    .iter()
                    .any(|alias| set.contains(&alias.to_lowercase()))
        };
        let has_known_fix =
            !finding.fixed_versions.is_empty() || !finding.upstream_fixes.is_empty();
        if listed_in(&self.ignore) {
            Some(IgnoreReason::Always)
        } else if listed_in(&self.until_fixed) && !has_known_fix {
            Some(IgnoreReason::UntilFixed)
        } else {
            None
        }
    }
}

fn record_finding(report: &mut AuditReport, mut finding: Finding, suppressions: &Suppressions) {
    match suppressions.reason_for(&finding) {
        Some(reason) => {
            finding.ignore_reason = Some(reason);
            report.ignored.push(finding);
        }
        None => report.vulnerabilities.push(finding),
    }
}

#[cfg(test)]
mod tests;
