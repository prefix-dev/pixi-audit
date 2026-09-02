//! Audit orchestration across the Basilisk and PyPI backends.

use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;

use futures::{StreamExt, TryStreamExt};

use crate::{
    advisory::{FixedVersions, advisory_url, fixed_versions, pypi_advisory_url},
    client::{AuditError, BasiliskClient, PypiAuditClient},
    report::{
        AuditPackage, AuditReport, Finding, IgnoreReason, IgnoreSpec, PackageEcosystem,
        SeverityBand, UncheckedPackage,
    },
    types::{BatchResult, OsvQuery, OsvVulnerability, QueryPackage},
};

/// How many `GET /v1/vulns/{id}` requests to keep in flight.
const MAX_CONCURRENT_DETAIL_FETCHES: usize = 16;

/// The vulnerability database a package is checked against, together with
/// the policy for interpreting what that database returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Backend {
    /// Basilisk, which answers for conda-forge packages.
    Basilisk,
    /// OSV.dev, which answers for PyPI packages.
    Pypi,
}

impl Backend {
    const ALL: [Backend; 2] = [Backend::Basilisk, Backend::Pypi];

    /// The ecosystem string sent in queries and matched against advisories.
    fn osv_ecosystem(self) -> &'static str {
        match self {
            Backend::Basilisk => "conda-forge",
            Backend::Pypi => "PyPI",
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
            Backend::Pypi => doc
                .summary
                .as_ref()
                .map(|summary| summary.trim().replace('\n', "")),
        }
    }

    fn url(self, doc: &OsvVulnerability) -> Option<String> {
        match self {
            Backend::Basilisk => advisory_url(doc),
            Backend::Pypi => Some(pypi_advisory_url(doc)),
        }
    }

    fn fixed_versions(self, doc: &OsvVulnerability, query_name: &str) -> FixedVersions {
        let mut fixes = fixed_versions(doc, query_name, self.osv_ecosystem());
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
}

/// The clients behind each [`Backend`].
struct Backends<'a> {
    basilisk: &'a BasiliskClient,
    pypi: &'a PypiAuditClient,
}

impl Backends<'_> {
    async fn query_batch(
        &self,
        backend: Backend,
        queries: &[OsvQuery],
    ) -> Result<Vec<BatchResult>, AuditError> {
        match backend {
            Backend::Basilisk => self.basilisk.query_batch(queries).await,
            Backend::Pypi => self.pypi.query_batch(queries).await,
        }
    }

    async fn get_vuln(&self, backend: Backend, id: &str) -> Result<OsvVulnerability, AuditError> {
        match backend {
            Backend::Basilisk => self.basilisk.get_vuln(id).await,
            Backend::Pypi => self.pypi.get_vuln(id).await,
        }
    }
}

/// A package that will be queried, with the exact identity sent to its
/// backend. Only packages with a version in a supported ecosystem are
/// planned; everything else is reported as unchecked.
struct PlannedQuery {
    /// Index into the audited package list.
    package: usize,
    backend: Backend,
    /// The name as the backend knows it: lowercased for Basilisk, PEP 503
    /// normalized for PyPI.
    query_name: String,
    /// The version as sent to the backend.
    query_version: String,
    /// The version as locked, reported on findings.
    version: String,
}

impl PlannedQuery {
    fn osv_query(&self) -> OsvQuery {
        OsvQuery {
            package: QueryPackage {
                name: Some(self.query_name.clone()),
                ecosystem: Some(self.backend.osv_ecosystem().to_string()),
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
fn plan_query(index: usize, package: &AuditPackage) -> Option<PlannedQuery> {
    let version = package.version.clone()?;
    match &package.ecosystem {
        PackageEcosystem::CondaForge => Some(PlannedQuery {
            package: index,
            backend: Backend::Basilisk,
            query_name: package.name.to_lowercase(),
            query_version: version.clone(),
            version,
        }),
        // Only normalized Python names and PEP 440 versions are safe to
        // send to OSV. Invalid PyPI entries remain explicitly unchecked.
        PackageEcosystem::Pypi => {
            let name = uv_normalize::PackageName::from_str(&package.name).ok()?;
            let query_version = uv_pep440::Version::from_str(&version).ok()?;
            Some(PlannedQuery {
                package: index,
                backend: Backend::Pypi,
                query_name: name.to_string(),
                query_version: query_version.to_string(),
                version,
            })
        }
        // No backend answers for other channels or source packages.
        PackageEcosystem::Other(_) => None,
    }
}

/// Runs every planned query against its backend. The result at position
/// `i` belongs to `planned[i]`.
async fn query_backends(
    backends: &Backends<'_>,
    planned: &[PlannedQuery],
) -> Result<Vec<BatchResult>, AuditError> {
    let mut results = vec![BatchResult::default(); planned.len()];
    for backend in Backend::ALL {
        let positions: Vec<usize> = (0..planned.len())
            .filter(|&i| planned[i].backend == backend)
            .collect();
        let queries: Vec<OsvQuery> = positions.iter().map(|&i| planned[i].osv_query()).collect();
        let batch = backends.query_batch(backend, &queries).await?;
        for (position, result) in positions.into_iter().zip(batch) {
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
            match backends.get_vuln(backend, &id).await {
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
    let planned: Vec<PlannedQuery> = packages
        .iter()
        .enumerate()
        .filter_map(|(index, package)| plan_query(index, package))
        .collect();
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
    let mut report = AuditReport::default();
    let mut checked = vec![false; packages.len()];
    for (query, result) in planned.iter().zip(&results) {
        checked[query.package] = true;
        let package = &packages[query.package];
        for vuln in &result.vulns {
            let doc = documents
                .get(&(query.backend, vuln.id.clone()))
                .expect("references were collected from these same results");
            if doc.withdrawn.is_some() {
                continue;
            }
            let fixes = query.backend.fixed_versions(doc, &query.query_name);
            let finding = Finding {
                package: package.name.clone(),
                version: query.version.clone(),
                ecosystem: package.ecosystem.clone(),
                environments: package.environments.clone(),
                id: doc.id.clone(),
                aliases: doc.aliases.clone(),
                severity: query.backend.severity(doc),
                fixed_versions: fixes.same_ecosystem,
                upstream_fixed_versions: fixes.upstream,
                summary: query.backend.summary(doc),
                url: query.backend.url(doc),
                ignore_reason: None,
            };
            record_finding(&mut report, finding, &suppressions);
        }
    }
    for (package, checked) in packages.iter().zip(checked) {
        if !checked {
            report.unchecked.push(UncheckedPackage {
                package: package.name.clone(),
                version: package.version.clone(),
                ecosystem: package.ecosystem.clone(),
                environments: package.environments.clone(),
            });
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
            !finding.fixed_versions.is_empty() || !finding.upstream_fixed_versions.is_empty();
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
