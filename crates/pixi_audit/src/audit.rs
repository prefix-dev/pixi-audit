//! Audit orchestration across the Basilisk and PyPI backends, plus the
//! threat-data enrichment of the resulting findings.

use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;

use futures::{StreamExt, TryStreamExt};

use crate::{
    advisory::{
        BasiliskMatch, FixedVersions, basilisk_advisory_url, basilisk_match, fixed_versions,
        pypi_advisory_url,
    },
    client::{AuditError, BasiliskClient, EpssClient, KevCatalog, KevClient, PypiAuditClient},
    report::{
        AuditPackage, AuditReport, CondaPublication, Finding, IgnoreReason, IgnoreSpec,
        MatchApplicability, PackageEcosystem, PackageIgnore, SeverityBand, SortStrategy,
        UncheckedPackage, UpstreamFix, UpstreamOrigin, mean_cvss_base_score,
    },
    threat::{EpssScore, RiskScore, ThreatDataStatus, ThreatSourceStatus, ThreatSources},
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
        Some(match self {
            Backend::Basilisk => basilisk_advisory_url(doc),
            Backend::Pypi => pypi_advisory_url(doc),
        })
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
        } else if matches!(package.name.as_str(), "python" | "libpython")
            && let Some(locked) = package.version.as_deref().and_then(python_release_line)
        {
            // CPython minor versions are maintained as separate release
            // lines. A published 3.15 fix is not a patch for Python 3.13.
            let other_lines = fixes.same_ecosystem.extract_if(.., |version| {
                python_release_line(version).is_some_and(|line| line != locked)
            });
            fixes
                .upstream
                .extend(other_lines.map(|version| UpstreamFix {
                    version,
                    origin: UpstreamOrigin::OtherReleaseLine {
                        conda_publication: CondaPublication::Published,
                    },
                }));
            for fix in &mut fixes.upstream {
                if python_release_line(&fix.version).is_some_and(|line| line != locked)
                    && let UpstreamOrigin::Project { conda_publication } = &fix.origin
                {
                    fix.origin = UpstreamOrigin::OtherReleaseLine {
                        conda_publication: *conda_publication,
                    };
                }
            }
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

fn python_release_line(version: &str) -> Option<(&str, &str)> {
    let (major, rest) = version.split_once('.')?;
    let minor = rest.split('.').next()?;
    major.parse::<u8>().ok()?;
    minor.parse::<u8>().ok()?;
    Some((major, minor))
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
/// (vulnerability ids or aliases, case-insensitive), and attaches EPSS and
/// KEV data from `threat` to every finding.
///
/// There is deliberately no partial-report mode: any request failure aborts
/// the audit as a whole. See [`Backend::tolerates_missing_document`] for the
/// one exception.
///
/// Threat data only ranks findings, so it degrades instead: a source that
/// cannot be fetched is recorded in the report's [`ThreatDataStatus`] and
/// the findings are reported without it.
pub async fn audit(
    client: &BasiliskClient,
    pypi_client: &PypiAuditClient,
    packages: Vec<AuditPackage>,
    ignore: IgnoreSpec<'_>,
    threat: ThreatSources<'_>,
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
    // The KEV catalog does not depend on the findings, so it downloads
    // while the vulnerability backends are queried.
    let (results, (kev_status, kev_catalog)) = futures::future::join(
        query_backends(&backends, &planned),
        load_kev_catalog(threat.kev),
    )
    .await;
    let results = results?;

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

    let mut suppressions = Suppressions::from_spec(ignore);
    for (query, result) in planned.iter().zip(&results) {
        let mut findings = Vec::with_capacity(result.vulns.len());
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
                severity: SeverityBand::from_severities(&doc.severity),
                cvss_base_score: mean_cvss_base_score(&doc.severity),
                fixed_versions: fixes.same_ecosystem,
                upstream_fixes: fixes.upstream,
                applicability: basilisk_match
                    .as_ref()
                    .map_or(MatchApplicability::Unspecified, |m| m.applicability),
                matched_identity: basilisk_match.and_then(|m| m.matched_identity),
                summary: query.backend.summary(doc),
                url: query.backend.url(doc),
                epss: Vec::new(),
                known_exploited: Vec::new(),
                risk: RiskScore::NONE,
                ignore_reason: None,
            };
            findings.push(finding);
        }
        for finding in coalesce_findings(findings) {
            record_finding(&mut report, finding, &mut suppressions);
        }
    }
    report.unmatched_ignores = suppressions.unmatched(ignore);

    let epss_status = attach_threat_data(&mut report, threat.epss, &kev_catalog).await;
    report.threat_data = ThreatDataStatus {
        epss: epss_status,
        kev: kev_status,
    };
    report.sort(SortStrategy::default());

    report.summary.audited = planned.len();
    report.summary.vulnerable = report.vulnerabilities.len();
    report.summary.ignored = report.ignored.len();
    report.summary.unchecked = report.unchecked.len();
    Ok(report)
}

async fn load_kev_catalog(client: Option<&KevClient>) -> (ThreatSourceStatus, KevCatalog) {
    let Some(client) = client else {
        return (ThreatSourceStatus::Disabled, KevCatalog::default());
    };
    match client.catalog().await {
        Ok(catalog) => {
            let date = catalog.date_released().map(str::to_string);
            (ThreatSourceStatus::Loaded { date }, catalog)
        }
        Err(err) => (
            ThreatSourceStatus::Failed {
                error: error_chain(&err),
            },
            KevCatalog::default(),
        ),
    }
}

/// Looks up EPSS scores for every CVE across the report's findings, attaches
/// them together with the KEV entries from `kev`, and computes each
/// finding's risk. Returns the EPSS source's status.
async fn attach_threat_data(
    report: &mut AuditReport,
    epss_client: Option<&EpssClient>,
    kev: &KevCatalog,
) -> ThreatSourceStatus {
    let cves: Vec<String> = report
        .vulnerabilities
        .iter()
        .chain(&report.ignored)
        .flat_map(Finding::cve_ids)
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();
    let (epss_status, epss_scores): (ThreatSourceStatus, HashMap<String, EpssScore>) =
        match epss_client {
            None => (ThreatSourceStatus::Disabled, HashMap::new()),
            Some(client) => match client.scores(&cves).await {
                Ok(scores) => {
                    let date = scores.first().map(|score| score.date.clone());
                    let by_cve = scores
                        .into_iter()
                        .map(|score| (score.cve.to_ascii_uppercase(), score))
                        .collect();
                    (ThreatSourceStatus::Loaded { date }, by_cve)
                }
                Err(err) => (
                    ThreatSourceStatus::Failed {
                        error: error_chain(&err),
                    },
                    HashMap::new(),
                ),
            },
        };

    for finding in report
        .vulnerabilities
        .iter_mut()
        .chain(report.ignored.iter_mut())
    {
        let cves = finding.cve_ids();
        finding.epss = cves
            .iter()
            .filter_map(|cve| epss_scores.get(cve).cloned())
            .collect();
        finding.known_exploited = cves
            .iter()
            .filter_map(|cve| kev.get(cve).cloned())
            .collect();
        finding.risk = RiskScore::compute(
            finding.severity,
            finding.cvss_base_score,
            &finding.epss,
            &finding.known_exploited,
        );
    }
    epss_status
}

/// The error and every cause below it, joined for a one-line status.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// Merge documents that share an id or alias for the same queried package.
/// An alias may connect two groups only after both have been seen.
fn coalesce_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut groups: Vec<Option<Finding>> = Vec::new();
    let mut by_id = HashMap::<String, usize>::new();
    for finding in findings {
        let matches: BTreeSet<usize> = std::iter::once(&finding.id)
            .chain(&finding.aliases)
            .filter_map(|id| by_id.get(&id.to_ascii_lowercase()).copied())
            .collect();
        let index = if let Some(&index) = matches.first() {
            merge_finding(groups[index].as_mut().expect("live group"), finding);
            for other in matches.into_iter().filter(|other| *other != index) {
                let previous = groups[other].take().expect("live group");
                merge_finding(groups[index].as_mut().expect("live group"), previous);
            }
            index
        } else {
            let index = groups.len();
            groups.push(Some(finding));
            index
        };
        let group = groups[index].as_ref().expect("live group");
        for id in std::iter::once(&group.id).chain(&group.aliases) {
            by_id.insert(id.to_ascii_lowercase(), index);
        }
    }
    groups.into_iter().flatten().collect()
}

fn merge_finding(into: &mut Finding, other: Finding) {
    into.aliases.push(other.id);
    into.aliases.extend(other.aliases);
    into.aliases.retain(|id| !id.eq_ignore_ascii_case(&into.id));
    into.aliases.sort_unstable();
    into.aliases.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    into.severity = into.severity.max(other.severity);
    into.cvss_base_score = match (into.cvss_base_score, other.cvss_base_score) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    for fixed in other.fixed_versions {
        if !into.fixed_versions.contains(&fixed) {
            into.fixed_versions.push(fixed);
        }
    }
    for fixed in other.upstream_fixes {
        if !into.upstream_fixes.contains(&fixed) {
            into.upstream_fixes.push(fixed);
        }
    }
    into.applicability = into.applicability.min(other.applicability);
    if into.matched_identity != other.matched_identity {
        into.matched_identity = None;
    }
    into.summary = into.summary.take().or(other.summary);
    into.url = into.url.take().or(other.url);
}

/// Lowercased suppression lists, ready for case-insensitive matching, the
/// package-scoped rules, and a record of which ids matched a finding.
struct Suppressions<'a> {
    ignore: BTreeSet<String>,
    until_fixed: BTreeSet<String>,
    package_rules: &'a [PackageIgnore],
    ignore_unfixed: bool,
    /// Lowercased ids from either list that matched a finding's id or
    /// alias, whether or not that finding ended up suppressed: an
    /// `until_fixed` id for a finding with a known fix has still matched.
    matched: BTreeSet<String>,
    matched_rules: BTreeSet<usize>,
}

impl<'a> Suppressions<'a> {
    fn from_spec(spec: IgnoreSpec<'a>) -> Self {
        let lowercase = |ids: &[String]| ids.iter().map(|id| id.to_lowercase()).collect();
        Self {
            ignore: lowercase(spec.ignore),
            until_fixed: lowercase(spec.ignore_until_fixed),
            package_rules: spec.package_rules,
            ignore_unfixed: spec.ignore_unfixed,
            matched: BTreeSet::new(),
            matched_rules: BTreeSet::new(),
        }
    }

    /// The lowercased id or alias of `finding` that `set` lists, if any.
    fn listed_in(set: &BTreeSet<String>, finding: &Finding) -> Option<String> {
        std::iter::once(&finding.id)
            .chain(&finding.aliases)
            .map(|id| id.to_lowercase())
            .find(|id| set.contains(id))
    }

    /// Why `finding` is suppressed, if it is. An unconditional rule, by id
    /// or by package, wins over an until-fixed one, and until-fixed rules
    /// lapse once any fix is known.
    fn reason_for(&mut self, finding: &Finding) -> Option<IgnoreReason> {
        let ignored = Self::listed_in(&self.ignore, finding);
        let until_fixed = Self::listed_in(&self.until_fixed, finding);
        self.matched
            .extend(ignored.iter().chain(until_fixed.iter()).cloned());
        let mut always = false;
        let mut until_fix = false;
        for (index, rule) in self.package_rules.iter().enumerate() {
            if rule.applies_to(finding) {
                self.matched_rules.insert(index);
                if rule.until_fixed {
                    until_fix = true;
                } else {
                    always = true;
                }
            }
        }
        let has_known_fix =
            !finding.fixed_versions.is_empty() || !finding.upstream_fixes.is_empty();
        if ignored.is_some() || always {
            Some(IgnoreReason::Always)
        } else if (self.ignore_unfixed || until_fixed.is_some() || until_fix) && !has_known_fix {
            Some(IgnoreReason::UntilFixed)
        } else {
            None
        }
    }

    /// The ids of `spec` that matched no finding, in their original
    /// spelling and order, each once.
    fn unmatched(&self, spec: IgnoreSpec<'_>) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut unmatched: Vec<String> = spec
            .ignore
            .iter()
            .chain(spec.ignore_until_fixed)
            .filter(|id| {
                let lowercase = id.to_lowercase();
                !self.matched.contains(&lowercase) && seen.insert(lowercase)
            })
            .cloned()
            .collect();
        for (index, rule) in self.package_rules.iter().enumerate() {
            if !self.matched_rules.contains(&index) {
                let mut parts = Vec::new();
                if let Some(id) = &rule.id {
                    parts.push(id.clone());
                }
                if let Some(package) = &rule.package {
                    parts.push(format!("package '{package}'"));
                }
                if let Some(ecosystem) = &rule.ecosystem {
                    parts.push(format!("ecosystem '{ecosystem}'"));
                }
                if let Some(version) = &rule.version {
                    parts.push(format!("version '{version}'"));
                }
                if let Some(version) = &rule.max_affected_version {
                    parts.push(format!("max affected version '{version}'"));
                }
                unmatched.push(parts.join(" in "));
            }
        }
        unmatched
    }
}

fn record_finding(report: &mut AuditReport, mut finding: Finding, suppressions: &mut Suppressions) {
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
