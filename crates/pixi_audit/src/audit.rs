//! Audit orchestration across the Basilisk and PyPI backends.

use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;

use crate::{
    advisory::{advisory_url, fixed_versions, pypi_advisory_url},
    client::{AuditError, BasiliskClient, PypiAuditClient},
    report::{
        AuditPackage, AuditReport, Finding, IgnoreReason, IgnoreSpec, PackageEcosystem,
        SeverityBand, UncheckedPackage,
    },
    types::{BatchResult, OsvQuery, OsvVulnerability, QueryPackage},
};
use futures::{StreamExt, TryStreamExt};

/// How many `GET /v1/vulns/{id}` requests to keep in flight.
const MAX_CONCURRENT_DETAIL_FETCHES: usize = 16;

fn build_query(package: &AuditPackage) -> OsvQuery {
    OsvQuery {
        package: QueryPackage {
            name: Some(package.name.to_lowercase()),
            ecosystem: Some(package.ecosystem.osv_ecosystem().to_string()),
            purl: None,
        },
        version: package.version.clone(),
        page_token: None,
    }
}

/// Audits `packages` against the vulnerability database, applying `ignore`
/// (vulnerability ids or aliases, case-insensitive).
///
/// A security audit must never silently drop findings, so there is
/// deliberately no partial-report mode: any detail fetch that fails aborts
/// the audit as a whole. A missing Basilisk document is the one
/// exception: its batch index can briefly reference an id that is not served
/// yet, so a 404 degrades to an id-only finding with unknown severity. Any
/// PyPI response or detail error fails the audit.
pub async fn audit(
    client: &BasiliskClient,
    pypi_client: &PypiAuditClient,
    packages: Vec<AuditPackage>,
    ignore: IgnoreSpec<'_>,
) -> Result<AuditReport, AuditError> {
    // Basilisk handles conda packages. PyPI packages are deliberately excluded
    // here and sent to OSV below.
    let queryable: Vec<usize> = packages
        .iter()
        .enumerate()
        .filter(|(_, package)| {
            package.version.is_some() && !matches!(package.ecosystem, PackageEcosystem::Pypi)
        })
        .map(|(idx, _)| idx)
        .collect();
    let queries: Vec<OsvQuery> = queryable
        .iter()
        .map(|&idx| build_query(&packages[idx]))
        .collect();
    let query_results = client.query_batch(&queries).await?;
    let mut results: Vec<BatchResult> = vec![BatchResult::default(); packages.len()];
    for (&idx, result) in queryable.iter().zip(query_results) {
        results[idx] = result;
    }

    // Only normalized Python names and PEP 440 versions are safe to send to
    // OSV. Invalid or version-less PyPI entries remain explicitly unchecked.
    let mut pypi_queryable = Vec::new();
    let mut pypi_queries = Vec::new();
    for (idx, package) in packages.iter().enumerate() {
        if !matches!(package.ecosystem, PackageEcosystem::Pypi) {
            continue;
        }
        let Some(version) = package.version.as_deref() else {
            continue;
        };
        let (Ok(name), Ok(version)) = (
            uv_normalize::PackageName::from_str(&package.name),
            uv_pep440::Version::from_str(version),
        ) else {
            continue;
        };
        pypi_queryable.push(idx);
        pypi_queries.push(OsvQuery {
            package: QueryPackage {
                name: Some(name.to_string()),
                ecosystem: Some("PyPI".to_string()),
                purl: None,
            },
            version: Some(version.to_string()),
            page_token: None,
        });
    }
    let query_results = pypi_client.query_batch(&pypi_queries).await?;
    let pypi_audited_indices: BTreeSet<usize> = pypi_queryable.iter().copied().collect();
    let mut pypi_results: Vec<BatchResult> = vec![BatchResult::default(); packages.len()];
    for (&idx, result) in pypi_queryable.iter().zip(query_results) {
        pypi_results[idx] = result;
    }

    // Fetch each distinct conda vulnerability document once.
    let ids: BTreeSet<String> = results
        .iter()
        .flat_map(|r| r.vulns.iter().map(|v| v.id.clone()))
        .collect();
    let docs: HashMap<String, OsvVulnerability> = futures::stream::iter(ids)
        .map(|id| async move {
            match client.get_vuln(&id).await {
                Ok(doc) => Ok((id, doc)),
                Err(AuditError::Status { status, .. })
                    if status == reqwest::StatusCode::NOT_FOUND =>
                {
                    let doc = OsvVulnerability {
                        id: id.clone(),
                        ..Default::default()
                    };
                    Ok((id, doc))
                }
                Err(err) => Err(err),
            }
        })
        .buffer_unordered(MAX_CONCURRENT_DETAIL_FETCHES)
        .try_collect()
        .await?;

    let pypi_ids: BTreeSet<String> = pypi_results
        .iter()
        .flat_map(|result| {
            result
                .vulns
                .iter()
                .map(|vulnerability| vulnerability.id.clone())
        })
        .collect();
    let pypi_docs: HashMap<String, OsvVulnerability> = futures::stream::iter(pypi_ids)
        .map(|id| async move {
            let document = pypi_client.get_vuln(&id).await?;
            Ok::<_, AuditError>((id, document))
        })
        .buffer_unordered(MAX_CONCURRENT_DETAIL_FETCHES)
        .try_collect()
        .await?;

    let ignore_set: BTreeSet<String> = ignore.ignore.iter().map(|s| s.to_lowercase()).collect();
    let until_fixed_set: BTreeSet<String> = ignore
        .ignore_until_fixed
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

    let mut report = AuditReport::default();
    for (idx, (package, result)) in packages.iter().zip(&results).enumerate() {
        let pypi_audited = pypi_audited_indices.contains(&idx);
        let audited = package.version.is_some()
            && package.ecosystem.is_audited()
            && (!matches!(package.ecosystem, PackageEcosystem::Pypi) || pypi_audited);
        if audited {
            report.summary.audited += 1;
        }
        let mut found_any = false;
        let is_pypi = matches!(package.ecosystem, PackageEcosystem::Pypi);
        let (result, documents) = if is_pypi {
            (&pypi_results[idx], &pypi_docs)
        } else {
            (result, &docs)
        };

        for vuln_ref in &result.vulns {
            let doc = documents
                .get(&vuln_ref.id)
                .expect("every referenced vulnerability was fetched");
            if doc.withdrawn.is_some() {
                continue;
            }
            found_any = true;
            let ecosystem = package.ecosystem.osv_ecosystem();
            let query_package_name = if is_pypi {
                uv_normalize::PackageName::from_str(&package.name)
                    .expect("audited PyPI package names were validated")
                    .to_string()
            } else {
                package.name.clone()
            };
            let (mut fixed_versions, mut upstream_fixed_versions) =
                fixed_versions(doc, &query_package_name, ecosystem);
            if is_pypi {
                fixed_versions.retain(|version| uv_pep440::Version::from_str(version).is_ok());
                upstream_fixed_versions.clear();
            }
            record_finding(
                &mut report,
                Finding {
                    package: package.name.clone(),
                    version: package
                        .version
                        .clone()
                        .expect("only packages with a version are queried"),
                    ecosystem: ecosystem.to_string(),
                    environments: package.environments.clone(),
                    id: doc.id.clone(),
                    aliases: doc.aliases.clone(),
                    severity: if is_pypi {
                        SeverityBand::Unknown
                    } else {
                        SeverityBand::from_severities(&doc.severity)
                    },
                    fixed_versions,
                    upstream_fixed_versions,
                    summary: if is_pypi {
                        doc.summary
                            .as_ref()
                            .map(|summary| summary.trim().replace('\n', ""))
                    } else {
                        doc.summary.clone()
                    },
                    url: if is_pypi {
                        Some(pypi_advisory_url(doc))
                    } else {
                        advisory_url(doc)
                    },
                    ignore_reason: None,
                },
                &ignore_set,
                &until_fixed_set,
            );
        }
        if !found_any && !audited {
            report.unchecked.push(UncheckedPackage {
                package: package.name.clone(),
                version: package.version.clone(),
                ecosystem: package.ecosystem.osv_ecosystem().to_string(),
                environments: package.environments.clone(),
            });
        }
    }

    let order =
        |a: &Finding, b: &Finding| b.severity.cmp(&a.severity).then(a.package.cmp(&b.package));
    report.vulnerabilities.sort_by(order);
    report.ignored.sort_by(order);

    report.summary.vulnerable = report.vulnerabilities.len();
    report.summary.ignored = report.ignored.len();
    report.summary.unchecked = report.unchecked.len();
    Ok(report)
}

fn record_finding(
    report: &mut AuditReport,
    finding: Finding,
    ignore_set: &BTreeSet<String>,
    until_fixed_set: &BTreeSet<String>,
) {
    let matches = |set: &BTreeSet<String>| {
        set.contains(&finding.id.to_lowercase())
            || finding
                .aliases
                .iter()
                .any(|alias| set.contains(&alias.to_lowercase()))
    };
    let has_known_fix =
        !finding.fixed_versions.is_empty() || !finding.upstream_fixed_versions.is_empty();
    let reason = if matches(ignore_set) {
        Some(IgnoreReason::Always)
    } else if matches(until_fixed_set) && !has_known_fix {
        Some(IgnoreReason::UntilFixed)
    } else {
        None
    };
    match reason {
        Some(reason) => {
            let mut finding = finding;
            finding.ignore_reason = Some(reason);
            report.ignored.push(finding);
        }
        None => report.vulnerabilities.push(finding),
    }
}

#[cfg(test)]
mod tests;
