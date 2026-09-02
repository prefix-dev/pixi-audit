//! Collecting auditable packages straight from a `pixi.lock` file.

use std::collections::{BTreeMap, BTreeSet};

use rattler_lock::{LockFile, LockedPackage};
use thiserror::Error;

use crate::{
    client::{AuditError, BasiliskClient, PypiAuditClient},
    report::{
        AuditPackage, AuditReport, IgnoreSpec, InvalidPackageName, PackageEcosystem, PackageName,
        audit,
    },
};

#[derive(Debug, Error)]
pub enum LockFileAuditError {
    #[error("the lock file contains no environments; run `pixi lock` first")]
    EmptyLockFile,
    /// A filter named an environment the lock file does not contain. This is
    /// an error rather than an empty selection: a misspelled filter must not
    /// silently produce a clean-looking audit.
    #[error("the lock file contains no environment named '{name}'")]
    UnknownEnvironment { name: String },
    /// A filter named a platform no selected environment contains.
    #[error("the selected environments contain no platform named '{name}'")]
    UnknownPlatform { name: String },
    /// A locked package name that its own ecosystem rejects. Lock files
    /// written by pixi never contain one.
    #[error(transparent)]
    InvalidPackageName(#[from] InvalidPackageName),
    #[error(transparent)]
    Audit(#[from] AuditError),
}

fn is_selected(filter: &[String], name: &str) -> bool {
    filter.is_empty() || filter.iter().any(|candidate| candidate == name)
}

/// Collects deduplicated packages to audit from the lock file, together with
/// the set of environments (across all selected platforms) containing each.
/// Empty filters select every environment/platform.
pub fn collect_packages(
    lock_file: &LockFile,
    environment_filter: &[String],
    platform_filter: &[String],
) -> Result<Vec<AuditPackage>, LockFileAuditError> {
    if lock_file.environments().len() == 0 {
        return Err(LockFileAuditError::EmptyLockFile);
    }

    // Reject filters that match nothing, so a typo cannot silently shrink
    // the audit to an empty, clean-looking report.
    for name in environment_filter {
        if !lock_file.environments().any(|(env, _)| env == name) {
            return Err(LockFileAuditError::UnknownEnvironment { name: name.clone() });
        }
    }
    for name in platform_filter {
        let known = lock_file
            .environments()
            .any(|(environment_name, environment)| {
                is_selected(environment_filter, environment_name)
                    && environment
                        .packages_by_platform()
                        .any(|(platform, _)| platform.name().as_str() == name.as_str())
            });
        if !known {
            return Err(LockFileAuditError::UnknownPlatform { name: name.clone() });
        }
    }

    // (name, version, ecosystem) -> environment names. Keyed on the enum, so
    // e.g. a hypothetical channel literally named "PyPI" cannot collide with
    // the real PyPI ecosystem.
    type DedupKey = (PackageName, Option<String>, PackageEcosystem);
    let mut dedup: BTreeMap<DedupKey, BTreeSet<String>> = BTreeMap::new();

    for (environment_name, environment) in lock_file.environments() {
        if !is_selected(environment_filter, environment_name) {
            continue;
        }
        for (platform, packages) in environment.packages_by_platform() {
            if !is_selected(platform_filter, platform.name().as_str()) {
                continue;
            }
            for package in packages {
                let (name, version, ecosystem) = match package {
                    LockedPackage::Conda(conda) => {
                        let channel = conda
                            .as_binary()
                            .and_then(|binary| binary.channel.as_ref())
                            .map(|channel| channel.to_string());
                        (
                            PackageName::Conda(conda.name().clone()),
                            conda.record().map(|record| record.version.to_string()),
                            PackageEcosystem::from_channel_url(channel.as_deref()),
                        )
                    }
                    LockedPackage::Pypi(pypi) => (
                        PackageName::pypi(pypi.name().as_ref())?,
                        pypi.version().map(ToString::to_string),
                        PackageEcosystem::Pypi,
                    ),
                };
                dedup
                    .entry((name, version, ecosystem))
                    .or_default()
                    .insert(environment_name.to_string());
            }
        }
    }

    Ok(dedup
        .into_iter()
        .map(|((name, version, ecosystem), environments)| AuditPackage {
            name,
            version,
            ecosystem,
            environments: environments.into_iter().collect(),
        })
        .collect())
}

/// Audits every package in the lock file (subject to the environment and
/// platform filters) against the vulnerability database.
pub async fn audit_lock_file(
    client: &BasiliskClient,
    pypi_client: &PypiAuditClient,
    lock_file: &LockFile,
    environment_filter: &[String],
    platform_filter: &[String],
    ignore: IgnoreSpec<'_>,
) -> Result<AuditReport, LockFileAuditError> {
    let packages = collect_packages(lock_file, environment_filter, platform_filter)?;
    Ok(audit(client, pypi_client, packages, ignore).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{basilisk_client, pypi_client as test_pypi_client, spawn_router};

    /// A small but realistic lock file: two environments sharing an openssl
    /// build from conda-forge, plus a bioconda package and a PyPI wheel in
    /// `default` only.
    const FIXTURE: &str = r#"version: 6
environments:
  default:
    channels:
    - url: https://conda.anaconda.org/conda-forge/
    packages:
      linux-64:
      - conda: https://conda.anaconda.org/conda-forge/linux-64/openssl-3.1.0-hd590300_3.conda
      - conda: https://conda.anaconda.org/bioconda/linux-64/samtools-1.19-h50ea8bc_0.conda
      - pypi: https://files.pythonhosted.org/packages/py3/r/requests/requests-2.32.0-py3-none-any.whl
      osx-arm64:
      - conda: https://conda.anaconda.org/conda-forge/osx-arm64/openssl-3.1.0-h53f4e23_3.conda
  prod:
    channels:
    - url: https://conda.anaconda.org/conda-forge/
    packages:
      linux-64:
      - conda: https://conda.anaconda.org/conda-forge/linux-64/openssl-3.1.0-hd590300_3.conda
packages:
- conda: https://conda.anaconda.org/conda-forge/linux-64/openssl-3.1.0-hd590300_3.conda
  sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  md5: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  license: Apache-2.0
  size: 100
  timestamp: 1700000000000
- conda: https://conda.anaconda.org/conda-forge/osx-arm64/openssl-3.1.0-h53f4e23_3.conda
  sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  md5: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  license: Apache-2.0
  size: 100
  timestamp: 1700000000000
- conda: https://conda.anaconda.org/bioconda/linux-64/samtools-1.19-h50ea8bc_0.conda
  sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  md5: cccccccccccccccccccccccccccccccc
  license: MIT
  size: 100
  timestamp: 1700000000000
- pypi: https://files.pythonhosted.org/packages/py3/r/requests/requests-2.32.0-py3-none-any.whl
  name: requests
  version: 2.32.0
  sha256: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
  requires_python: '>=3.8'
"#;

    fn fixture() -> LockFile {
        LockFile::from_str_with_base_directory(FIXTURE, None).expect("fixture parses")
    }

    #[test]
    fn collects_deduplicated_packages_with_environments() {
        let packages = collect_packages(&fixture(), &[], &[]).unwrap();

        let openssl: Vec<&AuditPackage> = packages
            .iter()
            .filter(|p| p.name.as_str() == "openssl")
            .collect();
        // Same (name, version, ecosystem) across platforms and environments
        // collapses into one entry listing both environments.
        assert_eq!(openssl.len(), 1);
        assert_eq!(openssl[0].version.as_deref(), Some("3.1.0"));
        assert_eq!(openssl[0].ecosystem, PackageEcosystem::CondaForge);
        assert_eq!(openssl[0].environments, vec!["default", "prod"]);

        let samtools = packages
            .iter()
            .find(|p| p.name.as_str() == "samtools")
            .unwrap();
        assert_eq!(
            samtools.ecosystem,
            PackageEcosystem::Other("bioconda".to_string())
        );
        assert_eq!(samtools.environments, vec!["default"]);

        let requests = packages
            .iter()
            .find(|p| p.name.as_str() == "requests")
            .unwrap();
        assert_eq!(requests.ecosystem, PackageEcosystem::Pypi);
        assert_eq!(requests.version.as_deref(), Some("2.32.0"));

        assert_eq!(packages.len(), 3);
    }

    #[test]
    fn environment_filter_limits_collection() {
        let packages = collect_packages(&fixture(), &["prod".to_string()], &[]).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name.as_str(), "openssl");
        assert_eq!(packages[0].environments, vec!["prod"]);
    }

    #[test]
    fn platform_filter_limits_collection() {
        let packages = collect_packages(&fixture(), &[], &["osx-arm64".to_string()]).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name.as_str(), "openssl");
        assert_eq!(packages[0].environments, vec!["default"]);
    }

    #[test]
    fn unknown_environment_filter_is_an_error() {
        // A misspelled environment must not silently produce an empty (i.e.
        // clean-looking) audit.
        let err = collect_packages(&fixture(), &["pord".to_string()], &[]).unwrap_err();
        assert!(
            matches!(&err, LockFileAuditError::UnknownEnvironment { name } if name == "pord"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unknown_platform_filter_is_an_error() {
        let err = collect_packages(&fixture(), &[], &["linux-46".to_string()]).unwrap_err();
        assert!(
            matches!(&err, LockFileAuditError::UnknownPlatform { name } if name == "linux-46"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn environment_and_platform_filters_must_intersect() {
        let err = collect_packages(
            &fixture(),
            &["prod".to_string()],
            &["osx-arm64".to_string()],
        )
        .unwrap_err();
        assert!(
            matches!(&err, LockFileAuditError::UnknownPlatform { name } if name == "osx-arm64"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn empty_lock_file_is_an_error() {
        let empty = LockFile::default();
        let err = collect_packages(&empty, &[], &[]).unwrap_err();
        assert!(matches!(err, LockFileAuditError::EmptyLockFile));
    }

    /// End to end: lock file in, audit report out, against a mock server
    /// where openssl 3.1.0 has one advisory and everything else is clean.
    #[tokio::test]
    async fn audits_a_lock_file_end_to_end() {
        use axum::{
            Json, Router,
            routing::{get, post},
        };

        let app = Router::new()
            .route(
                "/v1/querybatch",
                post(|Json(body): Json<serde_json::Value>| async move {
                    let results: Vec<serde_json::Value> = body["queries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|q| {
                            if q["package"]["name"] == "openssl" {
                                serde_json::json!({"vulns": [{"id": "BSLK-1"}]})
                            } else {
                                serde_json::json!({})
                            }
                        })
                        .collect();
                    Json(serde_json::json!({"results": results}))
                }),
            )
            .route(
                "/v1/vulns/{id}",
                get(|| async {
                    Json(serde_json::json!({
                        "id": "BSLK-1",
                        "summary": "Buffer overflow in openssl",
                        "severity": [{
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        }],
                        "affected": [{
                            "package": {"ecosystem": "conda-forge", "name": "openssl"},
                            "versions": ["3.1.0"]
                        }]
                    }))
                }),
            );
        let base = spawn_router(app).await;
        let client = basilisk_client(base.clone());
        let pypi_client = test_pypi_client(base);

        let report = audit_lock_file(
            &client,
            &pypi_client,
            &fixture(),
            &[],
            &[],
            IgnoreSpec::default(),
        )
        .await
        .unwrap();

        assert_eq!(report.vulnerabilities.len(), 1);
        let finding = &report.vulnerabilities[0];
        assert_eq!(finding.package.as_str(), "openssl");
        assert_eq!(finding.id, "BSLK-1");
        assert_eq!(finding.severity, crate::report::SeverityBand::Critical);
        assert_eq!(finding.environments, vec!["default", "prod"]);

        // samtools (bioconda) is unchecked; requests is audited through OSV.
        assert_eq!(report.summary.unchecked, 1);
        assert_eq!(report.summary.audited, 2);
    }
}
