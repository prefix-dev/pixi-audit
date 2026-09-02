use super::*;
use crate::test_support::{conda_name, pypi_name};

fn on_pypi(version: &str) -> UpstreamFix {
    UpstreamFix {
        version: version.to_string(),
        origin: UpstreamOrigin::Ecosystem {
            ecosystem: "PyPI".to_string(),
        },
    }
}

fn project_release(version: &str, conda_publication: CondaPublication) -> UpstreamFix {
    UpstreamFix {
        version: version.to_string(),
        origin: UpstreamOrigin::Project { conda_publication },
    }
}

fn versions(fixes: &[UpstreamFix]) -> Vec<&str> {
    fixes.iter().map(|fix| fix.version.as_str()).collect()
}
/// A document shaped like basilisk's real output: the conda-forge entry
/// carries `versions` + `database_specific` (no ranges); the upstream
/// PyPI entry carries the ranges with `fixed` events.
fn basilisk_shaped_doc() -> OsvVulnerability {
    serde_json::from_value(serde_json::json!({
            "id": "CVE-2026-9999",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "pillow", "purl": "pkg:pypi/pillow"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "10.2.0"}]}]
                },
                {
                    "package": {"ecosystem": "PyPI", "name": "django"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0.2"}]}]
                },
                {
                    "package": {
                        "ecosystem": "conda-forge",
                        "name": "pillow",
                        "purl": "pkg:conda/conda-forge/pillow"
                    },
                    "versions": ["10.0.0", "10.1.0"],
                    "database_specific": {"basilisk": {"applicability": "evaluated"}}
                }
            ]
        }))
        .unwrap()
}

fn basilisk_fix_doc(conda_publication: &str) -> OsvVulnerability {
    serde_json::from_value(serde_json::json!({
        "id": "CVE-2026-50219",
        "affected": [{
            "package": {
                "ecosystem": "conda-forge",
                "name": "libexpat",
                "purl": "pkg:conda/conda-forge/libexpat"
            },
            "versions": ["2.8.0", "2.8.1"],
            "database_specific": {
                "basilisk": {
                    "applicability": "evaluated",
                    "comparator": "conda",
                    "matcher_version": "nvd_cpe@3",
                    "fix_version": "2.8.2",
                    "conda_publication": conda_publication,
                    "reported_fixes": [{
                        "source_kind": "nvd",
                        "source_advisory_id": "CVE-2026-50219",
                        "reported_fix": "9.9.9",
                        "conda_publication": "published"
                    }]
                }
            }
        }]
    }))
    .unwrap()
}

#[test]
fn basilisk_fix_is_classified_by_publication_state() {
    for (publication, expected_fixed, expected_upstream) in [
        ("published", vec!["2.8.2"], vec![]),
        (
            "not_published",
            vec![],
            vec![project_release("2.8.2", CondaPublication::NotPublished)],
        ),
        (
            "unknown",
            vec![],
            vec![project_release("2.8.2", CondaPublication::Unknown)],
        ),
    ] {
        let FixedVersions {
            same_ecosystem: fixed,
            upstream,
        } = fixed_versions(
            &basilisk_fix_doc(publication),
            &conda_name("libexpat"),
            "conda-forge",
        );
        assert_eq!(fixed, expected_fixed, "publication: {publication}");
        assert_eq!(upstream, expected_upstream, "publication: {publication}");
        assert!(!versions(&upstream).contains(&"9.9.9"));
    }
}

#[test]
fn fixed_versions_only_come_from_the_queried_ecosystem() {
    let doc = basilisk_shaped_doc();
    // conda-forge entries carry no fixed events; the PyPI fix must not be
    // presented as a conda-forge fixed version.
    let FixedVersions {
        same_ecosystem: fixed,
        upstream,
    } = fixed_versions(&doc, &conda_name("pillow"), "conda-forge");
    assert!(fixed.is_empty());
    assert_eq!(upstream, vec![on_pypi("10.2.0")]);

    // Queried as PyPI, the same fix IS a same-ecosystem fixed version.
    let FixedVersions {
        same_ecosystem: fixed,
        upstream,
    } = fixed_versions(&doc, &pypi_name("pillow"), "PyPI");
    assert_eq!(fixed, vec!["10.2.0"]);
    assert!(upstream.is_empty());
}

#[test]
fn missing_or_malformed_basilisk_metadata_falls_back_to_osv_ranges() {
    let metadata_values = [
        None,
        Some(serde_json::json!({"basilisk": {"fix_version": "2.8.2"}})),
        Some(serde_json::json!({
            "basilisk": {
                "fix_version": 282,
                "conda_publication": "published"
            }
        })),
        Some(serde_json::json!({
            "basilisk": {
                "fix_version": "2.8.2",
                "conda_publication": "sometimes"
            }
        })),
    ];

    for database_specific in metadata_values {
        let mut affected = serde_json::json!({
            "package": {"ecosystem": "conda-forge", "name": "libexpat"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "2.8.3"}]
            }]
        });
        if let Some(database_specific) = database_specific {
            affected["database_specific"] = database_specific;
        }
        let doc: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "CVE-2026-50219",
            "affected": [affected]
        }))
        .unwrap();

        let FixedVersions {
            same_ecosystem: fixed,
            upstream,
        } = fixed_versions(&doc, &conda_name("libexpat"), "conda-forge");
        assert_eq!(fixed, vec!["2.8.3"]);
        assert!(upstream.is_empty());
    }
}

#[test]
fn basilisk_metadata_requires_matching_package_and_ecosystem() {
    let doc: OsvVulnerability = serde_json::from_value(serde_json::json!({
        "id": "CVE-2026-50219",
        "affected": [
            {
                "package": {"ecosystem": "conda-forge", "name": "other"},
                "database_specific": {"basilisk": {
                    "fix_version": "1.0.0",
                    "conda_publication": "published"
                }}
            },
            {
                "package": {"ecosystem": "PyPI", "name": "libexpat"},
                "database_specific": {"basilisk": {
                    "fix_version": "2.0.0",
                    "conda_publication": "not_published"
                }}
            },
            {
                "database_specific": {"basilisk": {
                    "fix_version": "3.0.0",
                    "conda_publication": "published"
                }}
            }
        ]
    }))
    .unwrap();

    let FixedVersions {
        same_ecosystem: fixed,
        upstream,
    } = fixed_versions(&doc, &conda_name("libexpat"), "conda-forge");
    assert!(fixed.is_empty());
    assert!(upstream.is_empty());
}

#[test]
fn non_conda_queries_ignore_basilisk_metadata_but_keep_osv_ranges() {
    let doc: OsvVulnerability = serde_json::from_value(serde_json::json!({
        "id": "PYSEC-2026-1",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "demo"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "4.0.0"}]}],
            "database_specific": {"basilisk": {
                "fix_version": "3.0.0",
                "conda_publication": "published"
            }}
        }]
    }))
    .unwrap();

    let FixedVersions {
        same_ecosystem: fixed,
        upstream,
    } = fixed_versions(&doc, &pypi_name("demo"), "PyPI");
    assert_eq!(fixed, vec!["4.0.0"]);
    assert!(upstream.is_empty());
}

#[test]
fn standard_range_fixes_and_basilisk_metadata_are_deduplicated() {
    let doc: OsvVulnerability = serde_json::from_value(serde_json::json!({
        "id": "CVE-2026-50219",
        "affected": [
            {
                "package": {"ecosystem": "conda-forge", "name": "libexpat"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"fixed": "2.8.2"},
                    {"fixed": "2.8.2"},
                    {"fixed": "2.8.3"}
                ]}],
                "database_specific": {"basilisk": {
                    "fix_version": "2.8.2",
                    "conda_publication": "published"
                }}
            },
            {
                "package": {"ecosystem": "PyPI", "name": "libexpat"},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"fixed": "2.8.2"},
                    {"fixed": "2.8.4"},
                    {"fixed": "2.8.4"}
                ]}]
            }
        ]
    }))
    .unwrap();

    let FixedVersions {
        same_ecosystem: fixed,
        upstream,
    } = fixed_versions(&doc, &conda_name("libexpat"), "conda-forge");
    assert_eq!(fixed, vec!["2.8.2", "2.8.3"]);
    assert_eq!(upstream, vec![on_pypi("2.8.4")]);
}

#[test]
fn only_release_ranges_contribute_fixed_versions() {
    let doc: OsvVulnerability = serde_json::from_value(serde_json::json!({
        "id": "GHSA-1",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "demo"},
            "ranges": [
                {"type": "GIT", "events": [{"fixed": "deadbeef"}]},
                {"type": "SEMVER", "events": [{"fixed": "1.2.3"}]}
            ]
        }]
    }))
    .unwrap();

    let FixedVersions {
        same_ecosystem: fixed,
        upstream,
    } = fixed_versions(&doc, &pypi_name("demo"), "PyPI");
    assert_eq!(fixed, vec!["1.2.3"]);
    assert!(upstream.is_empty());
}

#[test]
fn upstream_fixed_versions_require_a_name_match() {
    // The django entry in the same advisory must not leak its fixed
    // version into pillow's report.
    let doc = basilisk_shaped_doc();
    let FixedVersions {
        same_ecosystem: fixed,
        upstream,
    } = fixed_versions(&doc, &conda_name("pillow"), "conda-forge");
    assert!(!versions(&upstream).contains(&"5.0.2"));
    assert!(!fixed.contains(&"5.0.2".to_string()));
}

#[test]
fn fix_present_in_own_ecosystem_is_not_repeated_as_upstream() {
    let doc: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "X",
            "affected": [
                {
                    "package": {"ecosystem": "conda-forge", "name": "pillow"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "10.2.0"}]}]
                },
                {
                    "package": {"ecosystem": "PyPI", "name": "pillow"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "10.2.0"}]}]
                }
            ]
        }))
        .unwrap();
    let FixedVersions {
        same_ecosystem: fixed,
        upstream,
    } = fixed_versions(&doc, &conda_name("pillow"), "conda-forge");
    assert_eq!(fixed, vec!["10.2.0"]);
    assert!(
        upstream.is_empty(),
        "version already reported as fixed must not repeat as upstream: {upstream:?}"
    );
}

#[test]
fn advisory_reference_wins_over_patch_and_issue_links() {
    let doc: OsvVulnerability = serde_json::from_value(serde_json::json!({
        "id": "CVE-2026-50219",
        "references": [
            {"type": "FIX", "url": "https://example.com/patch"},
            {"type": "REPORT", "url": "https://example.com/issue"},
            {"type": "ADVISORY", "url": "https://example.com/advisory"}
        ]
    }))
    .unwrap();

    assert_eq!(
        advisory_url(&doc).as_deref(),
        Some("https://example.com/advisory")
    );
}

#[test]
fn pypi_advisory_url_prefers_web_then_falls_back_to_osv() {
    let with_web: OsvVulnerability = serde_json::from_value(serde_json::json!({
        "id": "PYSEC-1",
        "references": [
            {"type": "FIX", "url": "https://example.com/fix"},
            {"type": "WEB", "url": "https://example.com/details"}
        ]
    }))
    .unwrap();
    assert_eq!(pypi_advisory_url(&with_web), "https://example.com/details");

    let without_references = OsvVulnerability {
        id: "PYSEC-2".to_string(),
        ..Default::default()
    };
    assert_eq!(
        pypi_advisory_url(&without_references),
        "https://osv.dev/vulnerability/PYSEC-2"
    );
}

#[test]
fn affected_entry_without_package_counts_as_same_ecosystem() {
    let doc: OsvVulnerability = serde_json::from_value(serde_json::json!({
        "id": "X",
        "affected": [{
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]
        }]
    }))
    .unwrap();
    let FixedVersions {
        same_ecosystem: fixed,
        upstream,
    } = fixed_versions(&doc, &conda_name("anything"), "conda-forge");
    assert_eq!(fixed, vec!["1.2.3"]);
    assert!(upstream.is_empty());
}

#[test]
fn pypi_names_match_under_pep_503_normalization() {
    // OSV.dev keeps the advisory's spelling (`ruamel.yaml`); the lock file
    // and the query use the normalized `ruamel-yaml`. They are one package.
    let doc: OsvVulnerability = serde_json::from_value(serde_json::json!({
        "id": "PYSEC-2026-2",
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "Ruamel.YAML"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.18.7"}]}]
        }]
    }))
    .unwrap();
    let FixedVersions {
        same_ecosystem: fixed,
        upstream,
    } = fixed_versions(&doc, &pypi_name("ruamel_yaml"), "PyPI");
    assert_eq!(fixed, vec!["0.18.7"]);
    assert!(upstream.is_empty());

    // Conda names only fold case; `ruamel.yaml` and `ruamel-yaml` differ.
    let FixedVersions {
        same_ecosystem: fixed,
        ..
    } = fixed_versions(&doc, &conda_name("ruamel-yaml"), "PyPI");
    assert!(fixed.is_empty());
}
