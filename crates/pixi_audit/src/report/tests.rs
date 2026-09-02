use super::*;

#[test]
fn severity_band_round_trips_through_its_name() {
    for band in SeverityBand::ALL {
        assert_eq!(band.name().parse::<SeverityBand>(), Ok(band));
        assert_eq!(band.to_string(), band.name());
    }
    assert!("HIGH".parse::<SeverityBand>().is_err());
    assert!("severe".parse::<SeverityBand>().is_err());
}

#[test]
fn package_names_normalize_per_ecosystem() {
    let pypi = PackageName::pypi("Ruamel.YAML").unwrap();
    assert_eq!(pypi.as_str(), "ruamel-yaml");
    assert_eq!(pypi, PackageName::pypi("ruamel__yaml").unwrap());
    assert!(pypi.matches("ruamel.yaml"));
    assert!(!pypi.matches("ruamel"));

    let conda = PackageName::conda("OpenSSL").unwrap();
    assert_eq!(conda.as_str(), "openssl");
    assert!(conda.matches("openssl"));
    assert!(!conda.matches("open-ssl"));
    assert!(PackageName::conda("not valid").is_err());

    assert_eq!(
        serde_json::to_value([&pypi, &conda]).unwrap(),
        serde_json::json!(["ruamel-yaml", "openssl"])
    );
}

#[test]
fn ecosystem_serializes_as_osv_string() {
    let json = serde_json::to_value([
        PackageEcosystem::CondaForge,
        PackageEcosystem::Pypi,
        PackageEcosystem::Other("bioconda".to_string()),
    ])
    .unwrap();
    assert_eq!(json, serde_json::json!(["conda-forge", "PyPI", "bioconda"]));
}

fn severity(kind: &str, score: &str) -> crate::types::OsvSeverity {
    crate::types::OsvSeverity {
        kind: kind.to_string(),
        score: score.to_string(),
    }
}

#[test]
fn severity_band_from_cvss_vector() {
    // CVSS:3.1 9.8 => critical
    assert_eq!(
        SeverityBand::from_severities(&[severity(
            "CVSS_V3",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )]),
        SeverityBand::Critical
    );
    // Unparsable => unknown
    assert_eq!(SeverityBand::from_severities(&[]), SeverityBand::Unknown);
}

#[test]
fn severity_band_accepts_nvd_style_type_labels() {
    // basilisk's NVD ingestion labels entries "CVSS_V3.1" / "CVSS_V3.0".
    assert_eq!(
        SeverityBand::from_severities(&[severity(
            "CVSS_V3.1",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        )]),
        SeverityBand::High
    );
}

#[test]
fn severity_band_from_cvss_v4() {
    // CVSS:4.0 9.3 => critical
    assert_eq!(
        SeverityBand::from_severities(&[severity(
            "CVSS_V4",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        )]),
        SeverityBand::Critical
    );
}

#[test]
fn severity_band_from_cvss_v2() {
    // Known NVD base scores: 7.5 => high, 4.3 => medium.
    assert_eq!(
        SeverityBand::from_severities(&[severity("CVSS_V2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P")]),
        SeverityBand::High
    );
    assert_eq!(
        SeverityBand::from_severities(&[severity("CVSS_V2.0", "AV:N/AC:M/Au:N/C:P/I:N/A:N")]),
        SeverityBand::Medium
    );
    assert_eq!(
        SeverityBand::from_severities(&[severity("CVSS_V2.0", "AV:L/AC:H/Au:N/C:N/I:P/A:N")]),
        SeverityBand::Low
    );
}

#[test]
fn cvss_v2_has_no_critical_band() {
    // v2's qualitative scale tops out at "high" (7.0-10.0); a 10.0 v2-only
    // advisory must not be promoted to critical.
    assert_eq!(
        SeverityBand::from_severities(&[severity("CVSS_V2.0", "AV:N/AC:L/Au:N/C:C/I:C/A:C")]),
        SeverityBand::High
    );
}

#[test]
fn highest_band_across_mixed_severity_entries_wins() {
    assert_eq!(
        SeverityBand::from_severities(&[
            severity("CVSS_V2.0", "AV:N/AC:M/Au:N/C:P/I:N/A:N"), // medium
            severity("CVSS_V3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), // critical
        ]),
        SeverityBand::Critical
    );
}

#[test]
fn classify_channel_urls() {
    assert_eq!(
        PackageEcosystem::from_channel_url(Some("https://conda.anaconda.org/conda-forge/")),
        PackageEcosystem::CondaForge
    );
    assert_eq!(
        PackageEcosystem::from_channel_url(Some("https://prefix.dev/conda-forge")),
        PackageEcosystem::CondaForge
    );
    assert_eq!(
        PackageEcosystem::from_channel_url(Some("https://conda.anaconda.org/bioconda/")),
        PackageEcosystem::Other("bioconda".to_string())
    );
    assert_eq!(
        PackageEcosystem::from_channel_url(None),
        PackageEcosystem::Other("unknown".to_string())
    );
}
