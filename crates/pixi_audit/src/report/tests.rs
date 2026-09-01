use super::*;

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
