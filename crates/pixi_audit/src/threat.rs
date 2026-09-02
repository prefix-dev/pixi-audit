//! Threat intelligence attached to findings: EPSS exploit-probability
//! scores, entries from CISA's Known Exploited Vulnerabilities catalog, and
//! the risk score derived from them.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::{
    client::{EpssClient, KevClient},
    report::SeverityBand,
};

/// One EPSS record for a CVE, as published by FIRST.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpssScore {
    pub cve: String,
    /// Probability that the CVE is exploited in the next 30 days, 0.0-1.0.
    pub epss: f64,
    /// Rank of `epss` among all scored CVEs, 0.0-1.0.
    pub percentile: f64,
    /// Score date, `YYYY-MM-DD`.
    pub date: String,
}

/// Whether a KEV catalog entry is known to be used in ransomware campaigns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RansomwareCampaignUse {
    Known,
    Unknown,
}

impl RansomwareCampaignUse {
    /// Parses the catalog's `knownRansomwareCampaignUse` value; anything
    /// other than `Known` counts as unknown.
    pub fn parse(value: &str) -> Self {
        if value.trim().eq_ignore_ascii_case("known") {
            RansomwareCampaignUse::Known
        } else {
            RansomwareCampaignUse::Unknown
        }
    }
}

/// An entry of CISA's Known Exploited Vulnerabilities catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownExploited {
    pub cve: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    /// `YYYY-MM-DD`.
    pub date_added: String,
    pub required_action: String,
    /// `YYYY-MM-DD`.
    pub due_date: String,
    pub known_ransomware_campaign_use: RansomwareCampaignUse,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

/// Risk score in the range 0-100 combining how likely a vulnerability is
/// to be exploited with how severe it is, computed the way grype does so
/// the two tools rank findings identically.
///
/// Threat is 1.0 for a KEV-listed vulnerability and the EPSS probability
/// otherwise. Severity averages the band's midpoint with the mean CVSS base
/// score when one is known. KEV entries boost the result by 5%, known
/// ransomware use by 10%, and the product is capped at 1.0 before scaling.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RiskScore(f64);

impl RiskScore {
    /// No threat data and no severity contribution.
    pub const NONE: RiskScore = RiskScore(0.0);

    pub fn compute(
        severity: SeverityBand,
        cvss_base_score: Option<f64>,
        epss: &[EpssScore],
        known_exploited: &[KnownExploited],
    ) -> Self {
        let threat = if !known_exploited.is_empty() {
            1.0
        } else {
            epss.first().map(|score| score.epss).unwrap_or(0.0)
        };
        let band_score = severity_midpoint(severity) / 10.0;
        let severity_term = match cvss_base_score {
            Some(base_score) if base_score > 0.0 => (band_score + base_score / 10.0) / 2.0,
            Some(_) | None => band_score,
        };
        let kev_modifier = if known_exploited
            .iter()
            .any(|entry| entry.known_ransomware_campaign_use == RansomwareCampaignUse::Known)
        {
            1.1
        } else if !known_exploited.is_empty() {
            1.05
        } else {
            1.0
        };
        RiskScore((threat * severity_term * kev_modifier).min(1.0) * 100.0)
    }

    pub fn value(self) -> f64 {
        self.0
    }
}

impl Default for RiskScore {
    fn default() -> Self {
        RiskScore::NONE
    }
}

impl Eq for RiskScore {}

impl PartialOrd for RiskScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskScore {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.total_cmp(&other.0)
    }
}

/// The middle of each band's CVSS range. Unknown deliberately lands in the
/// middle so unscored advisories are neither buried nor promoted.
fn severity_midpoint(severity: SeverityBand) -> f64 {
    match severity {
        SeverityBand::Critical => 9.0,
        SeverityBand::High => 7.5,
        SeverityBand::Medium => 5.0,
        SeverityBand::Low => 3.0,
        SeverityBand::Unknown => 5.0,
    }
}

/// Whether one threat-data source contributed to the report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ThreatSourceStatus {
    /// No client was configured for the source.
    #[default]
    Disabled,
    /// The source was fetched; `date` is the data's publication date when
    /// the source reports one.
    Loaded {
        #[serde(skip_serializing_if = "Option::is_none")]
        date: Option<String>,
    },
    /// The source could not be fetched. Findings carry no data from it and
    /// the audit itself is unaffected.
    Failed { error: String },
}

/// Per-source availability of the threat data in a report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ThreatDataStatus {
    pub epss: ThreatSourceStatus,
    pub kev: ThreatSourceStatus,
}

/// The threat-data clients an audit may consult. Either source can be left
/// out, in which case findings simply carry no data from it.
#[derive(Default, Clone, Copy)]
pub struct ThreatSources<'a> {
    pub epss: Option<&'a EpssClient>,
    pub kev: Option<&'a KevClient>,
}

#[cfg(test)]
mod tests;
