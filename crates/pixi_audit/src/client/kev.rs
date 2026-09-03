use std::collections::HashMap;

use reqwest_middleware::ClientWithMiddleware;
use serde::Deserialize;
use url::Url;

use super::{AuditError, basilisk::status_error};
use crate::threat::{KnownExploited, RansomwareCampaignUse};

/// CISA's Known Exploited Vulnerabilities catalog feed.
pub const DEFAULT_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Environment variable to override the KEV catalog URL.
pub const KEV_URL_ENV_VAR: &str = "PIXI_AUDIT_KEV_URL";

/// Client for the KEV catalog. The catalog has no per-CVE query interface,
/// so the whole feed is downloaded and looked up locally.
pub struct KevClient {
    client: ClientWithMiddleware,
    url: Url,
}

impl KevClient {
    pub fn new(client: ClientWithMiddleware, url: Url) -> Self {
        Self { client, url }
    }

    pub async fn catalog(&self) -> Result<KevCatalog, AuditError> {
        let url = self.url.clone();
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|source| AuditError::Request {
                url: url.clone(),
                source,
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error(url, status, response).await);
        }
        let raw: RawCatalog = response
            .json()
            .await
            .map_err(|source| AuditError::InvalidResponse { url, source })?;
        Ok(KevCatalog::from(raw))
    }
}

/// The KEV catalog indexed by CVE id.
#[derive(Debug, Clone, Default)]
pub struct KevCatalog {
    date_released: Option<String>,
    entries: HashMap<String, KnownExploited>,
}

impl KevCatalog {
    /// Builds a catalog from entries, for callers that have the data
    /// already (tests, embedding consumers).
    pub fn from_entries(date_released: Option<String>, entries: Vec<KnownExploited>) -> Self {
        Self {
            date_released,
            entries: entries
                .into_iter()
                .map(|entry| (entry.cve.to_ascii_uppercase(), entry))
                .collect(),
        }
    }

    /// The catalog's release date, `YYYY-MM-DD`.
    pub fn date_released(&self) -> Option<&str> {
        self.date_released.as_deref()
    }

    /// The entry for `cve`, matched case-insensitively.
    pub fn get(&self, cve: &str) -> Option<&KnownExploited> {
        self.entries.get(&cve.to_ascii_uppercase())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl From<RawCatalog> for KevCatalog {
    fn from(raw: RawCatalog) -> Self {
        let date_released = raw
            .date_released
            .map(|timestamp| timestamp.split('T').next().unwrap_or_default().to_string())
            .filter(|date| !date.is_empty());
        let entries = raw
            .vulnerabilities
            .into_iter()
            .map(|entry| KnownExploited {
                cve: entry.cve_id,
                vendor_project: entry.vendor_project,
                product: entry.product,
                vulnerability_name: entry.vulnerability_name,
                date_added: entry.date_added,
                required_action: entry.required_action,
                due_date: entry.due_date,
                known_ransomware_campaign_use: RansomwareCampaignUse::parse(
                    &entry.known_ransomware_campaign_use,
                ),
                notes: entry.notes,
            })
            .collect();
        KevCatalog::from_entries(date_released, entries)
    }
}

/// The feed's JSON layout.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCatalog {
    #[serde(default)]
    date_released: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(default)]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    vulnerability_name: String,
    #[serde(default)]
    date_added: String,
    #[serde(default)]
    required_action: String,
    #[serde(default)]
    due_date: String,
    #[serde(default)]
    known_ransomware_campaign_use: String,
    #[serde(default)]
    notes: String,
}

#[cfg(test)]
mod tests;
