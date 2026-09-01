use std::time::Duration;

use reqwest_middleware::ClientBuilder;
use url::Url;

use super::{AuditError, BasiliskClient};
use crate::types::{BatchResult, OsvQuery, OsvVulnerability};

/// The default OSV API used to audit PyPI packages.
pub const DEFAULT_PYPI_BASE_URL: &str = "https://api.osv.dev";

/// Environment variable to override the PyPI vulnerability API.
pub const PYPI_BASE_URL_ENV_VAR: &str = "PIXI_AUDIT_PYPI_BASE_URL";

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Client for auditing PyPI packages against the OSV API.
pub struct PypiAuditClient {
    inner: BasiliskClient,
}

impl PypiAuditClient {
    pub fn new(base_url: Url) -> Result<Self, AuditError> {
        let client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(AuditError::PypiClient)?;
        let http = ClientBuilder::new(client).build();
        Ok(Self {
            inner: BasiliskClient::new(http, base_url),
        })
    }

    pub(crate) async fn query_batch(
        &self,
        queries: &[OsvQuery],
    ) -> Result<Vec<BatchResult>, AuditError> {
        self.inner.query_batch(queries).await
    }

    pub(crate) async fn get_vuln(&self, id: &str) -> Result<OsvVulnerability, AuditError> {
        self.inner.get_vuln(id).await
    }
}
