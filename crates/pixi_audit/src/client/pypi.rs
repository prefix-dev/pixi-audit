use reqwest_middleware::ClientWithMiddleware;
use url::Url;

use super::BasiliskClient;

/// The default OSV API used to audit PyPI packages.
pub const DEFAULT_PYPI_BASE_URL: &str = "https://api.osv.dev";

/// Environment variable to override the PyPI vulnerability API.
pub const PYPI_BASE_URL_ENV_VAR: &str = "PIXI_AUDIT_PYPI_BASE_URL";

/// Client for auditing PyPI packages against the OSV API.
///
/// A distinct type from [`BasiliskClient`] so the two backends cannot be
/// swapped by accident, even though they speak the same protocol.
pub struct PypiAuditClient {
    inner: BasiliskClient,
}

impl PypiAuditClient {
    /// Wraps `client`, which carries whatever middleware, timeouts, and
    /// proxy configuration the caller set up. The same client can be shared
    /// with a [`BasiliskClient`]. No timeout is applied here, so callers
    /// should configure one on `client`.
    pub fn new(client: ClientWithMiddleware, base_url: Url) -> Self {
        Self {
            inner: BasiliskClient::new(client, base_url),
        }
    }

    /// The OSV-protocol client this wraps.
    pub(crate) fn osv_client(&self) -> &BasiliskClient {
        &self.inner
    }
}
