//! Clients for the Basilisk and PyPI vulnerability backends.

use thiserror::Error;
use url::Url;

mod basilisk;
mod epss;
mod kev;
mod pypi;

pub use basilisk::{BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL};
pub use epss::{DEFAULT_EPSS_BASE_URL, EPSS_BASE_URL_ENV_VAR, EpssClient};
pub use kev::{DEFAULT_KEV_URL, KEV_URL_ENV_VAR, KevCatalog, KevClient};
pub use pypi::{DEFAULT_PYPI_BASE_URL, PYPI_BASE_URL_ENV_VAR, PypiAuditClient};

const MAX_PAGINATION_ROUNDS: usize = 32;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("failed to contact the vulnerability database at {url}")]
    Request {
        url: Url,
        #[source]
        source: reqwest_middleware::Error,
    },
    #[error(
        "the vulnerability database at {url} returned HTTP {status}{}",
        .message.as_ref().map(|m| format!(": {m}")).unwrap_or_default()
    )]
    Status {
        url: Url,
        status: reqwest::StatusCode,
        /// The server's `{"error": "..."}` body, when present.
        message: Option<String>,
    },
    #[error("failed to parse the response from {url}")]
    InvalidResponse {
        url: Url,
        #[source]
        source: reqwest::Error,
    },
    #[error("unexpected response from {url}: expected {expected} results, got {got}")]
    UnexpectedResponse {
        url: Url,
        expected: usize,
        got: usize,
    },
    #[error("invalid audit API base URL")]
    InvalidBaseUrl(#[source] url::ParseError),
    #[error(
        "the vulnerability database at {url} returned more than {MAX_PAGINATION_ROUNDS} result pages for one batch"
    )]
    TooManyPages { url: Url },
}

#[cfg(test)]
mod tests;
