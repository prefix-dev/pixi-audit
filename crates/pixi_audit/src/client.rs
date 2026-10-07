//! Clients for the Basilisk and PyPI vulnerability backends and the EPSS
//! and KEV threat feeds.

use thiserror::Error;
use url::Url;

mod basilisk;
mod epss;
mod http;
mod kev;
mod pypi;

pub use basilisk::{
    BASE_URL_ENV_VAR, BasiliskClient, DEFAULT_BASE_URL, TOKEN_ENV_VAR, TOKEN_LENGTH, TOKEN_PREFIX,
    looks_like_basilisk_token,
};
pub use epss::{DEFAULT_EPSS_BASE_URL, EPSS_BASE_URL_ENV_VAR, EpssClient};
pub use kev::{DEFAULT_KEV_URL, KEV_URL_ENV_VAR, KevCatalog, KevClient};
pub use pypi::{DEFAULT_PYPI_BASE_URL, PYPI_BASE_URL_ENV_VAR, PypiAuditClient};

use http::HttpFailure;

const MAX_PAGINATION_ROUNDS: usize = 32;

/// A failed request to a vulnerability database.
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
    #[error("fetched vulnerability document {id} was not available")]
    MissingDocument { id: String },
    #[error("invalid audit API base URL")]
    InvalidBaseUrl(#[source] url::ParseError),
    #[error(
        "the vulnerability database at {url} returned more than {MAX_PAGINATION_ROUNDS} result pages for one batch"
    )]
    TooManyPages { url: Url },
}

impl AuditError {
    fn from_http(url: Url, failure: HttpFailure) -> Self {
        match failure {
            HttpFailure::Request(source) => AuditError::Request { url, source },
            HttpFailure::Status { status, message } => AuditError::Status {
                url,
                status,
                message,
            },
            HttpFailure::InvalidResponse(source) => AuditError::InvalidResponse { url, source },
        }
    }
}

/// A failed request to a threat-data feed (EPSS or KEV).
#[derive(Debug, Error)]
pub enum ThreatFeedError {
    #[error("failed to contact {url}")]
    Request {
        url: Url,
        #[source]
        source: reqwest_middleware::Error,
    },
    #[error(
        "{url} returned HTTP {status}{}",
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
    #[error("invalid threat feed base URL")]
    InvalidBaseUrl(#[source] url::ParseError),
}

impl ThreatFeedError {
    fn from_http(url: Url, failure: HttpFailure) -> Self {
        match failure {
            HttpFailure::Request(source) => ThreatFeedError::Request { url, source },
            HttpFailure::Status { status, message } => ThreatFeedError::Status {
                url,
                status,
                message,
            },
            HttpFailure::InvalidResponse(source) => {
                ThreatFeedError::InvalidResponse { url, source }
            }
        }
    }
}

#[cfg(test)]
mod tests;
