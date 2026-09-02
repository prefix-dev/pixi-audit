use reqwest_middleware::{ClientWithMiddleware, RequestBuilder};
use serde::de::DeserializeOwned;
use url::Url;

use super::{AuditError, MAX_PAGINATION_ROUNDS};
use crate::types::{BatchResponse, BatchResult, OsvQuery, OsvVulnerability};

/// The default Basilisk API instance.
pub const DEFAULT_BASE_URL: &str = "https://api.basilisk.prefix.dev";

/// Environment variable to override the audit API base URL.
pub const BASE_URL_ENV_VAR: &str = "PIXI_AUDIT_BASE_URL";

/// Maximum number of queries per `querybatch` request (Basilisk/OSV limit).
const MAX_BATCH_SIZE: usize = 1000;

/// Client for an OSV-protocol vulnerability API (basilisk).
pub struct BasiliskClient {
    client: ClientWithMiddleware,
    base_url: Url,
}

impl BasiliskClient {
    pub fn new(client: ClientWithMiddleware, mut base_url: Url) -> Self {
        // `Url::join` treats a path without a trailing slash as a file:
        // https://host/prefix + "v1/querybatch" would drop "prefix".
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        Self { client, base_url }
    }

    fn endpoint(&self, path: &str) -> Result<Url, AuditError> {
        self.base_url.join(path).map_err(AuditError::InvalidBaseUrl)
    }

    /// Queries the database for all `queries`, in order. Handles chunking
    /// (max 1000 queries per request) and pagination transparently.
    pub async fn query_batch(&self, queries: &[OsvQuery]) -> Result<Vec<BatchResult>, AuditError> {
        let mut all_results = Vec::with_capacity(queries.len());
        for chunk in queries.chunks(MAX_BATCH_SIZE) {
            let mut results = self.query_batch_once(chunk).await?;

            // Follow pagination: re-send only the queries whose result
            // carried a `next_page_token`, until none are left. Bounded by
            // `MAX_PAGINATION_ROUNDS` so a server that always returns a
            // token can't make this loop forever.
            for round in 0.. {
                let mut pending_indices = Vec::new();
                let mut follow_up = Vec::new();
                for (idx, result) in results.iter().enumerate() {
                    if let Some(token) = &result.next_page_token {
                        let mut query = chunk[idx].clone();
                        query.page_token = Some(token.clone());
                        pending_indices.push(idx);
                        follow_up.push(query);
                    }
                }
                if follow_up.is_empty() {
                    break;
                }
                if round >= MAX_PAGINATION_ROUNDS {
                    return Err(AuditError::TooManyPages {
                        url: self.endpoint("v1/querybatch")?,
                    });
                }
                let follow_up_results = self.query_batch_once(&follow_up).await?;
                for (idx, extra) in pending_indices.into_iter().zip(follow_up_results) {
                    results[idx].vulns.extend(extra.vulns);
                    results[idx].next_page_token = extra.next_page_token;
                }
            }

            all_results.extend(results);
        }
        Ok(all_results)
    }

    async fn query_batch_once(&self, queries: &[OsvQuery]) -> Result<Vec<BatchResult>, AuditError> {
        let url = self.endpoint("v1/querybatch")?;
        let request = self
            .client
            .post(url.clone())
            .json(&serde_json::json!({ "queries": queries }));
        let body: BatchResponse = self.send_json(url.clone(), request).await?;
        if body.results.len() != queries.len() {
            return Err(AuditError::UnexpectedResponse {
                url,
                expected: queries.len(),
                got: body.results.len(),
            });
        }
        Ok(body.results)
    }

    /// Fetches the full OSV document for a vulnerability id.
    pub async fn get_vuln(&self, id: &str) -> Result<OsvVulnerability, AuditError> {
        let mut url = self.endpoint("v1/vulns")?;
        // Push the id as a single percent-encoded segment so an id like
        // `../health` cannot redirect the fetch to a different path.
        url.path_segments_mut()
            .expect("an HTTP(S) URL can always be a base")
            .push(id);
        let request = self.client.get(url.clone());
        self.send_json(url, request).await
    }

    /// Sends `request` and decodes a successful JSON response, mapping
    /// transport, status, and decoding failures to the matching
    /// [`AuditError`] variant.
    async fn send_json<T: DeserializeOwned>(
        &self,
        url: Url,
        request: RequestBuilder,
    ) -> Result<T, AuditError> {
        let response = request.send().await.map_err(|source| AuditError::Request {
            url: url.clone(),
            source,
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error(url, status, response).await);
        }
        response
            .json()
            .await
            .map_err(|source| AuditError::InvalidResponse { url, source })
    }
}

/// Builds a `Status` error, extracting the server's `{"error": "..."}` body
/// (basilisk's error format) when there is one.
pub(super) async fn status_error(
    url: Url,
    status: reqwest::StatusCode,
    response: reqwest::Response,
) -> AuditError {
    let message = response.text().await.ok().and_then(|body| {
        serde_json::from_str::<serde_json::Value>(&body)
            .ok()?
            .get("error")?
            .as_str()
            .map(str::to_string)
    });
    AuditError::Status {
        url,
        status,
        message,
    }
}
