use std::sync::{Arc, Mutex};

use super::*;
use crate::{
    test_support::{basilisk_client as client, pypi_client, spawn_router as spawn},
    types::*,
};
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};

fn query(name: &str, version: &str) -> OsvQuery {
    OsvQuery {
        package: QueryPackage {
            name: Some(name.to_string()),
            ecosystem: Some("conda-forge".to_string()),
            purl: None,
        },
        version: Some(version.to_string()),
        page_token: None,
    }
}

#[tokio::test]
async fn query_batch_chunks_requests_of_1000() {
    // Record the number of queries in each incoming request.
    let sizes: Arc<Mutex<Vec<usize>>> = Arc::default();
    let sizes_clone = sizes.clone();
    let app = Router::new()
        .route(
            "/v1/querybatch",
            post(
                move |State(sizes): State<Arc<Mutex<Vec<usize>>>>,
                      Json(body): Json<serde_json::Value>| async move {
                    let n = body["queries"].as_array().unwrap().len();
                    sizes.lock().unwrap().push(n);
                    let results: Vec<serde_json::Value> =
                        (0..n).map(|_| serde_json::json!({})).collect();
                    Json(serde_json::json!({ "results": results }))
                },
            ),
        )
        .with_state(sizes_clone);
    let base = spawn(app).await;

    let queries: Vec<OsvQuery> = (0..1001)
        .map(|i| query(&format!("pkg{i}"), "1.0"))
        .collect();
    let results = client(base).query_batch(&queries).await.unwrap();

    assert_eq!(results.len(), 1001);
    assert_eq!(*sizes.lock().unwrap(), vec![1000, 1]);
}

#[tokio::test]
async fn query_batch_follows_pagination_tokens() {
    // First request: query 0 returns one vuln and a page token, query 1 is clean.
    // Second request (only the paged query): returns the second vuln, no token.
    let app = Router::new().route(
        "/v1/querybatch",
        post(|Json(body): Json<serde_json::Value>| async move {
            let queries = body["queries"].as_array().unwrap();
            let paged = queries.first().and_then(|q| q.get("page_token")).is_some();
            if paged {
                assert_eq!(queries.len(), 1);
                Json(serde_json::json!({
                    "results": [{"vulns": [{"id": "BSLK-2", "modified": null}]}]
                }))
            } else {
                Json(serde_json::json!({
                    "results": [
                        {"vulns": [{"id": "BSLK-1", "modified": null}], "next_page_token": "tok"},
                        {}
                    ]
                }))
            }
        }),
    );
    let base = spawn(app).await;

    let queries = vec![query("openssl", "3.1.0"), query("zlib", "1.3")];
    let results = client(base).query_batch(&queries).await.unwrap();

    let ids: Vec<&str> = results[0].vulns.iter().map(|v| v.id.as_str()).collect();
    assert_eq!(ids, vec!["BSLK-1", "BSLK-2"]);
    assert!(results[1].vulns.is_empty());
}

#[tokio::test]
async fn query_batch_caps_unbounded_pagination() {
    // A buggy/malicious server that always returns a `next_page_token`
    // must not make `query_batch` loop forever.
    let app = Router::new().route(
        "/v1/querybatch",
        post(|Json(body): Json<serde_json::Value>| async move {
            let n = body["queries"].as_array().unwrap().len();
            let results: Vec<serde_json::Value> = (0..n)
                .map(|_| serde_json::json!({"next_page_token": "tok"}))
                .collect();
            Json(serde_json::json!({ "results": results }))
        }),
    );
    let pypi_base = spawn(app.clone()).await;
    let base = spawn(app).await;

    let err = client(base)
        .query_batch(&[query("openssl", "3.1.0")])
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuditError::TooManyPages { .. }),
        "unexpected error: {err}"
    );

    let err = pypi_client(pypi_base)
        .osv_client()
        .query_batch(&[query("requests", "2.32.0")])
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuditError::TooManyPages { .. }),
        "unexpected PyPI error: {err}"
    );
}

#[tokio::test]
async fn get_vuln_percent_encodes_the_id() {
    // Ids come from the server's own querybatch response, but a hostile
    // or buggy server must not be able to redirect the detail fetch to a
    // different path via an id like `../health`.
    let app = Router::new()
        .route(
            "/v1/vulns/{id}",
            get(
                |axum::extract::Path(id): axum::extract::Path<String>| async move {
                    Json(serde_json::json!({"id": id}))
                },
            ),
        )
        .route(
            "/health",
            get(|| async { Json(serde_json::json!({"id": "WRONG"})) }),
        );
    let base = spawn(app).await;

    let vuln = client(base).get_vuln("../health").await.unwrap();
    assert_eq!(vuln.id, "../health");
}

#[tokio::test]
async fn base_url_with_deep_path_keeps_all_segments() {
    let app = Router::new().route(
        "/a/b/v1/querybatch",
        post(|| async { Json(serde_json::json!({"results": [{}]})) }),
    );
    let base = spawn(app).await;
    let deep = base.join("a/b").unwrap();
    assert!(!deep.path().ends_with('/'));

    let results = client(deep)
        .query_batch(&[query("openssl", "3.1.0")])
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn pypi_base_url_with_deep_path_keeps_all_segments() {
    let app = Router::new().route(
        "/a/b/v1/querybatch",
        post(|| async { Json(serde_json::json!({"results": [{}]})) }),
    );
    let base = spawn(app).await;
    let deep = base.join("a/b").unwrap();
    assert!(!deep.path().ends_with('/'));
    let client = pypi_client(deep);

    let results = client
        .osv_client()
        .query_batch(&[query("requests", "2.32.0")])
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].vulns.is_empty());
}

#[tokio::test]
async fn get_vuln_fetches_full_document() {
    let app = Router::new().route(
        "/v1/vulns/{id}",
        get(
            |axum::extract::Path(id): axum::extract::Path<String>| async move {
                Json(serde_json::json!({"id": id, "aliases": ["CVE-2026-1234"]}))
            },
        ),
    );
    let base = spawn(app).await;

    let vuln = client(base).get_vuln("BSLK-1").await.unwrap();
    assert_eq!(vuln.id, "BSLK-1");
    assert_eq!(vuln.aliases, vec!["CVE-2026-1234"]);
}

#[tokio::test]
async fn server_error_is_reported() {
    let app = Router::new().route(
        "/v1/querybatch",
        post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
    );
    let base = spawn(app).await;

    let err = client(base)
        .query_batch(&[query("openssl", "3.1.0")])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("500"), "unexpected error: {err}");
}

#[tokio::test]
async fn server_error_body_message_is_surfaced() {
    // basilisk returns structured {"error": "..."} bodies on 4xx/5xx.
    let app = Router::new().route(
        "/v1/querybatch",
        post(|| async {
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "querybatch accepts at most 1000 queries"
                })),
            )
        }),
    );
    let base = spawn(app).await;

    let err = client(base)
        .query_batch(&[query("openssl", "3.1.0")])
        .await
        .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("400"), "unexpected error: {message}");
    assert!(
        message.contains("querybatch accepts at most 1000 queries"),
        "server message missing from: {message}"
    );
}

#[tokio::test]
async fn malformed_response_is_an_error() {
    let app = Router::new().route("/v1/querybatch", post(|| async { "not JSON" }));
    let base = spawn(app).await;

    let err = client(base)
        .query_batch(&[query("openssl", "3.1.0")])
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuditError::InvalidResponse { .. }),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn mismatched_result_count_is_an_error() {
    let app = Router::new().route(
        "/v1/querybatch",
        post(|| async { Json(serde_json::json!({"results": []})) }),
    );
    let base = spawn(app).await;

    let err = client(base)
        .query_batch(&[query("openssl", "3.1.0")])
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuditError::UnexpectedResponse { .. }),
        "unexpected error: {err}"
    );
}
