use super::*;
use axum::{Json, Router, extract::Form, http::StatusCode, routing::post};
use rattler_networking::authentication_storage::backends::memory::MemoryStorage;
use serde_json::json;
use std::sync::{Arc, Mutex, atomic::AtomicUsize};

const CLIENT_ID: &str = "rattler";
type Seen = Arc<Mutex<Vec<Request>>>;

struct Capture {
    seen: Seen,
    reject_auth: bool,
    status: StatusCode,
}

#[async_trait::async_trait]
impl Middleware for Capture {
    async fn handle(
        &self,
        req: Request,
        _extensions: &mut http::Extensions,
        _next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let status = if self.reject_auth && req.headers().contains_key(AUTHORIZATION) {
            StatusCode::UNAUTHORIZED
        } else {
            self.status
        };
        self.seen.lock().unwrap().push(req);
        Ok(http::Response::builder()
            .status(status)
            .body("{}")
            .unwrap()
            .into())
    }
}

fn storage() -> AuthenticationStorage {
    let mut store = AuthenticationStorage::empty();
    store.add_backend(Arc::new(MemoryStorage::new()));
    store
}

fn grant(endpoint: String, expiry: i64) -> Authentication {
    Authentication::OAuth {
        audience: Some(DEFAULT_BASE_URL.into()),
        access_token: "fixture-host-token".into(),
        refresh_token: Some("fixture-refresh".into()),
        expires_at: Some(expiry),
        token_endpoint: endpoint,
        revocation_endpoint: None,
        client_id: CLIENT_ID.into(),
    }
}

fn cached_grant() -> Authentication {
    grant("http://127.0.0.1:1/token".into(), i64::MAX)
}

fn capture_client(
    offline: bool,
    url: &Url,
    store: Option<AuthenticationStorage>,
    reject_auth: bool,
    status: StatusCode,
) -> (ClientWithMiddleware, Seen) {
    let seen = Seen::default();
    let http = client_builder(offline, url, store)
        .unwrap()
        .with(Capture {
            seen: seen.clone(),
            reject_auth,
            status,
        })
        .build();
    (http, seen)
}

fn headers(seen: &Seen) -> Vec<Option<String>> {
    seen.lock()
        .unwrap()
        .iter()
        .map(|req| {
            req.headers()
                .get(AUTHORIZATION)
                .map(|value| value.to_str().unwrap().to_owned())
        })
        .collect()
}

#[test]
fn rejects_secret_bearing_and_non_http_base_urls() {
    for value in [
        "https://user:fixture-secret@api.example",
        "https://api.example/?token=fixture-secret",
        "https://api.example/#fixture-secret",
        "file:///tmp/api",
    ] {
        let error = validate_base_url(&Url::parse(value).unwrap()).unwrap_err();
        assert!(!error.to_string().contains("fixture-secret"));
    }
    assert!(production_origin(
        &Url::parse("https://API.BASILISK.PREFIX.DEV:443/").unwrap()
    ));
}

#[tokio::test]
async fn missing_unrelated_and_old_credentials_stay_anonymous() {
    let url = Url::parse(DEFAULT_BASE_URL).unwrap();
    let mut old = cached_grant();
    if let Authentication::OAuth { audience, .. } = &mut old {
        *audience = None;
    }
    let mut wrong = cached_grant();
    if let Authentication::OAuth { audience, .. } = &mut wrong {
        *audience = Some("https://other.example".into());
    }
    for entry in [
        None,
        Some((CREDENTIAL_KEY.to_owned(), old)),
        Some((CREDENTIAL_KEY.to_owned(), wrong)),
        Some((
            CREDENTIAL_KEY.to_owned(),
            Authentication::BearerToken("fixture-channel".into()),
        )),
        Some((
            CREDENTIAL_KEY.to_owned(),
            Authentication::CondaToken("fixture-conda".into()),
        )),
        Some(("*.prefix.dev".into(), cached_grant())),
        Some(("api.basilisk.prefix.dev".into(), cached_grant())),
    ] {
        let store = storage();
        if let Some((key, auth)) = entry {
            store.store(&key, &auth).unwrap();
        }
        let (http, seen) = capture_client(false, &url, Some(store), false, StatusCode::OK);
        assert_eq!(
            http.post(url.clone()).send().await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(headers(&seen), vec![None]);
    }
    let (http, seen) = capture_client(false, &url, None, false, StatusCode::OK);
    http.post(url).send().await.unwrap();
    assert_eq!(headers(&seen), vec![None]);
}

#[tokio::test]
async fn malformed_cached_access_tokens_leave_audits_anonymous() {
    let url = Url::parse(DEFAULT_BASE_URL).unwrap();
    for token in ["", "fixture\ninvalid"] {
        let store = storage();
        let mut auth = cached_grant();
        if let Authentication::OAuth { access_token, .. } = &mut auth {
            *access_token = token.into();
        }
        store.store(CREDENTIAL_KEY, &auth).unwrap();
        let (http, seen) = capture_client(false, &url, Some(store), false, StatusCode::OK);
        assert_eq!(
            http.post(url.clone()).send().await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(headers(&seen), vec![None]);
    }
}

#[tokio::test]
async fn shared_login_is_sent_only_to_production_origin() {
    let store = storage();
    let auth = cached_grant();
    store.store(CREDENTIAL_KEY, &auth).unwrap();
    let production = Url::parse(DEFAULT_BASE_URL).unwrap();
    let (http, seen) = capture_client(
        false,
        &production,
        Some(store.clone()),
        false,
        StatusCode::OK,
    );
    http.post(production.clone()).send().await.unwrap();
    http.post(production.join("v1/audit").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(
        headers(&seen),
        vec![Some("Bearer fixture-host-token".into()); 2]
    );
    assert_eq!(store.get(CREDENTIAL_KEY).unwrap(), Some(auth));
    seen.lock().unwrap().clear();
    for other in [
        pixi_audit::DEFAULT_PYPI_BASE_URL,
        pixi_audit::DEFAULT_EPSS_BASE_URL,
        pixi_audit::DEFAULT_KEV_URL,
        "https://prefix.dev/",
        "https://custom.example/",
        "http://api.basilisk.prefix.dev/",
        "https://api.basilisk.prefix.dev:444/",
        "https://api.basilisk.prefix.dev.attacker.example/",
    ] {
        http.get(other).send().await.unwrap();
        let other = Url::parse(other).unwrap();
        let (custom, custom_seen) =
            capture_client(false, &other, Some(store.clone()), false, StatusCode::OK);
        custom.get(other).send().await.unwrap();
        assert_eq!(headers(&custom_seen), vec![None]);
    }
    assert!(headers(&seen).iter().all(Option::is_none));
}

#[tokio::test]
async fn replaced_credentials_are_checked_before_each_request() {
    let url = Url::parse(DEFAULT_BASE_URL).unwrap();
    let store = storage();
    store.store(CREDENTIAL_KEY, &cached_grant()).unwrap();
    let (http, seen) = capture_client(false, &url, Some(store.clone()), false, StatusCode::OK);
    http.post(url.clone()).send().await.unwrap();
    let mut old = cached_grant();
    if let Authentication::OAuth { audience, .. } = &mut old {
        *audience = None;
    }
    store.store(CREDENTIAL_KEY, &old).unwrap();
    http.post(url.clone()).send().await.unwrap();
    store
        .store(
            CREDENTIAL_KEY,
            &Authentication::BearerToken("fixture-channel".into()),
        )
        .unwrap();
    http.post(url).send().await.unwrap();
    assert_eq!(
        headers(&seen),
        vec![Some("Bearer fixture-host-token".into()), None, None]
    );
}

#[tokio::test]
async fn expired_login_refreshes_same_host_entry_or_audits_anonymously() {
    for success in [true, false] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let app = Router::new().route("/token", post(move |Form(form): Form<std::collections::HashMap<String, String>>| {
            assert_eq!(form["audience"], DEFAULT_BASE_URL);
            assert_eq!(form["client_id"], CLIENT_ID);
            assert_eq!(form["refresh_token"], "fixture-refresh");
            count.fetch_add(1, Ordering::SeqCst);
            async move {
                if success {
                    (StatusCode::OK, Json(json!({"access_token":"fixture-new", "refresh_token":"fixture-rotated", "expires_in":3600, "token_type":"Bearer"})))
                } else {
                    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"temporarily_unavailable"})))
                }
            }
        }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = storage();
        let old = grant(endpoint, 0);
        store.store(CREDENTIAL_KEY, &old).unwrap();
        let url = Url::parse(DEFAULT_BASE_URL).unwrap();
        let (http, seen) = capture_client(false, &url, Some(store.clone()), false, StatusCode::OK);
        assert_eq!(
            http.post(url).send().await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            headers(&seen),
            vec![success.then(|| "Bearer fixture-new".into())]
        );
        if success {
            assert!(
                matches!(store.get(CREDENTIAL_KEY).unwrap(), Some(Authentication::OAuth { refresh_token: Some(refresh), .. }) if refresh == "fixture-rotated")
            );
        } else {
            assert_eq!(store.get(CREDENTIAL_KEY).unwrap(), Some(old));
        }
        assert_eq!(store.list().unwrap().len(), 1);
        server.abort();
    }
}

#[tokio::test]
async fn rejected_login_retries_same_body_once_without_credentials() {
    let url = Url::parse(DEFAULT_BASE_URL).unwrap();
    for status in [StatusCode::OK, StatusCode::UNAUTHORIZED] {
        let store = storage();
        store.store(CREDENTIAL_KEY, &cached_grant()).unwrap();
        let (http, seen) = capture_client(false, &url, Some(store), true, status);
        let response = http
            .post(url.clone())
            .body("audit request")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(
            headers(&seen),
            vec![Some("Bearer fixture-host-token".into()), None]
        );
        let requests = seen.lock().unwrap();
        assert!(
            requests
                .iter()
                .all(|req| req.body().unwrap().as_bytes() == Some(b"audit request".as_slice()))
        );
        assert_eq!(requests[0].url(), requests[1].url());
    }
}

#[tokio::test]
async fn anonymous_401_and_other_server_errors_are_not_retried() {
    let url = Url::parse(DEFAULT_BASE_URL).unwrap();
    for (with_auth, status) in [
        (false, StatusCode::UNAUTHORIZED),
        (true, StatusCode::FORBIDDEN),
        (true, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let store = storage();
        if with_auth {
            store.store(CREDENTIAL_KEY, &cached_grant()).unwrap();
        }
        let (http, seen) = capture_client(false, &url, Some(store), false, status);
        assert_eq!(
            http.post(url.clone()).send().await.unwrap().status(),
            status
        );
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn offline_blocks_before_refresh_and_transport() {
    let store = storage();
    store
        .store(CREDENTIAL_KEY, &grant("http://127.0.0.1:1/token".into(), 0))
        .unwrap();
    let url = Url::parse(DEFAULT_BASE_URL).unwrap();
    let (http, seen) = capture_client(true, &url, Some(store), false, StatusCode::OK);
    assert!(http.post(url).send().await.is_err());
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn api_client_does_not_follow_redirects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let app = Router::new()
        .route(
            "/redirect",
            post(|| async {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [("location", "/destination")],
                )
            }),
        )
        .route(
            "/destination",
            post(move || {
                count.fetch_add(1, Ordering::SeqCst);
                async { "unexpected" }
            }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let http = client_builder(false, &url, None).unwrap().build();
    assert_eq!(
        http.post(url.join("redirect").unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::TEMPORARY_REDIRECT
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.abort();
}
