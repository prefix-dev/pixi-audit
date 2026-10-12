use super::*;
use rattler_networking::authentication_storage::backends::memory::MemoryStorage;
use std::sync::{Arc, Mutex};

type Seen = Arc<Mutex<Vec<Option<String>>>>;
struct Capture(Seen, StatusCode);

#[async_trait::async_trait]
impl Middleware for Capture {
    async fn handle(
        &self,
        request: Request,
        _extensions: &mut http::Extensions,
        _next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        self.0.lock().unwrap().push(
            request
                .headers()
                .get(AUTHORIZATION)
                .map(|value| value.to_str().unwrap().to_owned()),
        );
        Ok(http::Response::builder()
            .status(self.1)
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

fn grant() -> Authentication {
    Authentication::OAuth {
        audience: Some(DEFAULT_BASILISK_URL.into()),
        access_token: "fixture-audience".into(),
        refresh_token: Some("fixture-refresh".into()),
        expires_at: Some(i64::MAX),
        token_endpoint: "http://127.0.0.1:1/token".into(),
        revocation_endpoint: None,
        client_id: "rattler".into(),
    }
}

fn capture_client(
    url: &Url,
    store: Option<AuthenticationStorage>,
    env_token: Option<&str>,
    status: StatusCode,
) -> (ClientWithMiddleware, Seen) {
    let seen = Seen::default();
    let token = resolve_basilisk_token(env_token.map(str::to_owned), store.as_ref(), url)
        .unwrap()
        .map(|(token, _)| token);
    let http = client_builder(false, url, store, token)
        .unwrap()
        .with(Capture(seen.clone(), status))
        .build();
    (http, seen)
}

const BSK: &str = "bsk_Lm3xT9aK4fGh7JkLmN2pQrStUvWxYz0123456789";

#[tokio::test]
async fn environment_token_is_sent_to_the_configured_origin_only() {
    for base in [
        DEFAULT_BASILISK_URL,
        "https://staging.basilisk.example/api/",
    ] {
        let url = Url::parse(base).unwrap();
        let (http, seen) = capture_client(&url, None, Some(BSK), StatusCode::OK);
        http.post(url.join("v1/querybatch").unwrap())
            .send()
            .await
            .unwrap();
        for other in [
            "https://other.example/v1/querybatch",
            pixi_audit::DEFAULT_OSV_URL,
            pixi_audit::DEFAULT_EPSS_BASE_URL,
            pixi_audit::DEFAULT_KEV_URL,
        ] {
            http.get(other).send().await.unwrap();
        }
        assert_eq!(
            *seen.lock().unwrap(),
            vec![Some(format!("Bearer {BSK}")), None, None, None, None],
            "{base}"
        );
    }
}

#[tokio::test]
async fn environment_token_takes_precedence_over_the_stored_api_token() {
    let store = storage();
    store
        .store(
            "api.basilisk.prefix.dev",
            &Authentication::BearerToken(format!("bsk_{}", "A".repeat(40))),
        )
        .unwrap();
    let url = Url::parse(DEFAULT_BASILISK_URL).unwrap();
    let (http, seen) = capture_client(&url, Some(store), Some(BSK), StatusCode::OK);
    http.post(url).send().await.unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![Some(format!("Bearer {BSK}"))]);
}

#[test]
fn malformed_or_unsafe_environment_token_is_an_error_that_never_echoes_it() {
    let url = Url::parse(DEFAULT_BASILISK_URL).unwrap();
    for bad in [
        "pfx-notabasilisktoken",
        "bsk_short",
        &format!("{BSK}x"),
        "Bearer bsk_x",
    ] {
        let error = resolve_basilisk_token(Some(bad.into()), None, &url).unwrap_err();
        assert!(!error.to_string().contains(bad), "{bad}");
    }
    assert!(
        resolve_basilisk_token(Some("  ".into()), None, &url)
            .unwrap()
            .is_none()
    );
    let plain = Url::parse("http://basilisk.internal/").unwrap();
    let error = resolve_basilisk_token(Some(BSK.into()), None, &plain).unwrap_err();
    assert!(!error.to_string().contains(BSK));
    for local in [
        "http://localhost:3000/",
        "http://127.0.0.1:3000/",
        "http://[::1]:3000/",
    ] {
        let local = Url::parse(local).unwrap();
        assert!(
            resolve_basilisk_token(Some(BSK.into()), None, &local)
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn stored_token_is_used_only_for_the_exact_host_and_only_with_the_token_shape() {
    let url = Url::parse(DEFAULT_BASILISK_URL).unwrap();
    let store = storage();
    store
        .store(
            "api.basilisk.prefix.dev",
            &Authentication::BearerToken(BSK.into()),
        )
        .unwrap();
    let (http, seen) = capture_client(&url, Some(store), None, StatusCode::OK);
    http.post(url.clone()).send().await.unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![Some(format!("Bearer {BSK}"))]);

    let store = storage();
    store
        .store("*.prefix.dev", &Authentication::BearerToken(BSK.into()))
        .unwrap();
    let (http, seen) = capture_client(&url, Some(store), None, StatusCode::OK);
    http.post(url.clone()).send().await.unwrap();
    assert_eq!(*seen.lock().unwrap(), vec![None]);

    for credential in [
        Authentication::CondaToken(BSK.into()),
        Authentication::BearerToken("fixture-channel".into()),
    ] {
        let store = storage();
        store.store("api.basilisk.prefix.dev", &credential).unwrap();
        let (http, seen) = capture_client(&url, Some(store), None, StatusCode::OK);
        http.post(url.clone()).send().await.unwrap();
        assert_eq!(*seen.lock().unwrap(), vec![None]);
    }
}

#[tokio::test]
async fn rejected_api_tokens_do_not_retry_anonymously_or_use_the_shared_login() {
    for from_env in [true, false] {
        let store = storage();
        store.store("prefix.dev", &grant()).unwrap();
        if !from_env {
            store
                .store(
                    "api.basilisk.prefix.dev",
                    &Authentication::BearerToken(BSK.into()),
                )
                .unwrap();
        }
        let url = Url::parse(DEFAULT_BASILISK_URL).unwrap();
        let (http, seen) = capture_client(
            &url,
            Some(store),
            from_env.then_some(BSK),
            StatusCode::UNAUTHORIZED,
        );
        assert_eq!(
            http.post(url).send().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(*seen.lock().unwrap(), vec![Some(format!("Bearer {BSK}"))]);
    }
}
