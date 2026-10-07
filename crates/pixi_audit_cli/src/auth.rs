//! Audit transport is separate from package downloads: no channel credentials,
//! mirror rewriting, or automatic challenge-driven login.
//!
//! Two credentials can authenticate a Basilisk audit, in this order of
//! precedence: a Basilisk user API token (`bsk_…`, for CI and scripts) and the
//! prefix.dev OAuth audience grant obtained by `--login`. Both are optional; a
//! public audit always remains the fallback.

use std::{io::IsTerminal, time::Duration};

use miette::IntoDiagnostic;
use rattler::cli::auth::oauth::{
    CallbackPageTemplate, OAuthConfig, OAuthFlow, callback_page_renderer, perform_oauth_login,
};
use rattler_networking::{
    Authentication, AuthenticationMiddleware, AuthenticationStorage, OfflineMiddleware,
};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use url::{Origin, Url};

use pixi_audit::{DEFAULT_BASE_URL, TOKEN_ENV_VAR, looks_like_basilisk_token};

const ISSUER: &str = "https://prefix.dev";
const CLIENT_ID: &str = "rattler";

/// A Basilisk user API token bound to the one origin it may be sent to.
/// `Debug` never prints the token.
#[derive(Clone)]
pub(super) struct BasiliskToken {
    token: String,
    origin: Origin,
}

impl std::fmt::Debug for BasiliskToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasiliskToken")
            .field("token", &"<redacted>")
            .field("origin", &self.origin.ascii_serialization())
            .finish()
    }
}

/// Where a token came from, for the one-line notice that explains an
/// authenticated audit without echoing any secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TokenSource {
    Environment,
    AuthStore,
}

/// A token may travel only where it cannot be read in transit: TLS, or plain
/// HTTP to the local machine (a developer's own Basilisk).
fn token_transport_allowed(base_url: &Url) -> bool {
    match base_url.scheme() {
        "https" => true,
        "http" => matches!(
            base_url.host(),
            Some(url::Host::Domain("localhost"))
                | Some(url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST))
                | Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST))
        ),
        _ => false,
    }
}

/// Resolve the Basilisk token for `base_url`, if any.
///
/// `PIXI_AUDIT_TOKEN` wins; a malformed value there is an error, because a
/// CI secret that silently falls back to an anonymous audit is worse than a
/// failed job. Otherwise a `BearerToken` stored for the *exact* audit host
/// (`pixi auth login <host> --token bsk_…`) is used when it has the token
/// shape; the wildcard host walk is never consulted, so a `*.prefix.dev`
/// channel credential cannot reach the audit API. Anything else is ignored.
pub(super) fn resolve_basilisk_token(
    env_value: Option<String>,
    storage: Option<&AuthenticationStorage>,
    base_url: &Url,
) -> miette::Result<Option<(BasiliskToken, TokenSource)>> {
    let origin = base_url.origin();
    if let Some(value) = env_value {
        let value = value.trim().to_owned();
        if value.is_empty() {
            return Ok(None);
        }
        if !looks_like_basilisk_token(&value) {
            miette::bail!(
                "{TOKEN_ENV_VAR} is not a Basilisk API token (expected `bsk_` followed by 40 alphanumeric characters)"
            );
        }
        if !token_transport_allowed(base_url) {
            miette::bail!(
                "{TOKEN_ENV_VAR} is set but the audit API URL is not HTTPS (or local HTTP); refusing to send the token"
            );
        }
        return Ok(Some((
            BasiliskToken {
                token: value,
                origin,
            },
            TokenSource::Environment,
        )));
    }
    let Some(storage) = storage else {
        return Ok(None);
    };
    if !token_transport_allowed(base_url) {
        return Ok(None);
    }
    let Some(host) = base_url.host_str() else {
        return Ok(None);
    };
    match storage.get(host) {
        Ok(Some(Authentication::BearerToken(value))) if looks_like_basilisk_token(&value) => {
            Ok(Some((
                BasiliskToken {
                    token: value,
                    origin,
                },
                TokenSource::AuthStore,
            )))
        }
        _ => Ok(None),
    }
}

/// Sends the Basilisk token to its origin and nowhere else. Runs ahead of the
/// audience middleware, which skips requests that already carry
/// `Authorization`, so an explicit token takes precedence over `--login`.
struct BasiliskTokenMiddleware(BasiliskToken);

#[async_trait::async_trait]
impl reqwest_middleware::Middleware for BasiliskTokenMiddleware {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        if req.url().origin() == self.0.origin && req.headers().get(AUTHORIZATION).is_none() {
            let mut value = HeaderValue::from_str(&format!("Bearer {}", self.0.token))
                .map_err(reqwest_middleware::Error::middleware)?;
            value.set_sensitive(true);
            req.headers_mut().insert(AUTHORIZATION, value);
        }
        next.run(req, extensions).await
    }
}

fn production_origin(base_url: &Url) -> bool {
    base_url.origin()
        == Url::parse(DEFAULT_BASE_URL)
            .expect("valid default API URL")
            .origin()
}

fn validate_base_url(base_url: &Url) -> miette::Result<()> {
    if !matches!(base_url.scheme(), "http" | "https")
        || base_url.host_str().is_none()
        || !base_url.username().is_empty()
        || base_url.password().is_some()
        || base_url.query().is_some()
        || base_url.fragment().is_some()
    {
        miette::bail!(
            "Audit API URL must be HTTP(S), without credentials, query parameters, or a fragment"
        );
    }
    Ok(())
}

fn interactive_login_allowed(offline: bool, in_ci: bool, terminal: bool) -> bool {
    !offline && !in_ci && terminal
}

/// Build the audit client, optionally performing an explicitly requested login.
/// Credential failures never prevent an otherwise public audit.
pub(super) async fn build(
    offline: bool,
    base_url: &Url,
    login: bool,
) -> miette::Result<ClientWithMiddleware> {
    validate_base_url(base_url)?;
    // The audience grant is production-only; a Basilisk token may also be
    // used against a custom origin (staging, self-hosted), so the store is
    // loaded whenever a credential could legitimately be sent.
    let storage = if !offline && token_transport_allowed(base_url) {
        match AuthenticationStorage::from_env_and_defaults() {
            Ok(storage) => Some(storage),
            Err(_error) => {
                eprintln!("Warning: Could not load audit credentials; continuing anonymously");
                None
            }
        }
    } else {
        None
    };

    let token = if offline {
        None
    } else {
        resolve_basilisk_token(
            std::env::var(TOKEN_ENV_VAR).ok(),
            storage.as_ref(),
            base_url,
        )?
    };
    if let Some((_, source)) = &token {
        let via = match source {
            TokenSource::Environment => TOKEN_ENV_VAR,
            TokenSource::AuthStore => "the stored credential for the audit host",
        };
        eprintln!("Auditing with the Basilisk API token from {via}");
        if login {
            eprintln!("A Basilisk API token is configured; skipping --login");
        }
    }
    let login = login && token.is_none();

    if login {
        if !production_origin(base_url) {
            eprintln!(
                "Audit login is only supported for the default Basilisk origin; continuing anonymously"
            );
        } else if !interactive_login_allowed(
            offline,
            std::env::var_os("CI").is_some(),
            std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        ) {
            eprintln!("Warning: Skipping audit login in offline, CI, or noninteractive mode");
        } else if let Some(storage) = &storage {
            let oauth = OAuthConfig {
                audience: Some(DEFAULT_BASE_URL.into()),
                issuer_url: ISSUER.into(),
                client_id: CLIENT_ID.into(),
                client_secret: None,
                flow: OAuthFlow::Auto,
                scopes: Default::default(),
                redirect_uri: None,
                user_agent: Some(format!("pixi-audit/{}", env!("CARGO_PKG_VERSION"))),
                callback_page: Some(callback_page_renderer(
                    CallbackPageTemplate {
                        application_name: "pixi-audit".into(),
                        ..Default::default()
                    },
                    ISSUER,
                )),
            };
            match tokio::time::timeout(Duration::from_secs(300), perform_oauth_login(oauth)).await {
                Ok(Ok(auth)) => {
                    let key = AuthenticationStorage::oauth_audience_key(
                        ISSUER,
                        CLIENT_ID,
                        DEFAULT_BASE_URL,
                    );
                    if storage.store(&key, &auth).is_err() {
                        eprintln!(
                            "Could not save audit credentials; continuing with cached credentials if available"
                        );
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    eprintln!(
                        "Audit login did not complete; continuing with cached credentials if available"
                    );
                }
            }
        }
    }

    Ok(client_builder(offline, base_url, storage, token.map(|(token, _)| token))?.build())
}

fn client_builder(
    offline: bool,
    base_url: &Url,
    storage: Option<AuthenticationStorage>,
    token: Option<BasiliskToken>,
) -> miette::Result<ClientBuilder> {
    validate_base_url(base_url)?;
    // Dedicated API transport: never redirect a bearer to another service.
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .into_diagnostic()?;
    let mut builder = ClientBuilder::new(http);
    if offline {
        builder = builder.with(OfflineMiddleware);
    }
    if let Some(token) = token
        && !offline
        && token_transport_allowed(base_url)
    {
        builder = builder.with(BasiliskTokenMiddleware(token));
    }
    if production_origin(base_url)
        && !offline
        && let Some(storage) = storage
    {
        builder = builder.with(
            AuthenticationMiddleware::from_auth_storage(storage).with_oauth_audience(
                ISSUER,
                CLIENT_ID,
                DEFAULT_BASE_URL,
                base_url.origin(),
            ),
        );
    }
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::Form, http::StatusCode, routing::post};
    use rattler_networking::{
        Authentication, authentication_storage::backends::memory::MemoryStorage,
    };
    use serde_json::json;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    type Seen = Arc<Mutex<Vec<Option<String>>>>;
    struct Capture(Seen);
    #[async_trait::async_trait]
    impl reqwest_middleware::Middleware for Capture {
        async fn handle(
            &self,
            req: reqwest::Request,
            _extensions: &mut http::Extensions,
            _next: reqwest_middleware::Next<'_>,
        ) -> reqwest_middleware::Result<reqwest::Response> {
            self.0.lock().unwrap().push(
                req.headers()
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_owned()),
            );
            Ok(http::Response::builder()
                .status(200)
                .body("{}")
                .unwrap()
                .into())
        }
    }
    fn key() -> String {
        AuthenticationStorage::oauth_audience_key(ISSUER, CLIENT_ID, DEFAULT_BASE_URL)
    }
    fn storage() -> AuthenticationStorage {
        let mut store = AuthenticationStorage::empty();
        store.add_backend(Arc::new(MemoryStorage::new()));
        store
    }
    fn grant(endpoint: String, expiry: i64) -> Authentication {
        Authentication::OAuth {
            audience: Some(DEFAULT_BASE_URL.into()),
            access_token: "fixture-audience".into(),
            refresh_token: Some("fixture-refresh".into()),
            expires_at: Some(expiry),
            token_endpoint: endpoint,
            revocation_endpoint: None,
            client_id: CLIENT_ID.into(),
        }
    }
    fn capture_client(
        offline: bool,
        url: &Url,
        store: Option<AuthenticationStorage>,
    ) -> (ClientWithMiddleware, Seen) {
        capture_client_with_token(offline, url, store, None)
    }
    fn capture_client_with_token(
        offline: bool,
        url: &Url,
        store: Option<AuthenticationStorage>,
        env_token: Option<&str>,
    ) -> (ClientWithMiddleware, Seen) {
        let seen = Seen::default();
        let token = resolve_basilisk_token(env_token.map(str::to_owned), store.as_ref(), url)
            .unwrap()
            .map(|(token, _)| token);
        let http = client_builder(offline, url, store, token)
            .unwrap()
            .with(Capture(seen.clone()))
            .build();
        (http, seen)
    }
    const BSK: &str = "bsk_Lm3xT9aK4fGh7JkLmN2pQrStUvWxYz0123456789";

    #[test]
    fn login_requires_online_interactive_non_ci_execution() {
        for offline in [false, true] {
            for ci in [false, true] {
                for terminal in [false, true] {
                    assert_eq!(
                        interactive_login_allowed(offline, ci, terminal),
                        !offline && !ci && terminal
                    );
                }
            }
        }
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
        assert!(!production_origin(
            &Url::parse("http://api.basilisk.prefix.dev").unwrap()
        ));
        assert!(!production_origin(
            &Url::parse("https://api.basilisk.prefix.dev:444").unwrap()
        ));
    }

    #[tokio::test]
    async fn public_audit_does_not_use_channel_credentials() {
        let url = Url::parse(DEFAULT_BASE_URL).unwrap();
        let store = storage();
        store
            .store(
                "api.basilisk.prefix.dev",
                &Authentication::BearerToken("fixture-channel".into()),
            )
            .unwrap();
        for store in [None, Some(store)] {
            let (http, seen) = capture_client(false, &url, store);
            assert_eq!(
                http.post(url.clone()).send().await.unwrap().status(),
                StatusCode::OK
            );
            assert_eq!(*seen.lock().unwrap(), vec![None]);
        }
    }

    #[tokio::test]
    async fn environment_token_is_sent_to_the_configured_origin_only() {
        for base in [DEFAULT_BASE_URL, "https://staging.basilisk.example/api/"] {
            let url = Url::parse(base).unwrap();
            let (http, seen) = capture_client_with_token(false, &url, None, Some(BSK));
            http.post(url.join("v1/querybatch").unwrap())
                .send()
                .await
                .unwrap();
            for other in [
                "https://other.example/v1/querybatch",
                pixi_audit::DEFAULT_PYPI_BASE_URL,
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
    async fn environment_token_takes_precedence_over_the_audience_grant() {
        let store = storage();
        store
            .store(&key(), &grant("http://127.0.0.1:1/token".into(), i64::MAX))
            .unwrap();
        let url = Url::parse(DEFAULT_BASE_URL).unwrap();
        let (http, seen) = capture_client_with_token(false, &url, Some(store), Some(BSK));
        http.post(url).send().await.unwrap();
        assert_eq!(*seen.lock().unwrap(), vec![Some(format!("Bearer {BSK}"))]);
    }

    #[test]
    fn malformed_or_unsafe_environment_token_is_an_error_that_never_echoes_it() {
        let url = Url::parse(DEFAULT_BASE_URL).unwrap();
        for bad in [
            "pfx-notabasilisktoken",
            "bsk_short",
            &format!("{BSK}x"),
            "Bearer bsk_x",
        ] {
            let error = resolve_basilisk_token(Some(bad.into()), None, &url).unwrap_err();
            assert!(!error.to_string().contains(bad), "{bad}");
        }
        // Blank is "unset", not an error.
        assert!(
            resolve_basilisk_token(Some("  ".into()), None, &url)
                .unwrap()
                .is_none()
        );
        // Non-local plain HTTP refuses to carry a secret; local plain HTTP is a
        // developer's own instance.
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
        let url = Url::parse(DEFAULT_BASE_URL).unwrap();
        // A Basilisk token stored for the exact audit host is sent.
        let store = storage();
        store
            .store(
                "api.basilisk.prefix.dev",
                &Authentication::BearerToken(BSK.into()),
            )
            .unwrap();
        let (http, seen) = capture_client(false, &url, Some(store));
        http.post(url.clone()).send().await.unwrap();
        assert_eq!(*seen.lock().unwrap(), vec![Some(format!("Bearer {BSK}"))]);

        // A wildcard prefix.dev channel credential, even with the token shape, is not consulted.
        let store = storage();
        store
            .store("*.prefix.dev", &Authentication::BearerToken(BSK.into()))
            .unwrap();
        let (http, seen) = capture_client(false, &url, Some(store));
        http.post(url.clone()).send().await.unwrap();
        assert_eq!(*seen.lock().unwrap(), vec![None]);

        // Other credential kinds for the exact host are ignored too.
        let store = storage();
        store
            .store(
                "api.basilisk.prefix.dev",
                &Authentication::CondaToken(BSK.into()),
            )
            .unwrap();
        let (http, seen) = capture_client(false, &url, Some(store));
        http.post(url).send().await.unwrap();
        assert_eq!(*seen.lock().unwrap(), vec![None]);
    }

    #[tokio::test]
    async fn cached_audience_is_sent_only_to_production_origin() {
        let store = storage();
        let auth = grant("http://127.0.0.1:1/token".into(), i64::MAX);
        store.store(&key(), &auth).unwrap();
        let production = Url::parse(DEFAULT_BASE_URL).unwrap();
        let (http, seen) = capture_client(false, &production, Some(store.clone()));
        http.post(production.clone()).send().await.unwrap();
        http.post(production.clone()).send().await.unwrap();
        http.post("https://custom.example/api")
            .send()
            .await
            .unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                Some("Bearer fixture-audience".into()),
                Some("Bearer fixture-audience".into()),
                None
            ]
        );
        assert_eq!(store.get(&key()).unwrap(), Some(auth));
        for service in [
            pixi_audit::DEFAULT_PYPI_BASE_URL,
            pixi_audit::DEFAULT_EPSS_BASE_URL,
            pixi_audit::DEFAULT_KEV_URL,
        ] {
            let (http, seen) = capture_client(false, &production, Some(store.clone()));
            http.get(service).send().await.unwrap();
            assert_eq!(*seen.lock().unwrap(), vec![None]);
        }
        for url in [
            "https://custom.example/",
            "http://api.basilisk.prefix.dev/",
            "https://api.basilisk.prefix.dev:444/",
        ] {
            let url = Url::parse(url).unwrap();
            let (http, seen) = capture_client(false, &url, Some(store.clone()));
            http.post(url).send().await.unwrap();
            assert_eq!(*seen.lock().unwrap(), vec![None]);
        }
    }

    #[tokio::test]
    async fn expired_audience_refreshes_or_falls_back_to_public_audit() {
        for success in [true, false] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let app = Router::new().route("/token", post(move |Form(form): Form<std::collections::HashMap<String,String>>| {
                assert_eq!(form["audience"], DEFAULT_BASE_URL);
                assert_eq!(form["client_id"], CLIENT_ID);
                assert_eq!(form["refresh_token"], "fixture-refresh");
                count.fetch_add(1, Ordering::SeqCst);
                async move {
                    if success { (StatusCode::OK, Json(json!({"access_token":"fixture-new", "refresh_token":"fixture-rotated", "expires_in":3600,"token_type":"Bearer"}))) }
                    else { (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"temporarily_unavailable"}))) }
                }
            }));
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let store = storage();
            let old = grant(endpoint, 0);
            store.store(&key(), &old).unwrap();
            let url = Url::parse(DEFAULT_BASE_URL).unwrap();
            let (http, seen) = capture_client(false, &url, Some(store.clone()));
            assert_eq!(
                http.post(url).send().await.unwrap().status(),
                StatusCode::OK
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let expected = success.then(|| "Bearer fixture-new".to_owned());
            assert_eq!(*seen.lock().unwrap(), vec![expected]);
            if success {
                assert!(
                    matches!(store.get(&key()).unwrap(), Some(Authentication::OAuth { refresh_token: Some(refresh), .. }) if refresh == "fixture-rotated")
                );
            } else {
                assert_eq!(store.get(&key()).unwrap(), Some(old));
            }
            server.abort();
        }
    }

    #[tokio::test]
    async fn offline_blocks_before_authentication_and_transport() {
        let store = storage();
        store
            .store(&key(), &grant("http://127.0.0.1:1/token".into(), 0))
            .unwrap();
        let url = Url::parse(DEFAULT_BASE_URL).unwrap();
        let (http, seen) = capture_client(true, &url, Some(store));
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
        let http = client_builder(false, &url, None, None).unwrap().build();
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
}
