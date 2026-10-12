use super::*;
use rattler_networking::authentication_storage::backends::file::FileStorage;
use std::sync::{Arc, Mutex};

struct Capture(Arc<Mutex<Option<Request>>>);

#[async_trait::async_trait]
impl Middleware for Capture {
    async fn handle(
        &self,
        request: Request,
        _extensions: &mut http::Extensions,
        _next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        *self.0.lock().unwrap() = Some(request);
        Ok(http::Response::builder()
            .status(StatusCode::OK)
            .body("{}")
            .unwrap()
            .into())
    }
}

#[tokio::test]
async fn sends_saved_pixi_login_to_basilisk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let mut pixi_storage = AuthenticationStorage::empty();
    pixi_storage.add_backend(Arc::new(FileStorage::from_path(path.clone()).unwrap()));
    pixi_storage
        .store(
            "prefix.dev",
            &Authentication::OAuth {
                audience: Some(DEFAULT_BASE_URL.into()),
                access_token: "fixture-pixi-access-token".into(),
                refresh_token: None,
                expires_at: Some(i64::MAX),
                token_endpoint: "https://prefix.dev/token".into(),
                revocation_endpoint: None,
                client_id: "rattler".into(),
            },
        )
        .unwrap();

    let mut audit_storage = AuthenticationStorage::empty();
    audit_storage.add_backend(Arc::new(FileStorage::from_path(path).unwrap()));
    let url = Url::parse(DEFAULT_BASE_URL).unwrap();
    let captured = Arc::new(Mutex::new(None));
    let client = client_builder(false, &url, Some(audit_storage))
        .unwrap()
        .with(Capture(captured.clone()))
        .build();

    client.post(url.clone()).send().await.unwrap();

    let request = captured.lock().unwrap().take().unwrap();
    assert_eq!(request.url(), &url);
    assert_eq!(request.url().host_str(), Some("api.basilisk.prefix.dev"));
    assert_eq!(
        request.headers().get(AUTHORIZATION).unwrap(),
        "Bearer fixture-pixi-access-token"
    );
}
