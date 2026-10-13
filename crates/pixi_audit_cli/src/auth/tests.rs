use super::*;
use rattler_networking::authentication_storage::backends::file::FileStorage;
use reqwest::{StatusCode, header::AUTHORIZATION};
use std::sync::{Arc, Mutex};

struct Capture(Arc<Mutex<Option<Request>>>, StatusCode);

#[async_trait::async_trait]
impl Middleware for Capture {
    async fn handle(
        &self,
        request: Request,
        _extensions: &mut http::Extensions,
        _next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        assert!(
            self.0.lock().unwrap().replace(request).is_none(),
            "unexpected retry"
        );
        Ok(http::Response::builder()
            .status(self.1)
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
                audience: Some(DEFAULT_BASILISK_URL.into()),
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
    let url = Url::parse(DEFAULT_BASILISK_URL).unwrap();
    for status in [StatusCode::OK, StatusCode::UNAUTHORIZED] {
        let captured = Arc::new(Mutex::new(None));
        let client = client_builder(&url, Some(audit_storage.clone()), None)
            .unwrap()
            .with(Capture(captured.clone(), status))
            .build();

        let response = client.post(url.clone()).send().await.unwrap();
        assert_eq!(response.status(), status);

        let request = captured.lock().unwrap().take().unwrap();
        assert_eq!(request.url(), &url);
        assert_eq!(request.url().host_str(), Some("api.basilisk.prefix.dev"));
        assert_eq!(
            request.headers().get(AUTHORIZATION).unwrap(),
            "Bearer fixture-pixi-access-token"
        );
    }
}
