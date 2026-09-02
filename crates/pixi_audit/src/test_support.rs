use axum::Router;
use reqwest_middleware::ClientWithMiddleware;
use url::Url;

use crate::client::{BasiliskClient, PypiAuditClient};

pub async fn spawn_router(app: Router) -> Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Url::parse(&format!("http://{addr}/")).unwrap()
}

fn http_client() -> ClientWithMiddleware {
    reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build()
}

pub fn basilisk_client(base_url: Url) -> BasiliskClient {
    BasiliskClient::new(http_client(), base_url)
}

pub fn pypi_client(base_url: Url) -> PypiAuditClient {
    PypiAuditClient::new(http_client(), base_url)
}
