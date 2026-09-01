use axum::Router;
use url::Url;

use crate::client::BasiliskClient;

pub async fn spawn_router(app: Router) -> Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Url::parse(&format!("http://{addr}/")).unwrap()
}

pub fn basilisk_client(base_url: Url) -> BasiliskClient {
    let http = reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build();
    BasiliskClient::new(http, base_url)
}
