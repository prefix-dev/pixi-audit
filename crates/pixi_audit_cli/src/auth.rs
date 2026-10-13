//! Optional shared-login authentication for the production Basilisk API.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use miette::IntoDiagnostic;
use rattler_networking::{Authentication, AuthenticationMiddleware, AuthenticationStorage};
use reqwest::{Request, Response, StatusCode, header::AUTHORIZATION};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, Middleware, Next};
use url::Url;

use pixi_audit::DEFAULT_BASILISK_URL;

const CREDENTIAL_KEY: &str = "prefix.dev";

fn production_origin(base_url: &Url) -> bool {
    base_url.origin()
        == Url::parse(DEFAULT_BASILISK_URL)
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

/// Build a client with optional authentication, without initiating login.
pub(super) fn build(base_url: &Url) -> miette::Result<ClientWithMiddleware> {
    validate_base_url(base_url)?;
    let storage = if production_origin(base_url) {
        match AuthenticationStorage::from_env_and_defaults() {
            Ok(storage) => Some(storage),
            Err(_) => {
                eprintln!("Warning: Could not load audit credentials; continuing anonymously");
                None
            }
        }
    } else {
        None
    };
    Ok(client_builder(base_url, storage)?.build())
}

fn shared_login_available(storage: &AuthenticationStorage, warned: &AtomicBool) -> bool {
    match storage.get(CREDENTIAL_KEY) {
        Ok(Some(Authentication::OAuth {
            audience,
            access_token,
            ..
        })) => {
            if audience.as_deref() == Some(DEFAULT_BASILISK_URL)
                && !access_token.is_empty()
                && reqwest::header::HeaderValue::from_str(&format!("Bearer {access_token}")).is_ok()
            {
                true
            } else {
                if !warned.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "Warning: Saved prefix.dev login has no Basilisk audience or has an invalid token; \
                         continuing anonymously. Run `pixi auth login prefix.dev --oauth-audience {DEFAULT_BASILISK_URL}` to log in again."
                    );
                }
                false
            }
        }
        // Channel API tokens are not Basilisk credentials.
        Ok(_) => false,
        Err(_) => {
            if !warned.swap(true, Ordering::Relaxed) {
                eprintln!("Warning: Could not read prefix.dev credentials; continuing anonymously");
            }
            false
        }
    }
}

fn client_builder(
    base_url: &Url,
    storage: Option<AuthenticationStorage>,
) -> miette::Result<ClientBuilder> {
    validate_base_url(base_url)?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .into_diagnostic()?;
    let mut builder = ClientBuilder::new(http);
    if production_origin(base_url)
        && let Some(storage) = storage
    {
        builder = builder
            .with(SharedLogin {
                authentication: AuthenticationMiddleware::from_auth_storage(storage.clone())
                    .with_credentials_from(
                        url::Host::Domain(CREDENTIAL_KEY.to_owned()),
                        [base_url.origin()],
                    ),
                storage,
                origin: base_url.origin(),
                warned: AtomicBool::new(false),
            })
            // Retry after authentication to avoid reattaching credentials.
            .with(AnonymousRetry::default());
    }
    Ok(builder)
}

/// Validate the saved login before each request.
struct SharedLogin {
    authentication: AuthenticationMiddleware,
    storage: AuthenticationStorage,
    origin: url::Origin,
    warned: AtomicBool,
}

#[async_trait::async_trait]
impl Middleware for SharedLogin {
    async fn handle(
        &self,
        request: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        if request.url().origin() != self.origin
            || !shared_login_available(&self.storage, &self.warned)
        {
            return next.run(request, extensions).await;
        }
        self.authentication.handle(request, extensions, next).await
    }
}

/// Retry authenticated HTTP 401 responses once without credentials.
#[derive(Default)]
struct AnonymousRetry {
    warned: AtomicBool,
}

#[async_trait::async_trait]
impl Middleware for AnonymousRetry {
    async fn handle(
        &self,
        request: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let retry = request
            .headers()
            .contains_key(AUTHORIZATION)
            .then(|| request.try_clone())
            .flatten();
        let response = next.clone().run(request, extensions).await?;
        if response.status() == StatusCode::UNAUTHORIZED
            && let Some(mut retry) = retry
        {
            if !self.warned.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "Warning: Basilisk rejected the saved login; retrying anonymously. \
                     Run `pixi auth login prefix.dev --oauth-audience {DEFAULT_BASILISK_URL}` to log in again."
                );
            }
            retry.headers_mut().remove(AUTHORIZATION);
            return next.run(retry, extensions).await;
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
