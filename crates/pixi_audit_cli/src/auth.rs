//! Optional Basilisk API-token and shared-login authentication.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use miette::IntoDiagnostic;
use rattler_networking::{
    Authentication, AuthenticationMiddleware, AuthenticationStorage, OfflineMiddleware,
};
use reqwest::{
    Request, Response, StatusCode,
    header::{AUTHORIZATION, HeaderValue},
};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, Middleware, Next};
use url::{Origin, Url};

use pixi_audit::{DEFAULT_BASILISK_URL, TOKEN_ENV_VAR, looks_like_basilisk_token};

const CREDENTIAL_KEY: &str = "prefix.dev";

/// A Basilisk user API token bound to one origin, redacted in debug output.
#[derive(Clone)]
pub(super) struct BasiliskToken {
    token: String,
    origin: Origin,
}

impl BasiliskToken {
    fn parse(token: String, origin: Origin) -> miette::Result<Self> {
        if !looks_like_basilisk_token(&token) {
            miette::bail!(
                "Invalid Basilisk API token (expected `bsk_` followed by 40 alphanumeric characters)"
            );
        }
        Ok(Self { token, origin })
    }
}

impl std::fmt::Debug for BasiliskToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasiliskToken")
            .field("token", &"<redacted>")
            .field("origin", &self.origin.ascii_serialization())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TokenSource {
    Environment,
    AuthStore,
}

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

/// Prefer the environment token, then a token stored for the exact audit host.
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
        let token = BasiliskToken::parse(value, origin)?;
        if !token_transport_allowed(base_url) {
            miette::bail!(
                "{TOKEN_ENV_VAR} is set but the audit API URL is not HTTPS (or local HTTP); refusing to send the token"
            );
        }
        return Ok(Some((token, TokenSource::Environment)));
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
        Ok(Some(Authentication::BearerToken(value))) => Ok(BasiliskToken::parse(value, origin)
            .ok()
            .map(|token| (token, TokenSource::AuthStore))),
        _ => Ok(None),
    }
}

struct BasiliskTokenMiddleware(BasiliskToken);

#[async_trait::async_trait]
impl Middleware for BasiliskTokenMiddleware {
    async fn handle(
        &self,
        mut request: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        if request.url().origin() == self.0.origin && !request.headers().contains_key(AUTHORIZATION)
        {
            let mut value = HeaderValue::from_str(&format!("Bearer {}", self.0.token))
                .map_err(reqwest_middleware::Error::middleware)?;
            value.set_sensitive(true);
            request.headers_mut().insert(AUTHORIZATION, value);
        }
        next.run(request, extensions).await
    }
}

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
pub(super) fn build(offline: bool, base_url: &Url) -> miette::Result<ClientWithMiddleware> {
    validate_base_url(base_url)?;
    let storage = if token_transport_allowed(base_url) && !offline {
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
    }
    Ok(client_builder(offline, base_url, storage, token.map(|(token, _)| token))?.build())
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
    offline: bool,
    base_url: &Url,
    storage: Option<AuthenticationStorage>,
    token: Option<BasiliskToken>,
) -> miette::Result<ClientBuilder> {
    validate_base_url(base_url)?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .into_diagnostic()?;
    let mut builder = ClientBuilder::new(http);
    if offline {
        builder = builder.with(OfflineMiddleware);
    } else if let Some(token) = token
        && token_transport_allowed(base_url)
    {
        builder = builder.with(BasiliskTokenMiddleware(token));
    } else if production_origin(base_url)
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
#[cfg(test)]
mod token_tests;
