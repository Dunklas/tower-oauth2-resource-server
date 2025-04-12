use core::fmt;
use std::sync::Arc;

use http::Request;
use log::{debug, info};
use serde::de::DeserializeOwned;
use url::Url;

use crate::{
    claims::DefaultClaims,
    error::{AuthError, StartupError},
    jwks::{JwksProducer, TimerJwksProducer},
    jwt_extract::{BearerTokenJwtExtractor, JwtExtractor},
    jwt_validate::{JwtValidator, OnlyJwtValidator},
    layer::OAuth2ResourceServerLayer,
    tenant::TenantConfiguration,
    validation::ClaimsValidationSpec,
};

use mockall_double::double;

#[double]
use crate::oidc::OidcDiscovery;

/// OAuth2ResourceServer
///
/// This is the actual middleware.
/// May be turned into a tower layer by calling [into_layer](OAuth2ResourceServer::into_layer).
#[derive(Clone)]
pub struct OAuth2ResourceServer<Claims = DefaultClaims> {
    jwt_validator: Arc<dyn JwtValidator<Claims> + Send + Sync>,
    jwt_extractor: Arc<dyn JwtExtractor + Send + Sync>,
    #[allow(dead_code)]
    jwks_producer: Arc<dyn JwksProducer + Send + Sync>,
}

impl<Claims> OAuth2ResourceServer<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    pub(crate) async fn new(
        tenant_configurations: Vec<TenantConfiguration>,
    ) -> Result<OAuth2ResourceServer<Claims>, StartupError> {
        let config = tenant_configurations.into_iter().next().unwrap();
        let (jwks_url, claims_validation_spec) =
            resolve_config(config.issuer_url, config.jwks_url, config.audiences).await?;
        let claims_validation_spec = config
            .claims_validation_spec
            .unwrap_or(claims_validation_spec);
        info!(
            "Will validate the following claims: {}",
            claims_validation_spec
        );

        let validator = Arc::new(OnlyJwtValidator::new(claims_validation_spec));

        let mut jwks_producer =
            TimerJwksProducer::new(jwks_url.clone(), config.jwks_refresh_interval);
        jwks_producer.add_consumer(validator.clone());
        jwks_producer.start();

        Ok(OAuth2ResourceServer {
            jwt_validator: validator,
            jwt_extractor: Arc::new(BearerTokenJwtExtractor {}),
            jwks_producer: Arc::new(jwks_producer),
        })
    }

    pub(crate) async fn authorize_request<Body>(
        &self,
        mut request: Request<Body>,
    ) -> Result<Request<Body>, AuthError> {
        let token = match self.jwt_extractor.extract_jwt(request.headers()) {
            Ok(token) => token,
            Err(e) => {
                debug!("JWT extraction failed: {}", e);
                return Err(e);
            }
        };
        match self.jwt_validator.validate(&token).await {
            Ok(res) => {
                debug!("JWT validation successful");
                request.extensions_mut().insert(res);
                Ok(request)
            }
            Err(e) => {
                debug!("JWT validation failed: {}", e);
                Err(e)
            }
        }
    }
}

impl<Claims> fmt::Debug for OAuth2ResourceServer<Claims>
where
    Claims: DeserializeOwned,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2AuthenticationManager").finish()
    }
}

impl<Claims> OAuth2ResourceServer<Claims>
where
    Claims: Clone + DeserializeOwned,
{
    /// Returns a [tower layer](https://docs.rs/tower/latest/tower/trait.Layer.html).
    pub fn into_layer(&self) -> OAuth2ResourceServerLayer<Claims> {
        OAuth2ResourceServerLayer::new(self.clone())
    }
}

async fn resolve_config(
    issuer_url: Option<String>,
    jwks_url: Option<String>,
    audiences: Vec<String>,
) -> Result<(Url, ClaimsValidationSpec), StartupError> {
    let mut claims_spec = ClaimsValidationSpec::new().aud(audiences).exp(true);
    if let Some(issuer_uri) = &issuer_url {
        claims_spec = claims_spec.iss(issuer_uri);
    }

    if let Some(jwks_url) = jwks_url {
        let jwks_url = jwks_url.parse::<Url>().map_err(|_| {
            StartupError::InvalidParameter(format!("Invalid jwks_url: {}", jwks_url))
        })?;
        return Ok((jwks_url, claims_spec));
    }
    let issuer_url = issuer_url.ok_or(StartupError::InvalidParameter(format!(
        "Missing issuer url"
    )))?;
    let issuer_url = issuer_url.parse::<Url>().map_err(|_| {
        StartupError::InvalidParameter(format!("Invalid issuer_url: {}", issuer_url))
    })?;
    let oidc_config = OidcDiscovery::discover(&issuer_url)
        .await
        .map_err(|e| StartupError::OidcDiscoveryFailed(e.to_string()))?;

    if let Some(claims_supported) = &oidc_config.claims_supported {
        if claims_supported.contains(&"nbf".to_owned()) {
            claims_spec = claims_spec.nbf(true);
        }
    }
    Ok((oidc_config.jwks_uri, claims_spec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::{MockOidcDiscovery, OidcConfig};
    use std::sync::Mutex;

    static MTX: Mutex<()> = Mutex::new(());

    #[tokio::test]
    async fn test_should_perform_oidc_discovery() {
        let _m = MTX.lock();
        let ctx = MockOidcDiscovery::discover_context();
        ctx.expect()
            .returning(|_| {
                Ok(OidcConfig {
                    jwks_uri: "http://some-issuer.com/jwks".parse::<Url>().unwrap(),
                    claims_supported: None,
                })
            })
            .once();

        let result = <OAuth2ResourceServer>::new(vec![TenantConfiguration::builder()
            .issuer_url("http://some-issuer.com")
            .build()
            .unwrap()])
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_should_skip_oidc_discovery_if_jwks_url_set() {
        let _m = MTX.lock();
        let ctx = MockOidcDiscovery::discover_context();
        ctx.expect().never();

        let result = <OAuth2ResourceServer>::new(vec![TenantConfiguration::builder()
            .issuer_url("http://some-issuer.com")
            .jwks_url("https://some-issuer.com/jwks")
            .build()
            .unwrap()])
        .await;
        assert!(result.is_ok());
    }
}
