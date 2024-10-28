use core::fmt;
use std::{sync::Arc, time::Duration};

use http::Request;
use log::{debug, info};
use serde::de::DeserializeOwned;
use url::Url;

use crate::{
    builder::OAuth2ResourceServerBuilder,
    claims::DefaultClaims,
    error::{AuthError, StartupError},
    jwks::JwksDecodingKeysProvider,
    jwt::{BearerTokenJwtExtractor, JwtExtractor, JwtValidator, OnlyJwtValidator},
    layer::OAuth2ResourceServerLayer,
    validation::ClaimsValidationSpec,
};

use mockall_double::double;

#[double]
use crate::oidc::OidcDiscovery;

#[derive(Clone)]
pub struct OAuth2ResourceServer<Claims = DefaultClaims> {
    jwt_validator: Arc<dyn JwtValidator<Claims> + Send + Sync>,
    jwt_extractor: Arc<dyn JwtExtractor + Send + Sync>,
}

impl<Claims> OAuth2ResourceServer<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    pub fn builder() -> OAuth2ResourceServerBuilder<Claims> {
        OAuth2ResourceServerBuilder::new()
    }

    pub(crate) async fn new(
        issuer_uri: &Url,
        jwks_uri: Option<String>,
        audiences: Vec<String>,
        jwk_set_refresh_interval: Duration,
        custom_claims_validation_spec: Option<ClaimsValidationSpec>,
    ) -> Result<OAuth2ResourceServer<Claims>, StartupError> {
        let (jwks_uri, claims_validation_spec) =
            resolve_config(issuer_uri, jwks_uri, audiences).await?;
        let claims_validation_spec =
            custom_claims_validation_spec.unwrap_or(claims_validation_spec);
        info!(
            "Will validate the following claims: {}",
            claims_validation_spec
        );
        Ok(OAuth2ResourceServer {
            jwt_validator: Arc::new(OnlyJwtValidator::new(
                Arc::new(JwksDecodingKeysProvider::new(
                    &jwks_uri,
                    jwk_set_refresh_interval,
                )),
                claims_validation_spec,
            )),
            jwt_extractor: Arc::new(BearerTokenJwtExtractor {}),
        })
    }

    pub(crate) async fn authorize_request<Body>(
        &self,
        mut request: Request<Body>,
    ) -> Result<Request<Body>, AuthError> {
        let token = self.jwt_extractor.extract_jwt(request.headers())?;
        match self.jwt_validator.validate(&token).await {
            Ok(res) => {
                debug!("JWT validation successful");
                request.extensions_mut().insert(res);
                Ok(request)
            }
            Err(e) => {
                debug!("JWT validation failed due to: {:?}", e);
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
    pub fn into_layer(&self) -> OAuth2ResourceServerLayer<Claims> {
        OAuth2ResourceServerLayer::new(self.clone())
    }
}

async fn resolve_config(
    issuer_uri: &Url,
    jwks_uri: Option<String>,
    audiences: Vec<String>,
) -> Result<(String, ClaimsValidationSpec), StartupError> {
    let mut claims_spec = ClaimsValidationSpec::new()
        // http://127.0.0.1:42203 becomes http://127.0.0.1:42203/ here
        // TODO: Maybe need to take issuer_uri as str?
        .iss(issuer_uri.as_ref())
        .aud(audiences)
        .exp(true);
    println!("DEBUG: {:?}", claims_spec);

    if let Some(jwks_uri) = jwks_uri {
        return Ok((jwks_uri, claims_spec));
    }

    let oidc_config = OidcDiscovery::discover(issuer_uri)
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
                    jwks_uri: "".to_owned(),
                    claims_supported: None,
                })
            })
            .once();

        let issuer_uri = "http://some-issuer.com".parse::<Url>().unwrap();
        let result =
            <OAuth2ResourceServer>::new(&issuer_uri, None, vec![], Duration::from_secs(1), None)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_should_skip_oidc_discovery_if_jwks_uri_set() {
        let _m = MTX.lock();
        let ctx = MockOidcDiscovery::discover_context();
        ctx.expect().never();

        let issuer_uri = "http://some-issuer.com".parse::<Url>().unwrap();
        let result = <OAuth2ResourceServer>::new(
            &issuer_uri,
            Some("https://some-issuer.com/jwks".to_owned()),
            vec![],
            Duration::from_secs(1),
            None,
        )
        .await;
        assert!(result.is_ok());
    }
}
