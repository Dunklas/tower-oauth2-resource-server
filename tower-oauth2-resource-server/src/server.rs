use core::fmt;
use std::{marker::PhantomData, sync::Arc, time::Duration};

use http::Request;
use log::{debug, info};
use serde::de::DeserializeOwned;

use crate::{
    claims::DefaultClaims,
    error::{AuthError, StartupError},
    jwks::JwksDecodingKeysProvider,
    jwt::{BearerTokenJwtExtractor, JwtExtractor, JwtValidator, OnlyJwtValidator},
    layer::OAuth2ResourceServerLayer,
    oidc::OidcConfigProvider,
    validation::ClaimsValidationSpec,
};

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
        issuer_uri: String,
        jwks_uri: Option<String>,
        audiences: Vec<String>,
        jwk_set_refresh_interval: Duration,
        claims_validation_spec: Option<ClaimsValidationSpec>,
    ) -> Result<OAuth2ResourceServer<Claims>, StartupError> {
        let (jwks_uri, claims_validation_spec) =
            resolve_config(issuer_uri, jwks_uri, audiences, claims_validation_spec).await?;
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
    issuer_uri: String,
    jwks_uri: Option<String>,
    audiences: Vec<String>,
    claims_validation_spec: Option<ClaimsValidationSpec>,
) -> Result<(String, ClaimsValidationSpec), StartupError> {
    let mut claims_spec = ClaimsValidationSpec::new()
        .iss(&issuer_uri)
        .aud(audiences)
        .exp(true);

    if let Some(jwks_uri) = jwks_uri {
        return Ok((jwks_uri, claims_validation_spec.unwrap_or(claims_spec)));
    }

    let oidc_config = OidcConfigProvider::from_issuer_uri(&issuer_uri)
        .await
        .map_err(|_| StartupError::OidcDiscoveryFailed)?
        .config;
    if let Some(claims_supported) = &oidc_config.claims_supported {
        if claims_supported.contains(&"nbf".to_owned()) {
            claims_spec = claims_spec.nbf(true);
        }
    }
    Ok((
        oidc_config.jwks_uri,
        claims_validation_spec.unwrap_or(claims_spec),
    ))
}

pub struct OAuth2ResourceServerBuilder<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    issuer_uri: Option<String>,
    jwks_uri: Option<String>,
    audiences: Vec<String>,
    jwk_set_refresh_interval: Duration,
    claims_validation_spec: Option<ClaimsValidationSpec>,
    phantom: PhantomData<Claims>,
}

impl<Claims> OAuth2ResourceServerBuilder<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    pub fn new() -> Self {
        OAuth2ResourceServerBuilder::<Claims> {
            issuer_uri: None,
            jwks_uri: None,
            audiences: Vec::new(),
            jwk_set_refresh_interval: Duration::from_secs(60),
            claims_validation_spec: None,
            phantom: PhantomData,
        }
    }

    pub fn issuer_uri(mut self, issuer_uri: &str) -> Self {
        self.issuer_uri = Some(issuer_uri.to_owned());
        self
    }

    pub fn jwks_uri(mut self, jwks_uri: &str) -> Self {
        self.jwks_uri = Some(jwks_uri.to_owned());
        self
    }

    pub fn audiences(mut self, audiences: Vec<String>) -> Self {
        self.audiences = audiences;
        self
    }

    pub fn jwk_set_refresh_interval(mut self, jwk_set_refresh_interval: Duration) -> Self {
        self.jwk_set_refresh_interval = jwk_set_refresh_interval;
        self
    }

    pub async fn build(self) -> Result<OAuth2ResourceServer<Claims>, StartupError> {
        let issuer_uri = self.issuer_uri.ok_or(StartupError::InvalidParameter(
            "issuer_uri is required".to_owned(),
        ))?;
        OAuth2ResourceServer::new(
            issuer_uri,
            self.jwks_uri,
            self.audiences.clone(),
            self.jwk_set_refresh_interval,
            self.claims_validation_spec,
        )
        .await
    }
}

impl<Claims> Default for OAuth2ResourceServerBuilder<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}
