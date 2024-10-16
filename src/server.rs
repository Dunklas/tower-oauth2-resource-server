use core::fmt;
use std::{error::Error, fmt::Display, marker::PhantomData, sync::Arc, time::Duration};

use http::Request;
use log::{debug, info};
use serde::de::DeserializeOwned;

use crate::{
    claims::DefaultClaims,
    error::AuthError,
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

    pub(crate) fn new(
        issuer_uri: String,
        audiences: Vec<String>,
        jwk_set_refresh_interval: Duration,
        claims_validation_spec: Option<ClaimsValidationSpec>,
    ) -> Result<OAuth2ResourceServer<Claims>, Box<dyn Error>> {
        let config = OidcConfigProvider::from_issuer_uri(&issuer_uri)?.config;
        info!(
            "Successfully fetched oidc config for issuer: {:?}",
            &issuer_uri
        );
        let claims_validation_spec = claims_validation_spec.unwrap_or(
            ClaimsValidationSpec::from_oidc_config(&config, &audiences)
                .unwrap_or(ClaimsValidationSpec::recommended(&config.issuer, audiences)),
        );
        info!(
            "Will validate the following claims: {}",
            claims_validation_spec
        );
        Ok(OAuth2ResourceServer {
            jwt_validator: Arc::new(OnlyJwtValidator::new(
                Arc::new(JwksDecodingKeysProvider::new(
                    &config.jwks_uri,
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

pub struct OAuth2ResourceServerBuilder<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    issuer_uri: Option<String>,
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

    pub fn audiences(mut self, audiences: Vec<String>) -> Self {
        self.audiences = audiences;
        self
    }

    pub fn jwk_set_refresh_interval(mut self, jwk_set_refresh_interval: Duration) -> Self {
        self.jwk_set_refresh_interval = jwk_set_refresh_interval;
        self
    }

    pub fn build(self) -> Result<OAuth2ResourceServer<Claims>, Box<dyn Error>> {
        let issuer_uri = self
            .issuer_uri
            .ok_or(InvalidParametersError::new("issuer_uri is required"))?;
        OAuth2ResourceServer::new(
            issuer_uri,
            self.audiences.clone(),
            self.jwk_set_refresh_interval,
            self.claims_validation_spec,
        )
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

#[derive(Debug, Clone)]
pub struct InvalidParametersError {
    message: String,
}

impl InvalidParametersError {
    pub fn new(message: &str) -> Self {
        InvalidParametersError {
            message: message.to_owned(),
        }
    }
}

impl Display for InvalidParametersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid parameters: {}", self.message)
    }
}
impl Error for InvalidParametersError {
    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }
}
