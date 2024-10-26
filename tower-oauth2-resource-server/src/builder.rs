use std::{marker::PhantomData, time::Duration};

use http::Uri;
use serde::de::DeserializeOwned;

use crate::{error::StartupError, server::OAuth2ResourceServer, validation::ClaimsValidationSpec};

pub struct OAuth2ResourceServerBuilder<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    issuer_uri: Option<Uri>,
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

    pub fn issuer_uri(mut self, issuer_uri: impl Into<Uri>) -> Self {
        self.issuer_uri = Some(issuer_uri.into());
        self
    }

    pub fn jwks_uri(mut self, jwks_uri: impl Into<String>) -> Self {
        self.jwks_uri = Some(jwks_uri.into());
        self
    }

    pub fn audiences(mut self, audiences: &[impl ToString]) -> Self {
        self.audiences = audiences.iter().map(|aud| aud.to_string()).collect();
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
            &issuer_uri,
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

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::error::StartupError;

    #[derive(Clone, Deserialize)]
    struct Claims {}

    #[tokio::test]
    async fn require_issuer() {
        let result = OAuth2ResourceServerBuilder::<Claims>::new().build().await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            StartupError::InvalidParameter("issuer_uri is required".to_owned())
        );
    }
}
