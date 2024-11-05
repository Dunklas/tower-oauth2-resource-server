use std::{marker::PhantomData, time::Duration};

use serde::de::DeserializeOwned;

use crate::{error::StartupError, server::OAuth2ResourceServer, validation::ClaimsValidationSpec};

#[derive(Debug)]
pub struct OAuth2ResourceServerBuilder<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    issuer_url: Option<String>,
    jwks_url: Option<String>,
    audiences: Vec<String>,
    jwks_refresh_interval: Duration,
    claims_validation_spec: Option<ClaimsValidationSpec>,
    phantom: PhantomData<Claims>,
}

impl<Claims> OAuth2ResourceServer<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    pub fn builder() -> OAuth2ResourceServerBuilder<Claims> {
        OAuth2ResourceServerBuilder::new()
    }
}

impl<Claims> OAuth2ResourceServerBuilder<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    fn new() -> Self {
        OAuth2ResourceServerBuilder::<Claims> {
            issuer_url: None,
            jwks_url: None,
            audiences: Vec::new(),
            jwks_refresh_interval: Duration::from_secs(60),
            claims_validation_spec: None,
            phantom: PhantomData,
        }
    }

    /// Set the issuer_url (what authorization server to use).
    ///
    /// On startup, the OIDC Provider Configuration endpoint of the
    /// authorization server will be queried in order to
    /// self-configure the middleware.
    ///
    /// If `issuer_url` is set to `https://authorization-server.com/issuer`,
    /// at least one of the following endpoints need to available.
    ///
    /// - `https://authorization-server.com/issuer/.well-known/openid-configuration`
    /// - `https://authorization-server.com/.well-known/openid-configuration/issuer`
    /// - `https://authorization-server.com/.well-known/oauth-authorization-server/issuer`
    ///
    /// A consequence of the self-configuration is that the authorization server
    /// must be available when the middleware is started.
    /// In cases where the middleware must be able to start independently from
    /// the authorization server, the `jwks_url` property can be set.
    /// This will prevent the self-configuration on start up.
    ///
    /// **Note** that it's still required to provide `issuer_url`
    /// because it's used to validate `iss` claim of JWTs.
    pub fn issuer_url(mut self, issuer_url: impl Into<String>) -> Self {
        self.issuer_url = Some(issuer_url.into());
        self
    }

    /// Set the jwks_url (what url to query valid public keys from).
    ///
    /// This url is normally fetched by calling the OIDC Provider Configuration endpoint
    /// of the authorization server.
    /// Only provide this property if the middleware must be able to start
    /// independently from the authorization server.
    pub fn jwks_url(mut self, jwks_url: impl Into<String>) -> Self {
        self.jwks_url = Some(jwks_url.into());
        self
    }

    /// Set the expected audiences.
    ///
    /// Used to validate `aud` claim of JWTs.
    pub fn audiences(mut self, audiences: &[impl ToString]) -> Self {
        self.audiences = audiences.iter().map(|aud| aud.to_string()).collect();
        self
    }

    /// Set the interval for rotating jwks.
    ///
    /// The `jwks_url` is periodically queried in order to update
    /// public keys that JWT signatures will be validated against.
    ///
    /// Default value is `Duration::from_secs(60)`.
    pub fn jwks_refresh_interval(mut self, jwk_set_refresh_interval: Duration) -> Self {
        self.jwks_refresh_interval = jwk_set_refresh_interval;
        self
    }

    /// Set what claims of JWTs to validate.
    ///
    /// By default, `iss`, `exp`, `aud` and possibly `nbf` will be validated.
    pub fn claims_validation(mut self, claims_validation: ClaimsValidationSpec) -> Self {
        self.claims_validation_spec = Some(claims_validation);
        self
    }

    /// Construct an OAuth2ResourceServer.
    ///
    /// During construction the OIDC Provider Configuration endpoint of the
    /// authorization server might be queried.
    /// Thus, the operation can fail and therefore returns a Result.
    pub async fn build(self) -> Result<OAuth2ResourceServer<Claims>, StartupError> {
        let issuer_url = self.issuer_url.ok_or(StartupError::InvalidParameter(
            "issuer_url is required".to_owned(),
        ))?;
        OAuth2ResourceServer::new(
            &issuer_url,
            self.jwks_url,
            self.audiences.clone(),
            self.jwks_refresh_interval,
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
            StartupError::InvalidParameter("issuer_url is required".to_owned())
        );
    }
}
