use std::time::Duration;

use crate::{error::StartupError, validation::ClaimsValidationSpec};

#[derive(Debug, Clone)]
pub struct TenantConfiguration {
    pub identifier: String,
    pub issuer_url: Option<String>,
    pub jwks_url: Option<String>,
    pub audiences: Vec<String>,
    pub jwks_refresh_interval: Duration,
    pub claims_validation_spec: Option<ClaimsValidationSpec>,
}

impl TenantConfiguration {
    pub fn builder() -> TenantConfigurationBuilder {
        TenantConfigurationBuilder::new()
    }
}

pub struct TenantConfigurationBuilder {
    identifier: Option<String>,
    issuer_url: Option<String>,
    jwks_url: Option<String>,
    audiences: Vec<String>,
    jwk_set_refresh_interval: Option<Duration>,
    claims_validation_spec: Option<ClaimsValidationSpec>,
}

impl TenantConfigurationBuilder {
    fn new() -> Self {
        TenantConfigurationBuilder {
            identifier: None,
            issuer_url: None,
            jwks_url: None,
            audiences: Vec::new(),
            jwk_set_refresh_interval: None,
            claims_validation_spec: None,
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
        self.jwk_set_refresh_interval = Some(jwk_set_refresh_interval);
        self
    }

    /// Set what claims of JWTs to validate.
    ///
    /// By default, `iss`, `exp`, `aud` and possibly `nbf` will be validated.
    pub fn claims_validation(mut self, claims_validation: ClaimsValidationSpec) -> Self {
        self.claims_validation_spec = Some(claims_validation);
        self
    }

    /// Construct a TenantConfiguration.
    pub fn build(self) -> Result<TenantConfiguration, StartupError> {
        let identifier = match self.identifier {
            Some(id) => id,
            None => match &self.issuer_url {
                Some(issuer) => issuer.clone(),
                None => {
                    return Err(StartupError::InvalidParameter(
                        "Missing tenant identifier".to_owned(),
                    ))
                }
            },
        };

        Ok(TenantConfiguration {
            identifier,
            issuer_url: self.issuer_url,
            jwks_url: self.jwks_url,
            audiences: self.audiences,
            jwks_refresh_interval: self
                .jwk_set_refresh_interval
                .unwrap_or(Duration::from_secs(60)),
            claims_validation_spec: self.claims_validation_spec,
        })
    }
}
