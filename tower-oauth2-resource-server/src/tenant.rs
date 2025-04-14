use std::time::Duration;

use mockall_double::double;
use url::Url;

use crate::{error::StartupError, oidc::OidcConfig, validation::ClaimsValidationSpec};

#[double]
use crate::oidc::OidcDiscovery;

#[derive(Debug, Clone)]
pub struct TenantConfiguration {
    pub identifier: String,
    pub jwks_url: Url,
    pub audiences: Vec<String>,
    pub jwks_refresh_interval: Duration,
    pub claims_validation_spec: ClaimsValidationSpec,
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
    pub async fn build(self) -> Result<TenantConfiguration, StartupError> {
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

        let issuer_url = self
            .issuer_url
            .as_deref()
            .map(|issuer_url| {
                Url::parse(issuer_url).map_err(|_| {
                    StartupError::InvalidParameter("Invalid issuer_url format".to_string())
                })
            })
            .transpose()?;

        let jwks_url = self
            .jwks_url
            .as_deref()
            .map(|jwks_url| {
                Url::parse(jwks_url).map_err(|_| {
                    StartupError::InvalidParameter("Invalid jwks_url format".to_string())
                })
            })
            .transpose()?;

        let oidc_config = if jwks_url.is_some() {
            None
        } else if let Some(issuer_url) = &issuer_url {
            Some(
                OidcDiscovery::discover(issuer_url)
                    .await
                    .map_err(|e| StartupError::OidcDiscoveryFailed(e.to_string()))?,
            )
        } else {
            return Err(StartupError::InvalidParameter(
                "Either jwks_url or issuer_url must be provided".to_string(),
            ));
        };

        let claims_validation_spec =
            self.claims_validation_spec
                .unwrap_or(recommended_claims_spec(
                    &self.audiences,
                    &self.issuer_url,
                    &oidc_config,
                ));

        let jwks_url = match jwks_url {
            Some(jwks_url) => jwks_url,
            None => match oidc_config {
                Some(oidc_config) => oidc_config.jwks_uri,
                None => {
                    return Err(StartupError::InvalidParameter(
                        "Failed to resolve JWKS URL".to_string(),
                    ))
                }
            },
        };

        Ok(TenantConfiguration {
            identifier,
            jwks_url,
            audiences: self.audiences,
            jwks_refresh_interval: self
                .jwk_set_refresh_interval
                .unwrap_or(Duration::from_secs(60)),
            claims_validation_spec,
        })
    }
}

fn recommended_claims_spec(
    audiences: &Vec<String>,
    issuer_url: &Option<String>,
    oidc_config: &Option<OidcConfig>,
) -> ClaimsValidationSpec {
    let mut claims_spec = ClaimsValidationSpec::new().aud(audiences).exp(true);
    if let Some(issuer_uri) = &issuer_url {
        claims_spec = claims_spec.iss(&issuer_uri.to_string());
    }
    if let Some(config) = &oidc_config {
        if let Some(claims_supported) = &config.claims_supported {
            if claims_supported.contains(&"nbf".to_owned()) {
                claims_spec = claims_spec.nbf(true);
            }
        }
    }
    claims_spec
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

        let result = TenantConfigurationBuilder::new()
            .issuer_url("http://some-issuer.com")
            .build()
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_should_skip_oidc_discovery_if_jwks_url_set() {
        let _m = MTX.lock();
        let ctx = MockOidcDiscovery::discover_context();
        ctx.expect().never();

        let result = TenantConfigurationBuilder::new()
            .issuer_url("http://some-issuer.com")
            .jwks_url("https://some-issuer.com/jwks")
            .build()
            .await;
        assert!(result.is_ok());
    }
}
