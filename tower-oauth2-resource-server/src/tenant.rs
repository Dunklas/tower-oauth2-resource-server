use std::time::Duration;

use jsonwebtoken::jwk::JwkSet;
use mockall_double::double;
use url::Url;

use crate::{error::StartupError, oidc::OidcConfig, validation::ClaimsValidationSpec};

#[double]
use crate::oidc::OidcDiscovery;

#[derive(Debug, Clone)]
pub(crate) enum TenantKind {
    JwksUrl {
        jwks_url: Url,
        jwks_refresh_interval: Duration,
    },
    Static {
        jwks: JwkSet,
    },
}

#[derive(Debug, Clone)]
pub struct TenantConfiguration {
    pub(crate) identifier: String,
    pub(crate) claims_validation_spec: ClaimsValidationSpec,
    pub(crate) kind: TenantKind,
}

impl TenantConfiguration {
    /// Build a tenant configuration for issuer_url (what authorization server to use).
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
    pub fn builder(issuer_url: impl Into<String>) -> TenantConfigurationBuilder {
        TenantConfigurationBuilder::new(issuer_url)
    }

    /// Build a tenant configuration for a static JWK Set
    ///
    /// Format of `jwks` must follow the "JWK Set Format" as defined in  RFC 7517
    pub fn static_builder(jwks: impl Into<String>) -> TenantStaticConfigurationBuilder {
        TenantStaticConfigurationBuilder::new(jwks)
    }
}

pub struct TenantConfigurationBuilder {
    issuer_url: String,
    identifier: Option<String>,
    jwks_url: Option<String>,
    audiences: Vec<String>,
    jwk_set_refresh_interval: Option<Duration>,
    claims_validation_spec: Option<ClaimsValidationSpec>,
}

impl TenantConfigurationBuilder {
    fn new(issuer_url: impl Into<String>) -> Self {
        Self {
            issuer_url: issuer_url.into(),
            identifier: None,
            jwks_url: None,
            audiences: Vec::new(),
            jwk_set_refresh_interval: None,
            claims_validation_spec: None,
        }
    }

    /// Set an identifier for the tenant.
    ///
    /// Can be accessed on a [Authorizer](crate::authorizer::token_authorizer::Authorizer) in
    /// order to identify what authorization server the authorizer is configured for.
    ///
    /// Defaults to `issuer_url`.
    pub fn identifier(mut self, identifier: &str) -> Self {
        self.identifier = Some(identifier.to_string());
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
            None => self.issuer_url.clone(),
        };

        let issuer_url = Url::parse(&self.issuer_url)
            .map_err(|_| StartupError::InvalidParameter("Invalid issuer_url format".to_string()))?;

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
        } else {
            Some(
                OidcDiscovery::discover(&issuer_url)
                    .await
                    .map_err(|e| StartupError::OidcDiscoveryFailed(e.to_string()))?,
            )
        };

        let claims_validation_spec = self
            .claims_validation_spec
            .unwrap_or(recommended_claims_spec(&self.audiences, &oidc_config));

        let jwks_url = match jwks_url {
            Some(jwks_url) => jwks_url,
            None => match oidc_config {
                Some(oidc_config) => oidc_config.jwks_uri,
                None => {
                    return Err(StartupError::InvalidParameter(
                        "Failed to resolve JWKS URL".to_string(),
                    ));
                }
            },
        };

        let kind = TenantKind::JwksUrl {
            jwks_url,
            jwks_refresh_interval: self
                .jwk_set_refresh_interval
                .unwrap_or(Duration::from_secs(60)),
        };

        Ok(TenantConfiguration {
            identifier,
            claims_validation_spec,
            kind,
        })
    }
}

pub struct TenantStaticConfigurationBuilder {
    identifier: Option<String>,
    audiences: Vec<String>,
    claims_validation_spec: Option<ClaimsValidationSpec>,
    jwks: String,
}

impl TenantStaticConfigurationBuilder {
    fn new(jwks: impl Into<String>) -> Self {
        Self {
            jwks: jwks.into(),
            identifier: None,
            audiences: Vec::new(),
            claims_validation_spec: None,
        }
    }

    /// Set an identifier for the tenant.
    ///
    /// Can be accessed on a [Authorizer](crate::authorizer::token_authorizer::Authorizer) in
    /// order to identify what authorization server the authorizer is configured for.
    ///
    /// Used to validate the the iss
    ///
    /// Defaults to `static`.
    pub fn identifier(mut self, identifier: &str) -> Self {
        self.identifier = Some(identifier.to_string());
        self
    }

    /// Set the expected audiences.
    ///
    /// Used to validate `aud` claim of JWTs.
    pub fn audiences(mut self, audiences: &[impl ToString]) -> Self {
        self.audiences = audiences.iter().map(|aud| aud.to_string()).collect();
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
        let identifier = self.identifier.unwrap_or_else(|| String::from("static"));

        let claims_validation_spec = self
            .claims_validation_spec
            .unwrap_or(recommended_claims_spec(&self.audiences, &None));

        let jwks = serde_json::from_str(&self.jwks)
            .map_err(|e| StartupError::InvalidParameter(format!("Failed to parse JWKS: {e}")))?;

        let kind = TenantKind::Static { jwks };

        Ok(TenantConfiguration {
            identifier,
            claims_validation_spec,
            kind,
        })
    }
}

fn recommended_claims_spec(
    audiences: &Vec<String>,
    oidc_config: &Option<OidcConfig>,
) -> ClaimsValidationSpec {
    let mut claims_spec = ClaimsValidationSpec::new().exp(true);
    if !audiences.is_empty() {
        claims_spec = claims_spec.aud(audiences);
    }

    if let Some(config) = &oidc_config {
        if let Some(claims_supported) = &config.claims_supported {
            if claims_supported.contains(&"nbf".to_owned()) {
                claims_spec = claims_spec.nbf(true);
            }
        }
        claims_spec = claims_spec.iss(config.issuer.as_str());
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
        ctx.expect().returning(|_| Ok(default_oidc_config())).once();

        let result = TenantConfigurationBuilder::new("http://some-issuer.com")
            .build()
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_should_skip_oidc_discovery_if_jwks_url_set() {
        let _m = MTX.lock();
        let ctx = MockOidcDiscovery::discover_context();
        ctx.expect().never();

        let result = TenantConfigurationBuilder::new("http://some-issuer.com")
            .jwks_url("https://some-issuer.com/jwks")
            .build()
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_should_use_issuer_as_identifier() {
        let _m = MTX.lock();
        let ctx = MockOidcDiscovery::discover_context();
        ctx.expect().returning(|_| Ok(default_oidc_config())).once();

        let result = TenantConfigurationBuilder::new("http://some-issuer.com")
            .build()
            .await;

        assert!(result.is_ok());
        let tenant = result.unwrap();
        assert_eq!(tenant.identifier, "http://some-issuer.com");
    }

    #[tokio::test]
    async fn test_custom_identifier_overrides_issuer() {
        let _m = MTX.lock();
        let ctx = MockOidcDiscovery::discover_context();
        ctx.expect().returning(|_| Ok(default_oidc_config())).once();

        let result = TenantConfigurationBuilder::new("http://some-issuer.com")
            .identifier("custom-identifier")
            .build()
            .await;

        assert!(result.is_ok());
        let tenant = result.unwrap();
        assert_eq!(tenant.identifier, "custom-identifier");
    }

    #[tokio::test]
    async fn test_valid_issuer_url_required() {
        let _m = MTX.lock();
        let ctx = MockOidcDiscovery::discover_context();
        ctx.expect().never();

        let result = TenantConfigurationBuilder::new("not-a-url").build().await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            StartupError::InvalidParameter("Invalid issuer_url format".to_owned())
        )
    }

    #[tokio::test]
    async fn test_valid_jwks_url_required() {
        let _m = MTX.lock();
        let ctx = MockOidcDiscovery::discover_context();
        ctx.expect().never();

        let result = TenantConfigurationBuilder::new("https://some-issuer.com")
            .jwks_url("not-a-url")
            .build()
            .await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            StartupError::InvalidParameter("Invalid jwks_url format".to_owned())
        )
    }

    #[tokio::test]
    async fn test_provides_recommended_claims_validation_spec() {
        let _m = MTX.lock();
        let ctx = MockOidcDiscovery::discover_context();
        ctx.expect().returning(|_| Ok(default_oidc_config())).once();

        let result = TenantConfigurationBuilder::new("https://some-issuer.com")
            .audiences(&["https://some-resource-server.com"])
            .build()
            .await;

        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().claims_validation_spec,
            ClaimsValidationSpec::new()
                .exp(true)
                .iss("http://some-issuer.com")
                .aud(&vec!["https://some-resource-server.com".to_owned()])
        );
    }

    #[tokio::test]
    async fn test_custom_claims_validation_spec_overrides_recommended() {
        let _m = MTX.lock();
        let ctx = MockOidcDiscovery::discover_context();
        ctx.expect().returning(|_| Ok(default_oidc_config())).once();

        let claims_validation = ClaimsValidationSpec::new().exp(false);
        let result = TenantConfigurationBuilder::new("https://some-issuer.com")
            .audiences(&["https://some-resource-server.com"])
            .claims_validation(claims_validation.clone())
            .build()
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().claims_validation_spec, claims_validation);
    }

    #[test]
    fn test_static_build() {
        let jwks = mock_jwks();
        let t = TenantStaticConfigurationBuilder::new(jwks).build().unwrap();

        assert_eq!(t.identifier, "static");
        assert!(matches!(t.kind, TenantKind::Static { .. }));
    }

    #[test]
    fn test_static_build_invalid_jwks() {
        let jwks = " {}";
        let e = TenantStaticConfigurationBuilder::new(jwks)
            .build()
            .unwrap_err();
        assert!(matches!(e, StartupError::InvalidParameter { .. }))
    }

    #[test]
    fn test_static_build_custom_identifier() {
        let jwks = mock_jwks();
        let t = TenantStaticConfigurationBuilder::new(jwks)
            .identifier("custom")
            .build()
            .unwrap();

        assert_eq!(t.identifier, "custom");
        assert!(matches!(t.kind, TenantKind::Static { .. }));
    }

    #[test]
    fn test_static_provides_recommended_claims_validation_spec() {
        let jwks = mock_jwks();
        let t = TenantStaticConfigurationBuilder::new(jwks)
            .audiences(&["https://some-resource-server.com"])
            .build()
            .unwrap();

        assert_eq!(
            t.claims_validation_spec,
            ClaimsValidationSpec::new()
                .exp(true)
                .aud(&vec!["https://some-resource-server.com".to_owned()])
        );
    }

    fn mock_jwks() -> String {
        let modulus = "oEz_RrupHP9d9XiFbXLoJMwG-75Z18t4ziBy2PHTZHxkHOep7aFeNj-13NmIcL4ooj-2nxrLhWbgA2iBaWr95wKkf5peTsc-5Q6-B2uCcn9xPSQK08Y_jNVhtly3mAOdsT4Y9mQIO_oqaqEyzutypZBEu-18NkbGVwkNhG9sxvUjFXHvMoJs5iwILaDA2FhuEioIDzOy-ZjD8p928ye2v8CdPWl1xPxoBXd2KIe3RkocRDxLeeBg3wH8a9tQ5Z7fOmiXiAI8_lN57zYf078yazvLUlKzCo1pQoR25MU51d7zgI_I7H2Fb5PZGcCmfvN1Up41OfEQyMLL6JYyoP23XQ";
        let exponent = "AQAB";
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": "test-kid",
                "n": modulus,
                "e": exponent
            }]
        })
        .to_string()
    }

    fn default_oidc_config() -> OidcConfig {
        OidcConfig {
            jwks_uri: "http://some-issuer.com/jwks".parse::<Url>().unwrap(),
            issuer: "http://some-issuer.com".to_owned(),
            claims_supported: None,
        }
    }
}
