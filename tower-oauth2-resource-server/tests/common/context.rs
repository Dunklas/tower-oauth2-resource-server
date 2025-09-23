use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::future::join_all;
use tokio::time::sleep;
use tower_oauth2_resource_server::{
    server::OAuth2ResourceServer, tenant::TenantConfiguration, validation::ClaimsValidationSpec,
};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

use crate::common::{self, jwks, jwt::JwtBuilder, rsa_keys, Jwks, OpenIdConfig, RsaKey};

// Needed for initial jwks fetch
pub const START_UP_DELAY_MS: Duration = Duration::from_millis(500);

pub const DEFAULT_KID: &str = "good_key";
pub const DEFAULT_ISSUER_PATH: &str = "/auth-server";

pub struct TestContext {
    mock_server: MockServer,
    tenant_configurations: Vec<TenantConfiguration>,
}

impl<'a> TestContext {
    pub fn builder() -> TestContextBuilder<'a> {
        TestContextBuilder::new()
    }

    pub async fn new(tenant_configurations: Vec<TenantInput<'a>>) -> Self {
        let mock_server = MockServer::start().await;
        for tenant_input in &tenant_configurations {
            if let TenantInput::Oidc(options) = tenant_input {
                Self::mock_oidc(&mock_server, options.issuer_path).await;
                Self::mock_jwks(
                    &mock_server,
                    options.issuer_path,
                    &[(options.key.0, &options.key.1)],
                )
                .await;
            }
        }
        let tenants = join_all(
            tenant_configurations
                .iter()
                .map(async |input| match input {
                    TenantInput::Static(options) => {
                        let mut builder = TenantConfiguration::static_builder(
                            serde_json::to_string(&options.jwks).unwrap(),
                        )
                        .audiences(&options.audiences);

                        if let Some(claims_validation_spec) = &options.claims_validation {
                            builder = builder.claims_validation(claims_validation_spec.clone());
                        }

                        builder.build().unwrap()
                    }
                    TenantInput::Oidc(options) => {
                        let mut builder = TenantConfiguration::builder(format!(
                            "{}{}",
                            mock_server.uri(),
                            options.issuer_path
                        ))
                        .audiences(&options.audiences);

                        if let Some(claims_validation_spec) = &options.claims_validation {
                            builder = builder.claims_validation(claims_validation_spec.clone());
                        }

                        builder.build().await.unwrap()
                    }
                })
                .collect::<Vec<_>>(),
        )
        .await;
        Self {
            tenant_configurations: tenants,
            mock_server,
        }
    }

    pub fn tenant_configurations(&self) -> &Vec<TenantConfiguration> {
        &self.tenant_configurations
    }

    pub fn mock_server_url(&self) -> String {
        self.mock_server.uri()
    }

    pub async fn create_service(&self) -> OAuth2ResourceServer {
        let server = OAuth2ResourceServer::builder()
            .add_tenants(self.tenant_configurations.clone())
            .build()
            .await
            .expect("Failed to build OAuth2ResourceServer");
        sleep(START_UP_DELAY_MS).await;
        server
    }

    pub fn valid_jwt(&self) -> JwtBuilder {
        JwtBuilder::new()
            .iss(format!(
                "{}{}",
                &self.mock_server.uri(),
                DEFAULT_ISSUER_PATH
            ))
            .sub("someone@example.com")
            .nbf(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - 10,
            )
            .exp(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 10,
            )
    }

    async fn mock_oidc(mock_server: &MockServer, issuer_path: &str) {
        Mock::given(method("GET"))
            .and(path(format!(
                "{}/.well-known/openid-configuration",
                issuer_path
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(OpenIdConfig {
                issuer: format!("{}{}", &mock_server.uri(), issuer_path),
                jwks_uri: format!("{}{}/jwks", &mock_server.uri(), issuer_path),
            }))
            .mount(mock_server)
            .await;
    }

    async fn mock_jwks(mock_server: &MockServer, issuer_path: &str, keys: &[(&str, &RsaKey)]) {
        let jwks = jwks(keys);
        Mock::given(method("GET"))
            .and(path(format!("{}/jwks", issuer_path)))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(mock_server)
            .await;
    }
}

pub struct TestContextBuilder<'a> {
    tenants: Vec<TenantInput<'a>>,
}

impl<'a> TestContextBuilder<'a> {
    pub fn new() -> Self {
        Self { tenants: vec![] }
    }

    pub fn with_tenant_configuration(mut self, config: TenantInput<'a>) -> Self {
        self.tenants.push(config);
        self
    }

    pub async fn build(self) -> TestContext {
        TestContext::new(self.tenants).await
    }
}

impl<'a> Default for TestContextBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

pub enum TenantInput<'a> {
    Oidc(OidcOptions<'a>),
    Static(StaticOptions<'a>),
}

pub struct OidcOptions<'a> {
    issuer_path: &'a str,
    audiences: Vec<&'a str>,
    key: (&'a str, RsaKey),
    claims_validation: Option<ClaimsValidationSpec>,
}

impl<'a> Default for OidcOptions<'a> {
    fn default() -> Self {
        Self {
            issuer_path: DEFAULT_ISSUER_PATH,
            audiences: vec![],
            key: (DEFAULT_KID, rsa_keys()[0].clone()),
            claims_validation: None,
        }
    }
}

impl<'a> OidcOptions<'a> {
    pub fn issuer_path(mut self, issuer_path: &'a str) -> Self {
        self.issuer_path = issuer_path;
        self
    }
    pub fn audiences(mut self, audiences: Vec<&'a str>) -> Self {
        self.audiences = audiences;
        self
    }
    pub fn rsa(mut self, key: (&'a str, RsaKey)) -> Self {
        self.key = key;
        self
    }
    pub fn claims_validation(mut self, claims_validation: ClaimsValidationSpec) -> Self {
        self.claims_validation = Some(claims_validation);
        self
    }
}

pub struct StaticOptions<'a> {
    jwks: Jwks,
    audiences: Vec<&'a str>,
    claims_validation: Option<ClaimsValidationSpec>,
}

impl<'a> Default for StaticOptions<'a> {
    fn default() -> Self {
        Self {
            jwks: common::jwks(&[(DEFAULT_KID, &rsa_keys()[0])]),
            audiences: vec![],
            claims_validation: None,
        }
    }
}

impl<'a> StaticOptions<'a> {
    pub fn audiences(mut self, audiences: Vec<&'a str>) -> Self {
        self.audiences = audiences;
        self
    }
    pub fn jwks(mut self, jwks: Jwks) -> Self {
        self.jwks = jwks;
        self
    }
    pub fn claims_validation(mut self, claims_validation: ClaimsValidationSpec) -> Self {
        self.claims_validation = Some(claims_validation);
        self
    }
}
