use std::time::Duration;

use futures_util::future::join_all;
use tokio::time::sleep;
use tower_oauth2_resource_server::{
    server::OAuth2ResourceServer, tenant::TenantConfiguration, validation::ClaimsValidationSpec,
};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

use crate::common::{jwks, Jwks, OpenIdConfig, RsaKey};

// Needed for initial jwks fetch
pub const START_UP_DELAY_MS: Duration = Duration::from_millis(500);

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
            if let TenantInput::Oidc(issuer_path, _, (kid, rsa_key), _) = tenant_input {
                Self::mock_oidc(&mock_server, issuer_path).await;
                Self::mock_jwks(&mock_server, issuer_path, &[(kid, rsa_key)]).await;
            }
        }
        let tenants = join_all(
            tenant_configurations
                .iter()
                .map(async |input| match input {
                    TenantInput::Static(jwks, audiences, claims_validation_spec) => {
                        let mut builder = TenantConfiguration::static_builder(
                            serde_json::to_string(*jwks).unwrap(),
                        )
                        .audiences(&audiences);

                        if let Some(claims_validation_spec) = claims_validation_spec {
                            builder = builder.claims_validation(claims_validation_spec.clone());
                        }

                        builder.build().unwrap()
                    }
                    TenantInput::Oidc(issuer_path, audiences, _, claims_validation_spec) => {
                        let mut builder = TenantConfiguration::builder(format!(
                            "{}{}",
                            mock_server.uri(),
                            issuer_path
                        ))
                        .audiences(&audiences);

                        if let Some(claims_validation_spec) = claims_validation_spec {
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

    pub fn mock_server_uri(&self) -> String {
        self.mock_server.uri()
    }

    pub fn tenant_configurations(&self) -> &Vec<TenantConfiguration> {
        &self.tenant_configurations
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
    Oidc(
        &'a str,
        Vec<&'a str>,
        (&'a str, &'a RsaKey),
        Option<ClaimsValidationSpec>,
    ),
    Static(&'a Jwks, Vec<&'a str>, Option<ClaimsValidationSpec>),
}
