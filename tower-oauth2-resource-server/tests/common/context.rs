use futures_util::future::join_all;
use tower_oauth2_resource_server::{
    server::OAuth2ResourceServer,
    tenant::{TenantConfiguration, TenantConfigurationBuilder, TenantStaticConfigurationBuilder},
};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

use crate::common::{mock_oidc_config, OpenIdConfig};

pub const DEFAULT_ISSUER: &str = "https://auth-server.com";
pub const DEFAULT_KID: &str = "default-kid";

pub struct TestContext {
    mock_server: MockServer,
    key_id: String,
    tenant_configurations: Vec<TenantConfiguration>,
}

impl TestContext {
    pub fn builder() -> TestContextBuilder {
        TestContextBuilder::new()
    }

    pub async fn new(key_id: String, tenant_configurations: Vec<TenantInput>) -> Self {
        let mock_server = MockServer::start().await;
        for tenant_input in &tenant_configurations {
            if let TenantInput::Oidc(issuer_path, _) = tenant_input {
                Self::mock_oidc(&mock_server, issuer_path).await;
            }
        }
        let tenants = join_all(
            tenant_configurations
                .iter()
                .map(async |input| match input {
                    TenantInput::Static(jwks, audiences) => {
                        TenantConfiguration::static_builder(jwks)
                            .audiences(&audiences)
                            .build()
                            .unwrap()
                    }
                    TenantInput::Oidc(issuer_path, audiences) => TenantConfiguration::builder(
                        format!("{}{}", mock_server.uri(), issuer_path),
                    )
                    .audiences(&audiences)
                    .build()
                    .await
                    .unwrap(),
                })
                .collect::<Vec<_>>(),
        )
        .await;
        Self {
            key_id,
            tenant_configurations: tenants,
            mock_server,
        }
    }

    async fn mock_oidc(mock_server: &MockServer, issuer_path: &str) {
        Mock::given(method("GET"))
            .and(path(format!(
                "{}/.well-known/openid-configuration",
                issuer_path
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(OpenIdConfig {
                issuer: format!("{}{}", &mock_server.uri(), issuer_path),
                jwks_uri: format!("{}/jwks", &mock_server.uri()),
            }))
            .mount(mock_server)
            .await;
    }

    pub async fn create_service(&self) -> OAuth2ResourceServer {
        let builder = <OAuth2ResourceServer>::builder();
        builder
            .build()
            .await
            .expect("Failed to build OAuth2ResourceServer")
    }
}

pub struct TestContextBuilder {
    key_id: Option<String>,
    tenants: Vec<TenantInput>,
}

impl TestContextBuilder {
    pub fn new() -> Self {
        Self {
            key_id: None,
            tenants: vec![],
        }
    }

    pub fn with_key_id<S: Into<String>>(mut self, key_id: S) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    pub fn with_tenant_configuration(mut self, config: TenantInput) -> Self {
        self.tenants.push(config);
        self
    }

    pub async fn build(self) -> TestContext {
        TestContext::new(
            self.key_id.unwrap_or_else(|| DEFAULT_KID.to_string()),
            self.tenants,
        )
        .await
    }
}

impl Default for TestContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub enum TenantInput {
    Oidc(String, Vec<String>),
    Static(String, Vec<String>),
}
