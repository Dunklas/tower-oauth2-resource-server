use tower_oauth2_resource_server::{server::OAuth2ResourceServer, tenant::TenantConfiguration};
use wiremock::MockServer;

use crate::common::mock_oidc_config;

pub const DEFAULT_ISSUER: &str = "https://auth-server.com";
pub const DEFAULT_KID: &str = "default-kid";

pub struct TestContext {
    key_id: String,
    audiences: Vec<String>,
    tenant_configurations: Vec<TenantConfiguration>,
    mock_server: MockServer,
}

impl TestContext {
    pub fn builder() -> TestContextBuilder {
        TestContextBuilder::new()
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
    issuer: Option<String>,
    key_id: Option<String>,
    audiences: Vec<String>,
    tenant_configurations: Vec<TenantConfiguration>,
}

impl TestContextBuilder {
    pub fn new() -> Self {
        Self {
            issuer: None,
            key_id: None,
            audiences: Vec::new(),
            tenant_configurations: Vec::new(),
        }
    }

    pub fn with_key_id<S: Into<String>>(mut self, key_id: S) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    pub fn with_audience<S: Into<String>>(mut self, audience: S) -> Self {
        self.audiences.push(audience.into());
        self
    }

    pub fn with_tenant_configuration(mut self, config: TenantConfiguration) -> Self {
        self.tenant_configurations.push(config);
        self
    }

    pub async fn build(self) -> TestContext {
        let mock_server = MockServer::start().await;
        mock_oidc_config(
            &mock_server,
            &self.issuer.unwrap_or(DEFAULT_ISSUER.to_owned()),
        )
        .await;
        TestContext {
            key_id: self.key_id.unwrap_or_else(|| DEFAULT_KID.to_string()),
            audiences: self.audiences,
            tenant_configurations: self.tenant_configurations,
            mock_server,
        }
    }
}

impl Default for TestContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Add utility functions for create_service, create_valid_jwt, etc.
