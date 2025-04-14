use std::{marker::PhantomData, sync::Arc};

use serde::de::DeserializeOwned;

use crate::{
    auth_resolver::{AuthorizerResolver, IssuerAuthorizerResolver, SingleAuthorizerResolver},
    error::StartupError,
    server::OAuth2ResourceServer,
    tenant::TenantConfiguration,
};

#[derive(Debug)]
pub struct OAuth2ResourceServerBuilder<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    tenant_configurations: Vec<TenantConfiguration>,
    auth_resolver: Option<Arc<dyn AuthorizerResolver<Claims>>>,
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
            tenant_configurations: Vec::new(),
            auth_resolver: None,
            phantom: PhantomData,
        }
    }

    /// Add a tenant (authorization server).
    pub fn add_tenant(mut self, tenant_configuration: TenantConfiguration) -> Self {
        self.tenant_configurations.push(tenant_configuration);
        self
    }

    /// Provide a custom authorization resolver.
    ///
    /// Only needs to be provided if the default resolver is not sufficient.
    ///
    /// See [AuthorizerResolver] for more information.
    pub fn auth_resolver(mut self, auth_resolver: Arc<dyn AuthorizerResolver<Claims>>) -> Self {
        self.auth_resolver = Some(auth_resolver);
        self
    }

    /// Construct an OAuth2ResourceServer.
    ///
    /// During construction the OIDC Provider Configuration endpoint of the
    /// authorization server might be queried.
    /// Thus, the operation can fail and therefore returns a Result.
    pub async fn build(self) -> Result<OAuth2ResourceServer<Claims>, StartupError> {
        assert!(!self.tenant_configurations.is_empty());
        let num_tenants = self.tenant_configurations.len();
        let auth_resolver = self.auth_resolver.unwrap_or_else(|| {
            if num_tenants == 1 {
                Arc::new(SingleAuthorizerResolver {})
            } else {
                Arc::new(IssuerAuthorizerResolver {})
            }
        });
        OAuth2ResourceServer::new(self.tenant_configurations, auth_resolver).await
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
