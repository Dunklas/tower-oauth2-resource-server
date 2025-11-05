use std::{marker::PhantomData, sync::Arc};

use serde::de::DeserializeOwned;

use crate::{
    auth_resolver::{AuthorizerResolver, IssuerAuthorizerResolver, SingleAuthorizerResolver},
    error::StartupError,
    jwt_extract::JwtExtractor,
    server::OAuth2ResourceServer,
    tenant::TenantConfiguration,
};

pub struct OAuth2ResourceServerBuilder<Claims> {
    tenant_configurations: Vec<TenantConfiguration>,
    auth_resolver: Option<Arc<dyn AuthorizerResolver<Claims>>>,
    jwt_extractor: Option<Arc<dyn JwtExtractor + Send + Sync>>,
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

impl<Claims> OAuth2ResourceServerBuilder<Claims> {
    fn new() -> Self {
        OAuth2ResourceServerBuilder::<Claims> {
            tenant_configurations: Vec::new(),
            auth_resolver: None,
            jwt_extractor: None,
            phantom: PhantomData,
        }
    }
}

impl<Claims> OAuth2ResourceServerBuilder<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    /// Add a tenant (authorization server).
    pub fn add_tenant(mut self, tenant_configuration: TenantConfiguration) -> Self {
        self.tenant_configurations.push(tenant_configuration);
        self
    }

    /// Add multiple tenants (authorization servers).
    pub fn add_tenants(mut self, tenant_configurations: Vec<TenantConfiguration>) -> Self {
        self.tenant_configurations.extend(tenant_configurations);
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

    /// Provide a custom JWT extractor.
    ///
    /// Only needs to be provided if the default bearer token extraction is not sufficient.
    ///
    /// See [JwtExtractor] for more information.
    pub fn jwt_extractor(mut self, jwt_extractor: Arc<dyn JwtExtractor + Send + Sync>) -> Self {
        self.jwt_extractor = Some(jwt_extractor);
        self
    }

    /// Construct an OAuth2ResourceServer.
    ///
    /// During construction the OIDC Provider Configuration endpoint of the
    /// authorization server might be queried.
    /// Thus, the operation can fail and therefore returns a Result.
    pub async fn build(self) -> Result<OAuth2ResourceServer<Claims>, StartupError> {
        if self.tenant_configurations.is_empty() {
            return Err(StartupError::InvalidParameter(
                "At least one TenantConfiguration is required".to_owned(),
            ));
        }
        let num_tenants = self.tenant_configurations.len();
        let auth_resolver = self.auth_resolver.unwrap_or_else(|| {
            if num_tenants == 1 {
                Arc::new(SingleAuthorizerResolver {})
            } else {
                Arc::new(IssuerAuthorizerResolver {})
            }
        });
        OAuth2ResourceServer::new(
            self.tenant_configurations,
            auth_resolver,
            self.jwt_extractor,
        )
        .await
    }
}

impl<Claims> Default for OAuth2ResourceServerBuilder<Claims> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Clone, Debug, Deserialize)]
    struct Claims {}

    #[tokio::test]
    async fn should_require_tenant_configurations() {
        let result = OAuth2ResourceServerBuilder::<Claims>::new().build().await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            StartupError::InvalidParameter(
                "At least one TenantConfiguration is required".to_owned()
            )
        )
    }
}
