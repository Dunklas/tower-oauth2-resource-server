use std::marker::PhantomData;

use serde::de::DeserializeOwned;

use crate::{error::StartupError, server::OAuth2ResourceServer, tenant::TenantConfiguration};

#[derive(Debug)]
pub struct OAuth2ResourceServerBuilder<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    tenant_configurations: Vec<TenantConfiguration>,
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
            phantom: PhantomData,
        }
    }

    pub fn add_tenant(mut self, tenant_configuration: TenantConfiguration) -> Self {
        self.tenant_configurations.push(tenant_configuration);
        self
    }

    /// Construct an OAuth2ResourceServer.
    ///
    /// During construction the OIDC Provider Configuration endpoint of the
    /// authorization server might be queried.
    /// Thus, the operation can fail and therefore returns a Result.
    pub async fn build(self) -> Result<OAuth2ResourceServer<Claims>, StartupError> {
        assert!(self.tenant_configurations.len() > 0);
        OAuth2ResourceServer::new(self.tenant_configurations).await
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
