use std::sync::Arc;

use log::info;
use serde::de::DeserializeOwned;

use crate::{
    authorizer::{jwks::TimerJwksProducer, jwt_validate::OnlyJwtValidator},
    error::{AuthError, StartupError},
    jwt_unverified::UnverifiedJwt,
    tenant::TenantConfiguration,
};

use super::{jwks::JwksProducer, jwt_validate::JwtValidator};

#[derive(Clone)]
pub struct Authorizer<Claims> {
    identifier: String,
    jwt_validator: Arc<dyn JwtValidator<Claims> + Send + Sync>,
    #[allow(dead_code)]
    jwks_producer: Arc<dyn JwksProducer + Send + Sync>,
}

impl<Claims> Authorizer<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    pub(crate) async fn new(config: TenantConfiguration) -> Result<Self, StartupError> {
        info!(
            "Authorizer '{}' will validate the following claims: {}",
            &config.identifier, &config.claims_validation_spec
        );

        let validator = Arc::new(OnlyJwtValidator::new(config.claims_validation_spec));

        let mut jwks_producer =
            TimerJwksProducer::new(config.jwks_url, config.jwks_refresh_interval);
        jwks_producer.add_consumer(validator.clone());
        jwks_producer.start();

        Ok(Self {
            identifier: config.identifier,
            jwt_validator: validator,
            jwks_producer: Arc::new(jwks_producer),
        })
    }
}

impl<Claims> Authorizer<Claims> {
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub(crate) async fn validate(&self, token: &UnverifiedJwt) -> Result<Claims, AuthError> {
        self.jwt_validator.validate(token).await
    }
}
