use std::sync::Arc;

use log::info;
use serde::de::DeserializeOwned;

use crate::{
    error::StartupError,
    jwks::{JwksProducer, TimerJwksProducer},
    jwt_validate::{JwtValidator, OnlyJwtValidator},
    server::resolve_config,
    tenant::TenantConfiguration,
};

#[derive(Clone)]
pub struct Authorizer<Claims> {
    pub jwt_validator: Arc<dyn JwtValidator<Claims> + Send + Sync>,
    #[allow(dead_code)]
    jwks_producer: Arc<dyn JwksProducer + Send + Sync>,
}

impl<Claims> Authorizer<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    pub async fn new(config: TenantConfiguration) -> Result<Self, StartupError> {
        let (jwks_url, claims_validation_spec) =
            resolve_config(config.issuer_url, config.jwks_url, config.audiences).await?;
        let claims_validation_spec = config
            .claims_validation_spec
            .unwrap_or(claims_validation_spec);
        info!(
            "Will validate the following claims: {}",
            claims_validation_spec
        );

        let validator = Arc::new(OnlyJwtValidator::new(claims_validation_spec));

        let mut jwks_producer =
            TimerJwksProducer::new(jwks_url.clone(), config.jwks_refresh_interval);
        jwks_producer.add_consumer(validator.clone());
        jwks_producer.start();

        Ok(Self {
            jwt_validator: validator,
            jwks_producer: Arc::new(jwks_producer),
        })
    }
}
