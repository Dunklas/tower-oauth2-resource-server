use std::sync::Arc;

use crate::{jwks::JwksProducer, jwt_validate::JwtValidator};

#[derive(Clone)]
pub struct Authorizer<Claims> {
    pub jwt_validator: Arc<dyn JwtValidator<Claims> + Send + Sync>,
    #[allow(dead_code)]
    jwks_producer: Arc<dyn JwksProducer + Send + Sync>,
}

impl<Claims> Authorizer<Claims>
where
    Claims: Clone + Send + Sync + 'static,
{
    pub fn new(
        jwt_validator: Arc<dyn JwtValidator<Claims> + Send + Sync>,
        jwks_producer: Arc<dyn JwksProducer + Send + Sync>,
    ) -> Self {
        Self {
            jwt_validator,
            jwks_producer,
        }
    }
}
