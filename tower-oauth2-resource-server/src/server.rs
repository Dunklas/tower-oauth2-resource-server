use core::fmt;
use std::sync::Arc;

use futures_util::future::join_all;
use http::Request;
use log::debug;
use serde::de::DeserializeOwned;

use crate::{
    auth_resolver::AuthorizerResolver,
    authorizer::token_authorizer::Authorizer,
    claims::DefaultClaims,
    error::{AuthError, StartupError},
    error_handler::{DefaultErrorHandler, ErrorHandler},
    jwt_extract::{BearerTokenJwtExtractor, JwtExtractor},
    layer::OAuth2ResourceServerLayer,
    tenant::TenantConfiguration,
};

/// OAuth2ResourceServer
///
/// This is the actual middleware.
/// May be turned into a tower layer by calling [into_layer](OAuth2ResourceServer::into_layer).
#[derive(Clone)]
pub struct OAuth2ResourceServer<Claims = DefaultClaims> {
    authorizers: Vec<Authorizer<Claims>>,
    jwt_extractor: Arc<dyn JwtExtractor + Send + Sync>,
    auth_resolver: Arc<dyn AuthorizerResolver<Claims>>,
}

impl<Claims> OAuth2ResourceServer<Claims>
where
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    pub(crate) async fn new(
        tenant_configurations: Vec<TenantConfiguration>,
        auth_resolver: Arc<dyn AuthorizerResolver<Claims>>,
        jwt_extractor: Option<Arc<dyn JwtExtractor + Send + Sync>>,
    ) -> Result<OAuth2ResourceServer<Claims>, StartupError> {
        let authorizers = join_all(
            tenant_configurations
                .into_iter()
                .map(Authorizer::<Claims>::new)
                .collect::<Vec<_>>(),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>, StartupError>>()?;

        Ok(OAuth2ResourceServer {
            jwt_extractor: jwt_extractor.unwrap_or_else(|| Arc::new(BearerTokenJwtExtractor {})),
            authorizers,
            auth_resolver,
        })
    }

    pub(crate) async fn authorize_request<Body>(
        &self,
        mut request: Request<Body>,
    ) -> Result<Request<Body>, AuthError> {
        let token = match self.jwt_extractor.extract_jwt(request.headers()) {
            Ok(token) => token,
            Err(e) => {
                debug!("JWT extraction failed: {}", e);
                return Err(e);
            }
        };
        let authorizer = self
            .auth_resolver
            .as_ref()
            .select_authorizer(&self.authorizers, request.headers(), &token)
            .ok_or(AuthError::AuthorizerNotFound)?;
        match authorizer.validate(&token) {
            Ok(res) => {
                debug!("JWT validation successful ({})", authorizer.identifier());
                request.extensions_mut().insert(res);
                Ok(request)
            }
            Err(e) => {
                debug!(
                    "JWT validation failed ({}) : {}",
                    authorizer.identifier(),
                    e
                );
                Err(e)
            }
        }
    }
}

impl<Claims> fmt::Debug for OAuth2ResourceServer<Claims> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2AuthenticationManager").finish()
    }
}

impl<Claims> OAuth2ResourceServer<Claims>
where
    Claims: Clone,
{
    /// Returns a [tower layer](https://docs.rs/tower/latest/tower/trait.Layer.html).
    pub fn into_layer<ResBody>(&self) -> OAuth2ResourceServerLayer<ResBody, Claims>
    where
        ResBody: Default,
    {
        OAuth2ResourceServerLayer::new(self.clone(), Arc::new(DefaultErrorHandler))
    }

    /// Returns a [tower layer](https://docs.rs/tower/latest/tower/trait.Layer.html) that uses a custom [ErrorHandler] implementation.
    pub fn into_layer_with_error_handler<ResBody>(
        &self,
        error_handler: Arc<dyn ErrorHandler<ResBody>>,
    ) -> OAuth2ResourceServerLayer<ResBody, Claims> {
        OAuth2ResourceServerLayer::new(self.clone(), error_handler)
    }
}
