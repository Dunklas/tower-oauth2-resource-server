#![doc = include_str!("../README.md")]

/// [Authorizer](crate::authorizer::token_authorizer::Authorizer) is the struct responsible for
/// validating requests and performing JWKS rotation against an authorization server.
///
/// Not to be used directly.
/// Only need to be publically exposed for custom implementations of [AuthorizerResolver](crate::auth_resolver::AuthorizerResolver).
pub mod authorizer;

/// Builder used to construct an [OAuth2ResourceServer](crate::server::OAuth2ResourceServer) instance.
///
/// For further information on the different properties,
/// see [OAuth2ResourceServerBuilder](crate::builder::OAuth2ResourceServerBuilder)
/// and [TenantConfigurationBuilder](crate::tenant::TenantConfigurationBuilder).
///
/// # Example using [DefaultClaims](crate::claims::DefaultClaims)
///
/// ```no_run
/// use tower_oauth2_resource_server::server::OAuth2ResourceServer;
/// use tower_oauth2_resource_server::tenant::TenantConfiguration;
///
/// #[tokio::main]
/// async fn main() {
///     let oauth2_resource_server = <OAuth2ResourceServer>::builder()
///         .add_tenant(TenantConfiguration::builder("https://some-auth-server.com")
///             .audiences(&["https://some-resource-server.com"])
///             .build().await.expect("Failed to build tenant configuration"))
///         .build()
///         .await;
/// }
/// ```
///
/// # Example using custom claims implementation
///
/// ```no_run
/// use serde::{Deserialize, Serialize};
/// use tower_oauth2_resource_server::server::OAuth2ResourceServer;
/// use tower_oauth2_resource_server::tenant::TenantConfiguration;
///
/// #[derive(Clone, Debug, Deserialize, Serialize)]
/// struct MyClaims {
///     pub iss: String,
///     pub scp: Vec<String>
/// }
/// #[tokio::main]
/// async fn main() {
///     let oauth2_resource_server = OAuth2ResourceServer::<MyClaims>::builder()
///         .add_tenant(TenantConfiguration::builder("https://some-auth-server.com")
///             .audiences(&["https://some-resource-server.com"])
///             .build().await.expect("Failed to build tenant configuration"))
///         .build()
///         .await;
/// }
/// ```
pub mod builder;

/// Default claims implementation.
///
/// Used by default when constructing a [OAuth2ResourceServer](crate::server::OAuth2ResourceServer).
///
/// If you need other claims, an own struct can be provided
/// to [OAuth2ResourceServer](crate::server::OAuth2ResourceServer) as a
/// generic parameter.
pub mod claims;

/// The actual tower middleware
///
/// Contains implementations of [Service](https://docs.rs/tower/latest/tower/trait.Service.html)
/// and [Layer](https://docs.rs/tower/latest/tower/trait.Layer.html)
/// from the tower library.
///
/// You shouldn't need to interact with these implementations, more than
/// calling [OAuth2ResourceServer::into_layer()](crate::server::OAuth2ResourceServer::into_layer).
pub mod layer;

/// [OAuth2ResourceServer](crate::server::OAuth2ResourceServer) is
/// what underpins the tower middleware, and actually performs
/// JWT validation.
///
/// In addition, it queries and maintains a state of public
/// keys used by the external authorization server.
///
/// It's recommended to keep a single instance of this in
/// an [Arc](https://doc.rust-lang.org/std/sync/struct.Arc.html)
/// and provide references to it to the different routes
/// where JWT validation is needed.
pub mod server;

/// [ClaimsValidationSpec](crate::validation::ClaimsValidationSpec) is used to
/// optionally customize what claims that are required in incoming JWTs.
///
/// Provided when constructing a [OAuth2ResourceServer](crate::server::OAuth2ResourceServer)
/// via [claims_validation_spec](crate::tenant::TenantConfiguration::claims_validation_spec).
pub mod validation;

/// [AuthorizerResolver](crate::auth_resolver::AuthorizerResolver) is used to
/// decide what [Authorizer](crate::authorizer::token_authorizer::Authorizer) that
/// will validate a request.
///
/// By default, either [SingleAuthorizerResolver](crate::auth_resolver::SingleAuthorizerResolver)
/// or [IssuerAuthorizerResolver](crate::auth_resolver::IssuerAuthorizerResolver) will be used.
///
/// You can also provide your own implementation of [AuthorizerResolver](crate::auth_resolver::AuthorizerResolver)
/// to customize the behavior.
pub mod auth_resolver;

/// [UnverifiedJwt](crate::jwt_unverified::UnverifiedJwt) is used internally
/// to represent an unverified JWT.
///
/// May be accessed in a custom [AuthorizerResolver](crate::auth_resolver::AuthorizerResolver)
/// to make decisions based on JWT claims or header.
pub mod jwt_unverified;

/// [TenantConfiguration](crate::tenant::TenantConfiguration) is used to
/// configure the interaction with and validation strategy against an authorization server.
///
/// Provided when constructing a [OAuth2ResourceServer](crate::server::OAuth2ResourceServer)
/// via [add_tenant](crate::builder::OAuth2ResourceServerBuilder::add_tenant).
pub mod tenant;

/// [ErrorHandler](crate::error_handler::ErrorHandler) is used to produce a HTTP response
/// on authentication error.
///
/// A custom implementation may be provided by using [into_layer_with_error_handler](crate::server::OAuth2ResourceServer::into_layer_with_error_handler).
///
/// If no implementation is provided, [DefaultErrorHandler](crate::error_handler::DefaultErrorHandler)
/// will be used.
pub mod error_handler;

/// Error types
pub mod error;

/// [BearerTokenResolver](crate::jwt_resolver::BearerTokenResolver) is used to extract JWT tokens from HTTP requests.
///
/// The default implementation [DefaultBearerTokenResolver](crate::jwt_resolver::DefaultBearerTokenResolver)
/// extracts tokens from the Authorization header with the "Bearer" prefix.
///
/// You can provide a custom implementation to extract tokens from different headers,
/// query parameters, etc.
///
/// Custom implementations may be provided via [bearer_token_resolver](crate::builder::OAuth2ResourceServerBuilder::bearer_token_resolver).
pub mod jwt_resolver;

mod oidc;
