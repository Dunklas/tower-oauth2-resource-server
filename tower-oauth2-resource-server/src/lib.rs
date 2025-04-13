#![doc = include_str!("../README.md")]

/// Builder used to construct an [OAuth2ResourceServer](crate::server::OAuth2ResourceServer) instance.
///
/// For further information on the different properties,
/// see [OAuth2ResourceServerBuilder](crate::builder::OAuth2ResourceServerBuilder).
///
/// # Example using [DefaultClaims](crate::claims::DefaultClaims)
///
/// ```
/// use tower_oauth2_resource_server::server::OAuth2ResourceServer;
///
/// #[tokio::main]
/// async fn main() {
///     let oauth2_resource_server = <OAuth2ResourceServer>::builder()
///         .issuer_url("https://some-auth-server.com")
///         .audiences(&["https://some-resource-server.com"])
///         .build()
///         .await;
/// }
/// ```
///
/// # Example using custom claims implementation
///
/// ```
/// use serde::{Deserialize, Serialize};
/// use tower_oauth2_resource_server::server::OAuth2ResourceServer;
///
/// #[derive(Clone, Debug, Deserialize, Serialize)]
/// struct MyClaims {
///     pub iss: String,
///     pub scp: Vec<String>
/// }
/// #[tokio::main]
/// async fn main() {
///     let oauth2_resource_server = OAuth2ResourceServer::<MyClaims>::builder()
///         .issuer_url("https://some-auth-server.com")
///         .audiences(&["https://some-resource-server.com"])
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
/// via [claims_validation](crate::builder::OAuth2ResourceServerBuilder::claims_validation).
pub mod validation;

/// TODO: documentation
pub mod tenant;

mod authorizer;
mod error;
mod jwt_extract;
mod oidc;
