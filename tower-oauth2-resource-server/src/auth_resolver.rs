use http::HeaderMap;

use crate::{authorizer::token_authorizer::Authorizer, jwt_unverified::UnverifiedJwt};

pub trait AuthorizerResolver<Claims>: Send + Sync + std::fmt::Debug {
    fn select_authorizer<'a>(
        &'a self,
        authorizers: &'a [Authorizer<Claims>],
        headers: &HeaderMap,
        unverified_jwt: &UnverifiedJwt,
    ) -> Option<&'a Authorizer<Claims>>;
}

/// Selects the first of the configured authorizers.
///
/// This is the default when a single [TenantConfiguration](crate::tenant::TenantConfiguration) is provided.
#[derive(Debug)]
pub struct SingleAuthorizerResolver {}

impl<Claims> AuthorizerResolver<Claims> for SingleAuthorizerResolver {
    fn select_authorizer<'a>(
        &'a self,
        authorizers: &'a [Authorizer<Claims>],
        _headers: &HeaderMap,
        _unverified_jwt: &UnverifiedJwt,
    ) -> Option<&'a Authorizer<Claims>> {
        authorizers.first()
    }
}

/// Selects an authorizer based on `iss` claim of JWTs.
///
/// This is the default when multiple [TenantConfiguration](crate::tenant::TenantConfiguration) instances are provided.
#[derive(Debug)]
pub struct IssuerAuthorizerResolver {}

impl<Claims> AuthorizerResolver<Claims> for IssuerAuthorizerResolver {
    fn select_authorizer<'a>(
        &'a self,
        authorizers: &'a [Authorizer<Claims>],
        _headers: &HeaderMap,
        unverified_jwt: &UnverifiedJwt,
    ) -> Option<&'a Authorizer<Claims>> {
        let claims = unverified_jwt.claims()?;
        let issuer = claims.get("iss")?.as_str()?;
        authorizers
            .iter()
            .find(|authorizer| authorizer.identifier() == issuer)
    }
}

/// Selects an authorizer based on `kid` of JWTs.
///
#[derive(Debug)]
pub struct KidAuthorizerResolver {}

impl<Claims> AuthorizerResolver<Claims> for KidAuthorizerResolver {
    fn select_authorizer<'a>(
        &'a self,
        authorizers: &'a [Authorizer<Claims>],
        _headers: &HeaderMap,
        unverified_jwt: &UnverifiedJwt,
    ) -> Option<&'a Authorizer<Claims>> {
        let header = unverified_jwt.header()?;
        let kid = header.get("kid")?.as_str()?;
        authorizers
            .iter()
            .find(|authorizer| authorizer.has_kid(kid))
    }
}
