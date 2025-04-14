use http::HeaderMap;

use crate::{authorizer::token_authorizer::Authorizer, jwt_unverified::UnverifiedJwt};

pub trait AuthorizerResolver<Claims>: Send + Sync {
    fn select_authorizer<'a>(
        &'a self,
        headers: &HeaderMap,
        unverified_jwt: &UnverifiedJwt,
        authorizers: &'a [Authorizer<Claims>],
    ) -> Option<&'a Authorizer<Claims>>;
}

pub struct SingleAuthorizerResolver {}

impl<Claims> AuthorizerResolver<Claims> for SingleAuthorizerResolver {
    fn select_authorizer<'a>(
        &'a self,
        _headers: &HeaderMap,
        _unverified_jwt: &UnverifiedJwt,
        authorizers: &'a [Authorizer<Claims>],
    ) -> Option<&'a Authorizer<Claims>> {
        authorizers.first()
    }
}

pub struct IssuerAuthorizerResolver {}

impl<Claims> AuthorizerResolver<Claims> for IssuerAuthorizerResolver {
    fn select_authorizer<'a>(
        &'a self,
        _headers: &HeaderMap,
        unverified_jwt: &UnverifiedJwt,
        authorizers: &'a [Authorizer<Claims>],
    ) -> Option<&'a Authorizer<Claims>> {
        let claims = unverified_jwt.claims()?;
        let issuer = claims.get("iss")?.as_str()?;
        authorizers
            .iter()
            .find(|authorizer| authorizer.identifier() == issuer)
    }
}
