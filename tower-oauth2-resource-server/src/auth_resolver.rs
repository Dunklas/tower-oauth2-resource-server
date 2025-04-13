use http::HeaderMap;

use crate::authorizer::token_authorizer::Authorizer;

// TODO: Make fn take header_map and JWT claims instead? To avoid that B generic type
pub trait AuthorizerResolver<Claims>: Send + Sync {
    fn select_authorizer<'a>(
        &'a self,
        headers: &HeaderMap,
        authorizers: &'a [Authorizer<Claims>],
    ) -> Option<&'a Authorizer<Claims>>;
}

pub struct SingleAuthorizerResolver {}

impl<Claims> AuthorizerResolver<Claims> for SingleAuthorizerResolver {
    fn select_authorizer<'a>(
        &'a self,
        _headers: &HeaderMap,
        authorizers: &'a [Authorizer<Claims>],
    ) -> Option<&'a Authorizer<Claims>> {
        authorizers.first()
    }
}
