use http::HeaderMap;

use crate::authorizer::token_authorizer::Authorizer;

// TODO: Make fn take header_map and JWT claims instead? To avoid that B generic type
pub trait AuthorizerResolver<Claims>: Send + Sync {
    fn select_authorizer<'a, 'b>(
        &'a self,
        headers: &'b HeaderMap,
        authorizers: &'a Vec<Authorizer<Claims>>,
    ) -> Option<&'a Authorizer<Claims>>;
}

pub struct SingleAuthorizerResolver {}

impl<Claims> AuthorizerResolver<Claims> for SingleAuthorizerResolver {
    fn select_authorizer<'a, 'b>(
        &'a self,
        _headers: &'b HeaderMap,
        authorizers: &'a Vec<Authorizer<Claims>>,
    ) -> Option<&'a Authorizer<Claims>> {
        authorizers.first()
    }
}
