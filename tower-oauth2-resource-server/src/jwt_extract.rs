use http::HeaderMap;

use crate::error::AuthError;

pub trait JwtExtractor {
    fn extract_jwt(&self, headers: &HeaderMap) -> Result<String, AuthError>;
}

pub struct BearerTokenJwtExtractor;

impl JwtExtractor for BearerTokenJwtExtractor {
    fn extract_jwt(&self, headers: &HeaderMap) -> Result<String, AuthError> {
        Ok(headers
            .get(http::header::AUTHORIZATION)
            .ok_or(AuthError::MissingAuthorizationHeader)?
            .to_str()
            .map_err(|_| AuthError::InvalidAuthorizationHeader)?
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidAuthorizationHeader)?
            .to_owned())
    }
}
