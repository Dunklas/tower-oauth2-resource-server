use http::HeaderMap;

use crate::{error::AuthError, jwt_unverified::UnverifiedJwt};

pub trait JwtExtractor {
    fn extract_jwt(&self, headers: &HeaderMap) -> Result<UnverifiedJwt, AuthError>;
}

pub struct BearerTokenJwtExtractor;

impl JwtExtractor for BearerTokenJwtExtractor {
    fn extract_jwt(&self, headers: &HeaderMap) -> Result<UnverifiedJwt, AuthError> {
        Ok(UnverifiedJwt::new(
            headers
                .get(http::header::AUTHORIZATION)
                .ok_or(AuthError::MissingAuthorizationHeader)?
                .to_str()
                .map_err(|_| AuthError::InvalidAuthorizationHeader)?
                .strip_prefix("Bearer ")
                .ok_or(AuthError::InvalidAuthorizationHeader)?
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn test_missing_authorization() {
        let headers = HeaderMap::new();
        let result = BearerTokenJwtExtractor {}.extract_jwt(&headers);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::MissingAuthorizationHeader);
    }

    #[test]
    fn test_missing_bearer_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str("Boarer XXX").unwrap(),
        );
        let result = BearerTokenJwtExtractor {}.extract_jwt(&headers);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::InvalidAuthorizationHeader);
    }

    #[test]
    fn test_ok() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str("Bearer XXX").unwrap(),
        );
        let result = BearerTokenJwtExtractor {}.extract_jwt(&headers);

        assert!(result.is_ok());
    }
}
