use http::Request;

use crate::{error::AuthError, jwt_unverified::UnverifiedJwt};

/// Trait for resolving bearer tokens (JWT) from HTTP requests.
///
/// The trait accepts a reference to the request (without the body) to allow
/// implementations to extract tokens from headers, query parameters, or other
/// parts of the request.
pub trait BearerTokenResolver {
    fn resolve(&self, request: &Request<()>) -> Result<UnverifiedJwt, AuthError>;
}

/// Default implementation that extracts bearer tokens from the Authorization header.
pub struct DefaultBearerTokenResolver;

impl BearerTokenResolver for DefaultBearerTokenResolver {
    fn resolve(&self, request: &Request<()>) -> Result<UnverifiedJwt, AuthError> {
        Ok(UnverifiedJwt::new(
            request
                .headers()
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

pub(crate) fn request_ref<Body>(request: &Request<Body>) -> Request<()> {
    let mut builder = Request::builder()
        .method(request.method())
        .uri(request.uri())
        .version(request.version());

    if let Some(headers) = builder.headers_mut() {
        *headers = request.headers().clone();
    }

    builder.body(()).expect("Failed to build request reference")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_authorization() {
        let request = Request::builder().body(()).unwrap();
        let result = DefaultBearerTokenResolver {}.resolve(&request);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::MissingAuthorizationHeader);
    }

    #[test]
    fn test_missing_bearer_prefix() {
        let request = Request::builder()
            .header("Authorization", "Boarer XXX")
            .body(())
            .unwrap();
        let result = DefaultBearerTokenResolver {}.resolve(&request);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::InvalidAuthorizationHeader);
    }

    #[test]
    fn test_ok() {
        let request = Request::builder()
            .header("Authorization", "Bearer XXX")
            .body(())
            .unwrap();
        let result = DefaultBearerTokenResolver {}.resolve(&request);

        assert!(result.is_ok());
    }
}
