use http::{header::WWW_AUTHENTICATE, HeaderValue, Response, StatusCode};

#[derive(Debug, PartialEq)]
pub enum StartupError {
    InvalidParameter(String),
    OidcDiscoveryFailed(String),
}

#[derive(Debug, PartialEq)]
pub enum JwkError {
    FetchFailed,
    ParseFailed,
    MissingKeyId,
    UnexpectedAlgorithm,
    DecodingFailed,
}

#[derive(Debug, PartialEq)]
pub enum AuthError {
    MissingAuthorizationHeader,
    InvalidAuthorizationHeader,
    ParseJwtError,
    InvalidKeyId,
    ValidationFailed {
        reason: jsonwebtoken::errors::ErrorKind,
    },
}

impl<B> From<AuthError> for Response<B>
where
    B: Default,
{
    fn from(e: AuthError) -> Self {
        let mut response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(B::default())
            .unwrap();
        if e == AuthError::MissingAuthorizationHeader || e == AuthError::InvalidAuthorizationHeader
        {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_str("Bearer").unwrap());
        }
        response
    }
}
