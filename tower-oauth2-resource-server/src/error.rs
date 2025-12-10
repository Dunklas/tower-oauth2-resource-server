use std::{error::Error, fmt::Display};

use http::{HeaderValue, Response, StatusCode, header::WWW_AUTHENTICATE};
use jsonwebtoken::{Algorithm, jwk::KeyAlgorithm};

#[derive(Clone, Debug, PartialEq)]
pub enum StartupError {
    InvalidParameter(String),
    OidcDiscoveryFailed(String),
}

impl Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl Error for StartupError {}

#[derive(Clone, Debug, PartialEq)]
pub enum JwkError {
    FetchFailed,
    ParseFailed,
    MissingKeyId,
    DecodingFailed,
}

impl Display for JwkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl Error for JwkError {}

#[derive(Clone, Debug, PartialEq)]
pub enum AuthError {
    MissingAuthorizationHeader,
    InvalidAuthorizationHeader,
    ParseJwtError,
    InvalidKeyId,
    InvalidJwkAlgorithm(KeyAlgorithm),
    MismatchingAlgorithm(Algorithm, Algorithm),
    UnsupportedAlgorithm(Algorithm),
    ValidationFailed {
        reason: jsonwebtoken::errors::ErrorKind,
    },
    AuthorizerNotFound,
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl Error for AuthError {}

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
