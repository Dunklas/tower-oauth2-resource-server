use http::{header::WWW_AUTHENTICATE, HeaderValue, Response, StatusCode};

use crate::error::AuthError;

pub trait ErrorHandler<B>: Send + Sync {
    fn handle_error(&self, error: &AuthError) -> Response<B>;
}

pub struct DefaultErrorHandler;

impl<B> ErrorHandler<B> for DefaultErrorHandler
where
    B: Default,
{
    fn handle_error(&self, error: &AuthError) -> Response<B> {
        let mut response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(B::default())
            .unwrap();
        if *error == AuthError::MissingAuthorizationHeader
            || *error == AuthError::InvalidAuthorizationHeader
        {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_str("Bearer").unwrap());
        }
        response
    }
}
