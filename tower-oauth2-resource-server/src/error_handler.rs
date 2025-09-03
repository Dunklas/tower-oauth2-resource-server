use http::Response;

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
        error.into()
    }
}
