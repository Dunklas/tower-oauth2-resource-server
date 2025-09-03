use http::Response;

use crate::error::AuthError;

pub trait ErrorHandler<B>: Send + Sync {
    fn map_error(&self, error: AuthError) -> Response<B>;
}

pub struct DefaultErrorHandler;

impl<B> ErrorHandler<B> for DefaultErrorHandler
where
    B: Default,
{
    fn map_error(&self, error: AuthError) -> Response<B> {
        error.into()
    }
}
