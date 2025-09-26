use bytes::Bytes;
use http::{HeaderName, Request, Response, StatusCode};
use http_body_util::Full;
use tower::BoxError;
use tower_oauth2_resource_server::{error::AuthError, error_handler::ErrorHandler};

pub async fn echo(req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>, BoxError> {
    let b = req.into_body();
    let mut response = Response::new(b);
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}

pub fn request_with_headers(headers: Vec<(HeaderName, &str)>) -> Request<Full<Bytes>> {
    let mut request = Request::get("/");
    let request_headers = request.headers_mut().unwrap();
    headers.into_iter().for_each(|(name, value)| {
        request_headers.insert(name, value.parse().unwrap());
    });
    request.body(Full::<Bytes>::default()).unwrap()
}

pub struct DetailedErrorHandler {}

impl ErrorHandler<Full<Bytes>> for DetailedErrorHandler {
    fn map_error(&self, error: AuthError) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Full::new(error.to_string().into()))
            .unwrap()
    }
}
