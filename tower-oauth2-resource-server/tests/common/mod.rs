use bytes::Bytes;
use http::{HeaderName, Request, Response, StatusCode};
use http_body_util::Full;
use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};
use tower::BoxError;
use tower_oauth2_resource_server::{error::AuthError, error_handler::ErrorHandler};

pub mod context;
pub mod jwt;

#[derive(Clone, Debug, Deserialize)]
pub struct RsaKey {
    pub private_key: String,
    pub modulus: String,
    pub exponent: String,
}

impl RsaKey {
    pub fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_rsa_pem(self.private_key.as_bytes())
            .expect("Failed to create EncodingKey")
    }
}

#[derive(Serialize)]
pub struct OpenIdConfig {
    pub issuer: String,
    pub jwks_uri: String,
}

#[derive(Serialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Serialize)]
struct Jwk {
    kty: String,
    use_: String,
    alg: String,
    kid: String,
    n: String,
    e: String,
}

pub fn jwks(keys: &[(&str, &RsaKey)]) -> Jwks {
    let keys = keys
        .iter()
        .map(|(kid, pub_key)| Jwk {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            alg: "RS256".to_string(),
            kid: kid.to_string(),
            n: pub_key.modulus.to_string(),
            e: pub_key.exponent.to_string(),
        })
        .collect::<Vec<_>>();
    Jwks { keys }
}

pub fn rsa_keys() -> [RsaKey; 2] {
    let key_pairs = include_str!("key-pairs.json");
    serde_json::from_str(key_pairs).expect("Failed to read key-pairs.json")
}

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
