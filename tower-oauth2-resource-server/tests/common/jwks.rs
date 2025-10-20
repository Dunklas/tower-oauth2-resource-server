use serde::Serialize;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use crate::common::rsa::RsaKey;

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

pub fn build_jwks(keys: &[(&str, &RsaKey)]) -> Jwks {
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

pub async fn mock_jwks(mock_server: &MockServer, issuer_path: &str, keys: &[(&str, &RsaKey)]) {
    let jwks = build_jwks(keys);
    Mock::given(method("GET"))
        .and(path(format!("{}/jwks", issuer_path)))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(mock_server)
        .await;
}
