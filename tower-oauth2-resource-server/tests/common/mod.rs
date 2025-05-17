use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[derive(Debug, Deserialize)]
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
struct OpenIdConfig {
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

pub async fn mock_oidc_config(mock_server: &MockServer, issuer: &str) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(OpenIdConfig {
            issuer: issuer.to_owned(),
            jwks_uri: format!("{}/jwks", &mock_server.uri()),
        }))
        .mount(mock_server)
        .await;
}

pub fn jwks(keys: &[(String, &RsaKey)]) -> Jwks {
    let keys = keys
        .iter()
        .map(|(kid, pub_key)| Jwk {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            alg: "RS256".to_string(),
            kid: kid.clone(),
            n: pub_key.modulus.to_string(),
            e: pub_key.exponent.to_string(),
        })
        .collect::<Vec<_>>();
    Jwks { keys }
}

pub async fn mock_jwks(mock_server: &MockServer, keys: &[(String, &RsaKey)]) {
    let jwks = jwks(keys);
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(mock_server)
        .await;
}

pub fn rsa_keys() -> Vec<RsaKey> {
    let key_pairs = include_str!("key-pairs.json");
    serde_json::from_str(key_pairs).expect("Failed to read key-pairs.json")
}

pub fn jwt_from(private_key: &RsaKey, kid: &str, claims: Value) -> String {
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    encode(&header, &claims, &private_key.encoding_key()).unwrap()
}
