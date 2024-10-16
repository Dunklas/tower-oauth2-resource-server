use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine,
};
use jsonwebtoken::{encode, EncodingKey, Header};
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use serde_json::Value;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[derive(Serialize)]
struct OpenIdConfig {
    pub issuer: String,
    pub jwks_uri: String,
}

#[derive(Serialize)]
struct Jwks {
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

const CUSTOM_ENGINE: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

pub async fn mock_oidc_config(mock_server: &MockServer, issuer: &str) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(OpenIdConfig {
            issuer: issuer.to_owned(),
            jwks_uri: format!("{}/jwks", &mock_server.uri()),
        }))
        .mount(&mock_server)
        .await;
}

pub async fn mock_jwks(mock_server: &MockServer, keys: Vec<(String, RsaPublicKey)>) {
    let keys = keys
        .into_iter()
        .map(|(kid, pub_key)| Jwk {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            alg: "RS256".to_string(),
            kid,
            n: CUSTOM_ENGINE.encode(pub_key.n().to_bytes_be()),
            e: CUSTOM_ENGINE.encode(pub_key.e().to_bytes_be()),
        })
        .collect::<Vec<_>>();
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(Jwks { keys }))
        .mount(&mock_server)
        .await;
}

pub fn rsa_key_pair() -> (RsaPrivateKey, RsaPublicKey) {
    let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

pub fn jwt_from(private_key: &RsaPrivateKey, kid: &str, claims: Value) -> String {
    let encoding_key = EncodingKey::from_rsa_der(private_key.to_pkcs1_der().unwrap().as_bytes());
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    encode(&header, &claims, &encoding_key).unwrap()
}
