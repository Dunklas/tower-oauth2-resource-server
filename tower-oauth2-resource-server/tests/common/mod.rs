use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod context;

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

pub fn jwt_from(private_key: &RsaKey, kid: &str, claims: Value) -> String {
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    encode(&header, &claims, &private_key.encoding_key()).unwrap()
}
