use jsonwebtoken::EncodingKey;
use serde::{Deserialize, Serialize};

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
