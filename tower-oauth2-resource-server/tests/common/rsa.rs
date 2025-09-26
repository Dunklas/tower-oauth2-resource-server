use jsonwebtoken::EncodingKey;
use serde::Deserialize;

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

pub fn rsa_keys() -> [RsaKey; 2] {
    let key_pairs = include_str!("key-pairs.json");
    serde_json::from_str(key_pairs).expect("Failed to read key-pairs.json")
}
