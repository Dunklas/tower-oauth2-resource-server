use jsonwebtoken::{Header, encode};
use serde_json::json;

use crate::common::{
    context::DEFAULT_KID,
    rsa::{RsaKey, rsa_keys},
};

#[derive(Clone, Debug)]
pub struct JwtBuilder {
    encoding_key: (String, RsaKey),
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
    nbf: Option<u64>,
    exp: Option<u64>,
    custom_claims: Vec<(String, String)>,
}

impl JwtBuilder {
    pub fn new() -> Self {
        JwtBuilder::default()
    }

    pub fn encoding_key(mut self, encoding_key: (String, RsaKey)) -> Self {
        self.encoding_key = encoding_key;
        self
    }

    pub fn iss<S: Into<String>>(mut self, iss: S) -> Self {
        self.iss = Some(iss.into());
        self
    }

    pub fn subject<S: Into<String>>(mut self, sub: S) -> Self {
        self.sub = Some(sub.into());
        self
    }

    pub fn aud<S: Into<String>>(mut self, aud: S) -> Self {
        self.aud = Some(aud.into());
        self
    }

    pub fn nbf(mut self, nbf: u64) -> Self {
        self.nbf = Some(nbf);
        self
    }

    pub fn exp(mut self, exp: u64) -> Self {
        self.exp = Some(exp);
        self
    }

    pub fn custom_claim(mut self, key: String, value: String) -> Self {
        self.custom_claims.push((key, value));
        self
    }

    pub fn build(&self) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.encoding_key.0.clone());

        let mut claims = json!({});

        if let Some(ref iss) = self.iss {
            claims["iss"] = json!(iss);
        }
        if let Some(ref sub) = self.sub {
            claims["sub"] = json!(sub);
        }
        if let Some(ref aud) = self.aud {
            claims["aud"] = json!(aud);
        }
        if let Some(nbf) = self.nbf {
            claims["nbf"] = json!(nbf);
        }
        if let Some(exp) = self.exp {
            claims["exp"] = json!(exp);
        }

        for (key, value) in &self.custom_claims {
            claims[key] = json!(value);
        }

        encode(&header, &claims, &self.encoding_key.1.encoding_key()).unwrap()
    }
}

impl Default for JwtBuilder {
    fn default() -> Self {
        JwtBuilder {
            encoding_key: (DEFAULT_KID.to_string(), rsa_keys()[0].clone()),
            iss: None,
            sub: None,
            aud: None,
            nbf: None,
            exp: None,
            custom_claims: Vec::new(),
        }
    }
}
