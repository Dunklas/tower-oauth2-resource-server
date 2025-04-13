#[derive(Debug, Clone)]
pub struct UnverifiedJwt {
    token: String,
}

impl UnverifiedJwt {
    pub fn new(raw_token: impl Into<String>) -> Self {
        UnverifiedJwt {
            token: raw_token.into(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.token
    }

    pub fn header(&self) -> Option<serde_json::Value> {
        let header_b64 = self.token.split('.').nth(0).unwrap();
        let header_bytes = base64::decode(header_b64).unwrap();
        let header_str = String::from_utf8(header_bytes).unwrap();
        serde_json::from_str(&header_str).ok()?
    }

    pub fn claims(&self) -> Option<serde_json::Value> {
        let claims_b64 = self.token.split('.').nth(1).unwrap();
        let claims_bytes = base64::decode(claims_b64).unwrap();
        let claims_str = String::from_utf8(claims_bytes).unwrap();
        serde_json::from_str(&claims_str).ok()?
    }
}
