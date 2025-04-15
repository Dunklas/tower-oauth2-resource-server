use base64::prelude::BASE64_STANDARD_NO_PAD;

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
        let header_b64 = self.token.split('.').nth(0)?;
        let header_bytes = base64::Engine::decode(&BASE64_STANDARD_NO_PAD, header_b64).ok()?;
        let header_str = String::from_utf8(header_bytes).ok()?;
        serde_json::from_str(&header_str).ok()?
    }

    pub fn claims(&self) -> Option<serde_json::Value> {
        let claims_b64 = self.token.split('.').nth(1)?;
        let claims_bytes = base64::Engine::decode(&BASE64_STANDARD_NO_PAD, claims_b64).unwrap();
        let claims_str = String::from_utf8(claims_bytes).ok()?;
        serde_json::from_str(&claims_str).ok()?
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const VALID_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";

    #[test]
    fn parse_header() {
        let header = UnverifiedJwt::new(VALID_TOKEN).header();
        assert!(header.is_some());
        assert_eq!(
            header,
            Some(json!({
                "alg": "HS256",
                "typ": "JWT"
            }))
        );
    }

    #[test]
    fn parse_claims() {
        let claims = UnverifiedJwt::new(VALID_TOKEN).claims();
        assert!(claims.is_some());
        assert_eq!(
            claims,
            Some(json!({
              "sub": "1234567890",
              "name": "John Doe",
              "admin": true,
              "iat": 1516239022
            }))
        );
    }
}
