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
        let header = jsonwebtoken::decode_header(self.as_str()).ok()?;
        serde_json::to_value(header).ok()
    }

    pub fn claims(&self) -> Option<serde_json::Value> {
        jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(self.as_str())
            .ok()
            .map(|token| token.claims)
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

    #[test]
    fn malformed_claims_return_none() {
        let claims = UnverifiedJwt::new("a.%ff.c").claims();

        assert!(claims.is_none());
    }
}
