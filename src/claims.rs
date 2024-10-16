use serde::Deserialize;
use serde_with::{formats::PreferMany, serde_as, OneOrMany};

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct DefaultClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    pub aud: Vec<String>,
    pub jti: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_aud() {
        let raw_claims = "{ \"aud\": \"single\" }";
        let claims: DefaultClaims = serde_json::from_str(raw_claims).unwrap();
        assert_eq!(claims.aud.len(), 1);
        assert_eq!(claims.aud.get(0).unwrap(), "single");
    }

    #[test]
    fn multiple_aud() {
        let raw_claims = "{ \"aud\": [\"first\", \"second\"] }";
        let claims: DefaultClaims = serde_json::from_str(raw_claims).unwrap();
        assert_eq!(claims.aud.len(), 2);
        assert_eq!(claims.aud.get(0).unwrap(), "first");
        assert_eq!(claims.aud.get(1).unwrap(), "second");
    }
}
