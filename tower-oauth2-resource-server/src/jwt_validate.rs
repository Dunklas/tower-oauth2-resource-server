use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{Jwk, JwkSet, KeyAlgorithm},
};
use log::{info, warn};
use serde::de::DeserializeOwned;
use tokio::sync::RwLock;

use crate::{
    error::{AuthError, JwkError},
    jwks::JwksConsumer,
    validation::ClaimsValidationSpec,
};

#[async_trait]
pub trait JwtValidator<Claims> {
    async fn validate(&self, jwt: &str) -> Result<Claims, AuthError>;
}

pub struct OnlyJwtValidator {
    claims_validation: ClaimsValidationSpec,
    decoding_keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
    validations: Arc<RwLock<HashMap<Algorithm, Validation>>>,
}

#[async_trait]
impl<Claims> JwtValidator<Claims> for OnlyJwtValidator
where
    Claims: DeserializeOwned,
{
    async fn validate(&self, token: &str) -> Result<Claims, AuthError> {
        let header = decode_header(token).or(Err(AuthError::ParseJwtError))?;
        let key_id = header.kid.ok_or(AuthError::ParseJwtError)?;

        let decoding_keys = self.decoding_keys.read().await;
        let decoding_key = decoding_keys.get(&key_id).ok_or(AuthError::InvalidKeyId)?;
        let validations = self.validations.read().await;
        let validation = validations
            .get(&header.alg)
            .ok_or(AuthError::UnsupportedAlgorithm(header.alg))?;

        match decode::<Claims>(token, decoding_key, validation) {
            Ok(result) => Ok(result.claims),
            Err(e) => Err(AuthError::ValidationFailed {
                reason: e.into_kind(),
            }),
        }
    }
}

#[async_trait]
impl JwksConsumer for OnlyJwtValidator {
    async fn receive_jwks(&self, jwks: JwkSet) {
        self.update_decoding_keys(&jwks).await;
        self.update_validations(&jwks).await;
    }
}

impl OnlyJwtValidator {
    pub fn new(claims_validation: ClaimsValidationSpec) -> Self {
        Self {
            claims_validation,
            decoding_keys: Arc::new(RwLock::new(HashMap::new())),
            validations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn update_validations(&self, jwks: &JwkSet) {
        let algs = jwks
            .keys
            .iter()
            .filter_map(|jwk| jwk.common.key_algorithm)
            .filter_map(parse_key_alg)
            .collect::<HashSet<_>>();
        let mut validations = self.validations.write().await;
        *validations = algs
            .into_iter()
            .map(|alg| (alg, self.create_validation(&alg)))
            .collect();
    }

    fn create_validation(&self, alg: &Algorithm) -> Validation {
        let mut validation = Validation::new(*alg);
        let mut required_claims = Vec::<&'static str>::new();
        if let Some(iss) = &self.claims_validation.iss {
            required_claims.push("iss");
            validation.set_issuer(&[iss]);
        }
        if self.claims_validation.exp {
            required_claims.push("exp");
            validation.validate_exp = true;
        }
        if self.claims_validation.nbf {
            required_claims.push("nbf");
            validation.validate_nbf = true;
        }
        if let Some(aud) = &self.claims_validation.aud {
            required_claims.push("aud");
            validation.set_audience(aud);
        }
        validation.set_required_spec_claims(&required_claims);
        validation
    }

    async fn update_decoding_keys(&self, jwks: &JwkSet) {
        let decoding_keys = jwks
            .keys
            .iter()
            .map(|jwk| self.parse_jwk(jwk))
            .collect::<Result<HashMap<_, _>, _>>();
        match decoding_keys {
            Ok(decoding_keys) => {
                let mut keys = self.decoding_keys.write().await;
                *keys = decoding_keys;
                info!("Successfully updated JWK set");
            }
            Err(e) => {
                warn!("Unable to parse at least one JWK due to: {:?}", e);
            }
        }
    }

    fn parse_jwk(&self, jwk: &Jwk) -> Result<(String, DecodingKey), JwkError> {
        let key_id = jwk.common.key_id.as_ref().ok_or(JwkError::MissingKeyId)?;
        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|_| JwkError::DecodingFailed)?;
        Ok((key_id.clone(), decoding_key))
    }
}

fn parse_key_alg(key_alg: KeyAlgorithm) -> Option<Algorithm> {
    match key_alg {
        KeyAlgorithm::HS256 => Some(Algorithm::HS256),
        KeyAlgorithm::HS384 => Some(Algorithm::HS384),
        KeyAlgorithm::HS512 => Some(Algorithm::HS512),
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use base64::{
        Engine, alphabet,
        engine::{self, general_purpose},
    };
    use jsonwebtoken::{
        EncodingKey, Header, encode,
        errors::ErrorKind,
        jwk::{Jwk, JwkSet},
    };
    use lazy_static::lazy_static;
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{error::AuthError, jwks::JwksConsumer, validation::ClaimsValidationSpec};

    use super::{JwtValidator, OnlyJwtValidator};

    #[derive(Deserialize, Debug)]
    struct Claims {}

    lazy_static! {
        static ref DEFAULT_KID: String = "test-kid".to_owned();
        static ref PRIVATE_KEY: RsaPrivateKey =
            RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        static ref PUBLIC_KEY: RsaPublicKey = RsaPublicKey::from(PRIVATE_KEY.deref());
        static ref ENCODING_KEY: EncodingKey =
            EncodingKey::from_rsa_der(PRIVATE_KEY.to_pkcs1_der().unwrap().as_bytes());
        static ref CUSTOM_ENGINE: engine::GeneralPurpose =
            engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    }

    #[tokio::test]
    async fn empty_token() {
        let validator = create_validator(ClaimsValidationSpec::new()).await;
        let result = validator.validate("").await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::ParseJwtError);
    }

    #[tokio::test]
    async fn missing_kid() {
        let validator = create_validator(ClaimsValidationSpec::new()).await;
        let token = jwt_from(&serde_json::json!({}), None);

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::ParseJwtError);
    }

    #[tokio::test]
    async fn non_existing_kid() {
        let validator = create_validator(ClaimsValidationSpec::new()).await;
        let token = jwt_from(&serde_json::json!({}), Some("another-kid".to_owned()));

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::InvalidKeyId);
    }

    #[tokio::test]
    async fn invalid_key() {
        let validator = create_validator(ClaimsValidationSpec::new()).await;
        let another_encoding_key = EncodingKey::from_rsa_der(
            RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
                .unwrap()
                .to_pkcs1_der()
                .unwrap()
                .as_bytes(),
        );
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(DEFAULT_KID.to_owned());
        let token = encode(&header, &serde_json::json!({}), &another_encoding_key).unwrap();

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::ValidationFailed {
                reason: ErrorKind::InvalidSignature
            }
        )
    }

    #[tokio::test]
    async fn missing_nbf() {
        let validator = create_validator(ClaimsValidationSpec::new().nbf(true)).await;
        let token = jwt_from(&serde_json::json!({}), Some(DEFAULT_KID.to_owned()));

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::ValidationFailed {
                reason: ErrorKind::MissingRequiredClaim("nbf".to_owned())
            }
        );
    }

    #[tokio::test]
    async fn invalid_nbf() {
        let validator = create_validator(ClaimsValidationSpec::new().nbf(true)).await;
        let token = jwt_from(
            &serde_json::json!({
                "nbf": unix_epoch_sec_from_now(60 * 2),
            }),
            Some(DEFAULT_KID.to_owned()),
        );

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::ValidationFailed {
                reason: ErrorKind::ImmatureSignature
            }
        );
    }

    #[tokio::test]
    async fn missing_exp() {
        let validator = create_validator(ClaimsValidationSpec::new().exp(true)).await;
        let token = jwt_from(&serde_json::json!({}), Some(DEFAULT_KID.to_owned()));

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::ValidationFailed {
                reason: ErrorKind::MissingRequiredClaim("exp".to_owned())
            }
        );
    }

    #[tokio::test]
    async fn missing_aud() {
        let validator = create_validator(
            ClaimsValidationSpec::new()
                .aud(["https://some-resource.server.com".to_owned()].to_vec()),
        )
        .await;
        let token = jwt_from(&serde_json::json!({}), Some(DEFAULT_KID.to_owned()));

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::ValidationFailed {
                reason: ErrorKind::MissingRequiredClaim("aud".to_owned())
            }
        );
    }

    #[tokio::test]
    async fn invalid_aud() {
        let validator = create_validator(
            ClaimsValidationSpec::new()
                .aud(["https://some-resource-server.com".to_owned()].to_vec()),
        )
        .await;
        let token = jwt_from(
            &serde_json::json!({
                "aud": "https://another-resource-server.com",
            }),
            Some(DEFAULT_KID.to_owned()),
        );

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::ValidationFailed {
                reason: ErrorKind::InvalidAudience
            }
        );
    }

    #[tokio::test]
    async fn invalid_exp() {
        let validator = create_validator(ClaimsValidationSpec::new().exp(true)).await;
        let token = jwt_from(
            &serde_json::json!({
                "exp": unix_epoch_sec_from_now(-(60 * 2))
            }),
            Some(DEFAULT_KID.to_owned()),
        );

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::ValidationFailed {
                reason: ErrorKind::ExpiredSignature
            }
        );
    }

    #[tokio::test]
    async fn missing_iss() {
        let validator = create_validator(ClaimsValidationSpec::new().iss("iss")).await;
        let token = jwt_from(&serde_json::json!({}), Some(DEFAULT_KID.to_owned()));

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::ValidationFailed {
                reason: ErrorKind::MissingRequiredClaim("iss".to_owned())
            }
        );
    }

    #[tokio::test]
    async fn invalid_iss() {
        let validator =
            create_validator(ClaimsValidationSpec::new().iss("https://some-auth-server.com")).await;
        let token = jwt_from(
            &serde_json::json!({
                "iss": "https://another-auth-server.com",
            }),
            Some(DEFAULT_KID.to_owned()),
        );

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            AuthError::ValidationFailed {
                reason: ErrorKind::InvalidIssuer
            }
        );
    }

    async fn create_validator(
        claims_validation: ClaimsValidationSpec,
    ) -> Box<dyn JwtValidator<Claims>> {
        let validator = OnlyJwtValidator::new(claims_validation);
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "RSA",
            "use_": "sig",
            "alg": "RS256",
            "kid": DEFAULT_KID.to_owned(),
            "n": CUSTOM_ENGINE.encode(PUBLIC_KEY.n().to_bytes_be()),
            "e": CUSTOM_ENGINE.encode(PUBLIC_KEY.e().to_bytes_be())
        }))
        .unwrap();
        validator.receive_jwks(JwkSet { keys: vec![jwk] }).await;
        Box::new(validator)
    }

    fn jwt_from(claims: &Value, kid: Option<String>) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = kid;
        encode(&header, claims, &ENCODING_KEY).unwrap()
    }

    fn unix_epoch_sec_from_now(sec: i64) -> u64 {
        (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + sec) as u64
    }
}
