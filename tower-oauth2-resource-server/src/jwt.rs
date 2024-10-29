use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use http::HeaderMap;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, Jwk, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use log::{info, warn};
use serde::de::DeserializeOwned;
use tokio::sync::RwLock;

use crate::{
    error::{AuthError, JwkError},
    jwks2::JwksConsumer,
    validation::ClaimsValidationSpec,
};

pub trait JwtExtractor {
    fn extract_jwt(&self, headers: &HeaderMap) -> Result<String, AuthError>;
}

pub struct BearerTokenJwtExtractor;

impl JwtExtractor for BearerTokenJwtExtractor {
    fn extract_jwt(&self, headers: &HeaderMap) -> Result<String, AuthError> {
        Ok(headers
            .get(http::header::AUTHORIZATION)
            .ok_or(AuthError::MissingAuthorizationHeader)?
            .to_str()
            .map_err(|_| AuthError::InvalidAuthorizationHeader)?
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidAuthorizationHeader)?
            .to_owned())
    }
}

#[async_trait]
pub trait JwtValidator<Claims> {
    async fn validate(&self, jwt: &str) -> Result<Claims, AuthError>;
}

pub struct OnlyJwtValidator {
    claims_validation: ClaimsValidationSpec,
    decoding_keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
    validations: Arc<RwLock<HashMap<String, Validation>>>,
}

impl OnlyJwtValidator {
    pub fn new(claims_validation: ClaimsValidationSpec) -> Self {
        Self {
            claims_validation,
            decoding_keys: Arc::new(RwLock::new(HashMap::new())),
            validations: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl JwksConsumer for OnlyJwtValidator {
    async fn receive_jwks(&self, jwks: JwkSet) {
        match jwks
            .keys
            .iter()
            .map(to_decoding_key)
            .collect::<Result<HashMap<_, _>, _>>()
        {
            Ok(decoding_keys) => {
                let mut keys = self.decoding_keys.write().await;
                *keys = decoding_keys;
                info!("Successfully updated JWK set");
            }
            Err(e) => {
                warn!("Unable to parse at least one JWK due to: {:?}", e);
            }
        };
    }
}

fn to_decoding_key(jwk: &Jwk) -> Result<(String, DecodingKey), JwkError> {
    let key_id = jwk.common.key_id.as_ref().ok_or(JwkError::MissingKeyId)?;
    let decoding_key = match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa) => {
            DecodingKey::from_rsa_components(&rsa.n, &rsa.e).or(Err(JwkError::DecodingFailed))
        }
        _ => Err(JwkError::UnexpectedAlgorithm),
    }?;
    Ok((key_id.clone(), decoding_key))
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
        let validation = self.jwt_validation(header.alg, &self.claims_validation);
        match decode::<Claims>(token, &decoding_key, &validation) {
            Ok(result) => Ok(result.claims),
            Err(e) => Err(AuthError::ValidationFailed {
                reason: e.into_kind(),
            }),
        }
    }
}

impl OnlyJwtValidator {
    fn jwt_validation(
        &self,
        alg: Algorithm,
        claims_validation: &ClaimsValidationSpec,
    ) -> Validation {
        let mut validation = Validation::new(alg);
        let mut required_claims = Vec::<&'static str>::new();
        if let Some(iss) = &claims_validation.iss {
            required_claims.push("iss");
            validation.set_issuer(&[iss]);
        }
        if claims_validation.exp {
            required_claims.push("exp");
            validation.validate_exp = true;
        }
        if claims_validation.nbf {
            required_claims.push("nbf");
            validation.validate_nbf = true;
        }
        if let Some(aud) = &claims_validation.aud {
            required_claims.push("aud");
            validation.set_audience(aud);
        }
        validation.set_required_spec_claims(&required_claims);
        validation
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, errors::ErrorKind, DecodingKey, EncodingKey, Header};
    use lazy_static::lazy_static;
    use rsa::{
        pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
        RsaPrivateKey, RsaPublicKey,
    };
    use serde::Deserialize;
    use serde_json::Value;
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{error::AuthError, validation::ClaimsValidationSpec};

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
        static ref DECODING_KEY: Arc<DecodingKey> = Arc::new(DecodingKey::from_rsa_der(
            PUBLIC_KEY.to_pkcs1_der().unwrap().as_bytes()
        ));
    }

    #[tokio::test]
    async fn empty_token() {
        let validator = create_validator(ClaimsValidationSpec::new());
        let result = validator.validate("").await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::ParseJwtError);
    }

    #[tokio::test]
    async fn missing_kid() {
        let validator = create_validator(ClaimsValidationSpec::new());
        let token = jwt_from(&serde_json::json!({}), None);

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::ParseJwtError);
    }

    #[tokio::test]
    async fn non_existing_kid() {
        let validator = create_validator(ClaimsValidationSpec::new());
        let token = jwt_from(&serde_json::json!({}), Some("another-kid".to_owned()));

        let result = validator.validate(&token).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::InvalidKeyId);
    }

    #[tokio::test]
    async fn invalid_key() {
        let validator = create_validator(ClaimsValidationSpec::new());
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
        let validator = create_validator(ClaimsValidationSpec::new().nbf(true));
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
        let validator = create_validator(ClaimsValidationSpec::new().nbf(true));
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
        let validator = create_validator(ClaimsValidationSpec::new().exp(true));
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
        );
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
        );
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
        let validator = create_validator(ClaimsValidationSpec::new().exp(true));
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
        let validator = create_validator(ClaimsValidationSpec::new().iss("iss"));
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
            create_validator(ClaimsValidationSpec::new().iss("https://some-auth-server.com"));
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

    fn create_validator(claims_validation: ClaimsValidationSpec) -> Box<dyn JwtValidator<Claims>> {
        let validator = OnlyJwtValidator::new(claims_validation);
        // No idea how to mock Jwks
        // validator.receive_jwks();
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
