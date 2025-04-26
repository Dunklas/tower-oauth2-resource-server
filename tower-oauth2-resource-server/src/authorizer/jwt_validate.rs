use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{Jwk, JwkSet, KeyAlgorithm},
    Algorithm, DecodingKey, Validation,
};
use log::{info, warn};
use serde::de::DeserializeOwned;
use std::sync::RwLock;

use crate::{
    error::{AuthError, JwkError},
    jwt_unverified::UnverifiedJwt,
    validation::ClaimsValidationSpec,
};

use super::jwks::JwksConsumer;

pub trait JwtValidator<Claims> {
    fn validate(&self, jwt: &UnverifiedJwt) -> Result<Claims, AuthError>;
}

pub struct OnlyJwtValidator {
    claims_validation: ClaimsValidationSpec,
    decoding_keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
    validations: Arc<RwLock<HashMap<Algorithm, Validation>>>,
}

impl<Claims> JwtValidator<Claims> for OnlyJwtValidator
where
    Claims: DeserializeOwned,
{
    fn validate(&self, token: &UnverifiedJwt) -> Result<Claims, AuthError> {
        let header = decode_header(token.as_str()).or(Err(AuthError::ParseJwtError))?;
        let key_id = header.kid.ok_or(AuthError::ParseJwtError)?;

        let decoding_keys = self.decoding_keys.read().unwrap();
        let decoding_key = decoding_keys.get(&key_id).ok_or(AuthError::InvalidKeyId)?;
        let validations = self.validations.read().unwrap();
        let validation = validations
            .get(&header.alg)
            .ok_or(AuthError::UnsupportedAlgorithm(header.alg))?;

        match decode::<Claims>(token.as_str(), decoding_key, validation) {
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
        let mut validations = self.validations.write().unwrap();
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
        } else {
            validation.validate_aud = self.claims_validation.validate_aud;
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
                let mut keys = self.decoding_keys.write().unwrap();
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
    use super::*;
    use jsonwebtoken::{
        encode,
        errors::ErrorKind,
        jwk::{Jwk, JwkSet},
        EncodingKey, Header,
    };
    use lazy_static::lazy_static;
    use serde::Deserialize;
    use serde_json::{json, Value};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{
        authorizer::jwks::JwksConsumer, error::AuthError, validation::ClaimsValidationSpec,
    };

    use super::{JwtValidator, OnlyJwtValidator};

    #[derive(Deserialize, Debug)]
    struct Claims {}

    lazy_static! {
        static ref DEFAULT_KID: String = "test-kid".to_owned();
        static ref TEST_RSA_PRIVATE: &'static str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCgTP9Gu6kc/131
eIVtcugkzAb7vlnXy3jOIHLY8dNkfGQc56ntoV42P7Xc2YhwviiiP7afGsuFZuAD
aIFpav3nAqR/ml5Oxz7lDr4Ha4Jyf3E9JArTxj+M1WG2XLeYA52xPhj2ZAg7+ipq
oTLO63KlkES77Xw2RsZXCQ2Eb2zG9SMVce8ygmzmLAgtoMDYWG4SKggPM7L5mMPy
n3bzJ7a/wJ09aXXE/GgFd3Yoh7dGShxEPEt54GDfAfxr21Dlnt86aJeIAjz+U3nv
Nh/TvzJrO8tSUrMKjWlChHbkxTnV3vOAj8jsfYVvk9kZwKZ+83VSnjU58RDIwsvo
ljKg/bddAgMBAAECggEAToB2kU6simlau7A6c3eOzRpnnxhAikf4UMWeSLTgx7iN
FIS0+I0KhLmdl9qmEURmxNI73l3yZlGTice/fH8reVqXcXAJGD5GBEm8cQjK2MSl
kYIZlU1kaNVEpVhxho3ax2Z4Ng2V5L1l0VNA/Qlb2020A25RYok1b4Ec8ArbM/Ep
ECxHjMjViHlqFLo25AfqxW0Q/TeNyMdYDWn/l6+qw9OI5OYswGwW1xwjL6ElcqnT
tDDC/wqorxv+sRrTTyxQ1mUg1K2vm7wjml2PlVgjv7P28O0LjlDspPFChVZ2xbp0
+ohEiNARBabqVt1gs/aYmoN8SZ9NDneCCzFSL/P4lwKBgQDT9QQXMB2lgEMaEIS/
1z2E1ByL6cN7uiqo4rTDrvnLGL/vBqb3751YV/sJubi6Da1QpAZJQ/ssHNs6T1zh
nImXkSWG+OravA10driJL8wWcKD3bIQOEc6FFrz+t/tiLf6tx5Ok6+vWL89muiWw
xouU/msV0ZXHcIoKonB2a7sYqwKBgQDBnCQYhbb8T7U248Cd6jv0gaJn5VHA9mF7
/Wg0oHgAi/TFGlO/1nktkmHbDE0BH4Y9NM3vOmik5ag4tVGFIQU7MkDx9HKo9GnZ
Tx2OcwpQ5l/02GMO634y2w/zoS1GoGNqWLYVPsK3kyM+LmzAc29fpOBxxomqA1Pw
SRuVBouAFwKBgHpL5z5R3uk9ZnpFibL/SFm54XbBPK/JLRAhLtexwCN1dlk+Z1yr
fwgYS5rC9Fk1xwi+e3oOpYBAbiXo4Ni0b5dqglKskSYAV2sZjURqtcFE3zuj+1X6
5ERaaFY4Ze2ySD6Q5xnDnmIJWAwX3+Nty9/+JF+EfH2E68FTFLzfUCbdAoGBALzB
k9dslegLdesbxLCwqt9Ie6O7SSdNjeEqP6v/Pr+Zs3tunXQMj3vEmS7MIU8VAvUt
RBEV6uvJE2amL+IRPV5nMjYyUo8yKvg4T+KPeeFBmQ/G31yubwz50eV+n/uZZxNJ
hcvUslXzV4rKDDDc2hpvTnreS1y7fdxoCkISbXLlAoGAQ2W04sNMa6sFI/9rAcFv
yviLtRw4G2epS0AtGhPsy3cPX8XIiRbkQXrZSSV9FSlZyC0Fr1IS8qTCF9rJMawm
iiVw58CWKo4qO6HQGC/W5nD3maFnHnnp3mtIgfGsWEyc9tgdhFZuTtHxDPTjm/xU
kTlUuvwRMeoB7RdcxaYHaQo=
-----END PRIVATE KEY-----"#;
        static ref TEST_RSA_MODULUS: &'static str = "oEz_RrupHP9d9XiFbXLoJMwG-75Z18t4ziBy2PHTZHxkHOep7aFeNj-13NmIcL4ooj-2nxrLhWbgA2iBaWr95wKkf5peTsc-5Q6-B2uCcn9xPSQK08Y_jNVhtly3mAOdsT4Y9mQIO_oqaqEyzutypZBEu-18NkbGVwkNhG9sxvUjFXHvMoJs5iwILaDA2FhuEioIDzOy-ZjD8p928ye2v8CdPWl1xPxoBXd2KIe3RkocRDxLeeBg3wH8a9tQ5Z7fOmiXiAI8_lN57zYf078yazvLUlKzCo1pQoR25MU51d7zgI_I7H2Fb5PZGcCmfvN1Up41OfEQyMLL6JYyoP23XQ";
        static ref TEST_RSA_EXPONENT: &'static str = "AQAB";
        static ref ENCODING_KEY: EncodingKey =
            EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE.as_bytes()).unwrap();
    }

    #[tokio::test]
    async fn empty_token() {
        let validator = create_validator(ClaimsValidationSpec::new()).await;
        let result = validator.validate(&UnverifiedJwt::new(""));

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::ParseJwtError);
    }

    #[tokio::test]
    async fn missing_kid() {
        let validator = create_validator(ClaimsValidationSpec::new()).await;
        let token = jwt_from(&serde_json::json!({}), None);

        let result = validator.validate(&UnverifiedJwt::new(token));

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::ParseJwtError);
    }

    #[tokio::test]
    async fn non_existing_kid() {
        let validator = create_validator(ClaimsValidationSpec::new()).await;
        let token = jwt_from(&serde_json::json!({}), Some("another-kid".to_owned()));

        let result = validator.validate(&UnverifiedJwt::new(token));

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AuthError::InvalidKeyId);
    }

    #[tokio::test]
    async fn invalid_key() {
        let validator = create_validator(ClaimsValidationSpec::new()).await;
        let another_rsa_private_key = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDcjka/kUq76+c3
J5XklEl2lEgjV5jsbTY39tnlYYH6d5/LZG3i90lKBLi+xuyLBPQzMIS5GigOMev1
+JNmcsry5m5Okd65uypi86RyOIGZ/sFOyUElkrGHUoBTZqD8xDQJu8q65vOyz8XK
zs5+bALmLp3v0/QapXMHU7MjUxyTY+OJEKKQE5buaHkrrkNwlDgkiWZNrD3jGpbe
NMvplhx0/+PM07RngrtHnv63c0jdS0lXQBTvmtOb6SxKBz9kvXx3KDkROgIWoQJV
eXelnA2ZM1zwVWi7bbKHbMtI6S0ngPlugVYxETgN95YObdqNfRyF39uIYH3/KGXR
+ZAivkQDAgMBAAECggEAGCIyB/c61r+e9XA4R3fvEUceHPk9AK3d72zBoLG1OnYe
1ETWfgMyD/kz9Ugot6OLTGikNT7xSsWtUfppDUjv/86Kxmp8FRWvsyksLDAWWlvq
b20NMF0nXi0ptovgf21sBklNYHsyB7W9fmN3wT9KEpbfmE+4gmE/6iQp/L+055mj
6kLVxiNWHxLRg+L39imtxrnVFgYFYCoPZWb8CkdXFH6yFe9nnjKUGTzMdJh55Jdg
Z6smOmd9Hl9uAJFjFg1EAXHC0Xo+BBEGVITE8ExXVY4oDtttyzYEJl1hgsEOSHTi
3yHOQDnJtcrtS+Q3TTHgsAFjOvF7XhFFJBJdHEOLmQKBgQD9N9eApP6yM4o2f9xd
95C1xbmMUlghnh1KXrOBFg2VnC8NK4z39oxhp9dntBcvcvTcdfr8U2l/GJbKGFZu
cO6IQgpfbSIm/jcqffsG6R7W1U7kS7Hx5dAZKZwWCsbYhEIQij3nMC/9uC/w0Nj+
x+mZtvTfpOJ7cyAlVeVyhI+TWwKBgQDe+pLuTJgYF2gnmTKgfhb8Jz5JHcqpsED+
MdjhcmDMoatpXTMYFOaVpt0Pxeg/AOX7J5+w1SdhnojEzi3YQsdguruJ+ij/T/iF
mk2YLL640AlHQPTz24fPY3XiLSawwdtskigNE0l1OpKctYo5r5RcKza3Q6gNPKha
L/OKTa06eQKBgFJj9Q66oNTCyFnrSHyarM84QqNRt7NYixdDsQxzbIAdjYGvhfK4
mfy8a+4mPtUFhn6lNMEdMtpT2dxwBs9wl2xmcJGUJOSjGrgMvb0F5S7pwP2vU3rt
18QYMd1KLGEOx6AyGuo6V6MqZw7oJXLhATUuvoZ2U+rvDqqXREz6rOy5AoGAb9I1
kS/0LlC+uO0JCJdzK2z6vWwlUEfFsDSLUTQs+zIwZhyJHRCOOop93gUf3Ui0DOno
GaQrpbb9W8USFJwYpJfAqQc9PBx8w3OIakI2OzSJEqSuswRq7UQxwAVom8f8JEx/
rV74vcNr9w7LjPZSbo51WB6jzk+XFfNqLPebYfECgYAf5SEOuZgwmdUrF/UGuyFb
YjtcKqsWL5tG7HIxmvRjvjuwEGo2tcCCUKK+9rz+RUBVX+Bd7WJwr+z4L7dHd1tH
y3Hu3pMgFhRj5cqxonKfp5Rtulf0IgvxH7lcfeoQS/qoNrqLbGOgit1yTuKxrGK6
ScHBAP/qVF3+Qfg9iKDMkg==
-----END PRIVATE KEY-----"#;
        let another_encoding_key =
            EncodingKey::from_rsa_pem(another_rsa_private_key.as_bytes()).unwrap();
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(DEFAULT_KID.to_owned());
        let token = encode(&header, &serde_json::json!({}), &another_encoding_key).unwrap();

        let result = validator.validate(&UnverifiedJwt::new(token));

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

        let result = validator.validate(&UnverifiedJwt::new(token));

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

        let result = validator.validate(&UnverifiedJwt::new(token));

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

        let result = validator.validate(&UnverifiedJwt::new(token));

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
                .aud(&["https://some-resource.server.com".to_owned()].to_vec()),
        )
        .await;
        let token = jwt_from(&serde_json::json!({}), Some(DEFAULT_KID.to_owned()));

        let result = validator.validate(&UnverifiedJwt::new(token));

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
                .aud(&["https://some-resource-server.com".to_owned()].to_vec()),
        )
        .await;
        let token = jwt_from(
            &serde_json::json!({
                "aud": "https://another-resource-server.com",
            }),
            Some(DEFAULT_KID.to_owned()),
        );

        let result = validator.validate(&UnverifiedJwt::new(token));

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

        let result = validator.validate(&UnverifiedJwt::new(token));

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

        let result = validator.validate(&UnverifiedJwt::new(token));

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

        let result = validator.validate(&UnverifiedJwt::new(token));

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
            "n": TEST_RSA_MODULUS.to_string(),
            "e": TEST_RSA_EXPONENT.to_string(),
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
