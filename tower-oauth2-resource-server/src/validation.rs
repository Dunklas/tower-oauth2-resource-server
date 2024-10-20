use std::fmt::Display;

use crate::oidc::OidcConfig;

#[derive(Debug, Default)]
pub struct ClaimsValidationSpec {
    pub iss: Option<String>,
    pub exp: bool,
    pub nbf: bool,
    pub aud: Option<Vec<String>>,
}

impl ClaimsValidationSpec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recommended(issuer: &str, audiences: Vec<String>) -> Self {
        Self::new().exp(true).nbf(true).iss(issuer).aud(audiences)
    }

    pub(crate) fn from_oidc_config(oidc_config: &OidcConfig, audiences: &[String]) -> Option<Self> {
        match &oidc_config.claims_supported {
            Some(claims_supported) => {
                let mut spec = ClaimsValidationSpec::new().exp(true);
                if claims_supported.contains(&"iss".to_owned()) {
                    spec = spec.iss(&oidc_config.issuer);
                }
                if claims_supported.contains(&"nbf".to_owned()) {
                    spec = spec.nbf(true);
                }
                if claims_supported.contains(&"aud".to_owned()) {
                    spec = spec.aud(audiences.iter().map(|a| a.to_string()).collect());
                }
                Some(spec)
            }
            None => None,
        }
    }

    pub fn iss(mut self, issuer: &str) -> Self {
        self.iss = Some(issuer.to_owned());
        self
    }

    pub fn exp(mut self, validate: bool) -> Self {
        self.exp = validate;
        self
    }

    pub fn nbf(mut self, validate: bool) -> Self {
        self.nbf = validate;
        self
    }

    pub fn aud(mut self, audiences: Vec<String>) -> Self {
        self.aud = Some(audiences);
        self
    }
}

impl Display for ClaimsValidationSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
