use std::fmt::Display;

#[derive(Clone, Debug, Default)]
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
