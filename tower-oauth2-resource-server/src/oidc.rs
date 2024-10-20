use std::error::Error;

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct OidcConfig {
    pub issuer: String,
    pub jwks_uri: String,
    pub claims_supported: Option<Vec<String>>,
}

pub(crate) struct OidcConfigProvider {
    pub config: OidcConfig,
}

impl OidcConfigProvider {
    pub fn from_issuer_uri(issuer_uri: &str) -> Result<Self, Box<dyn Error>> {
        Ok(OidcConfigProvider {
            config: ureq::get(&format!("{}/.well-known/openid-configuration", issuer_uri))
                .call()?
                .into_json::<OidcConfig>()?,
        })
    }
}
