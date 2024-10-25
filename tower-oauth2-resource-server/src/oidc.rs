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
    pub async fn from_issuer_uri(issuer_uri: &str) -> Result<Self, Box<dyn Error>> {
        let paths = vec![
            "/.well-known/openid-configuration",
            "/.well-known/openid-configuration/issuer",
            "/.well-known/oauth-authorization-server/issuer",
        ];
        for path in paths {
            if let Ok(response) = reqwest::get(format!("{}{}", issuer_uri, path)).await {
                if let Ok(oidc_config) = response.json().await {
                    return Ok(OidcConfigProvider {
                        config: oidc_config,
                    });
                }
            }
        }
        Err("Failed to fetch OIDC configuration".into())
    }
}
