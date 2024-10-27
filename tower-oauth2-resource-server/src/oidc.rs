use std::error::Error;

use serde::Deserialize;
use url::Url;

#[cfg(test)]
use mockall::automock;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct OidcConfig {
    pub jwks_uri: String,
    pub claims_supported: Option<Vec<String>>,
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) struct OidcDiscovery {}

#[cfg_attr(test, automock)]
impl OidcDiscovery {
    #[cfg_attr(test, allow(dead_code))]
    pub async fn discover(issuer_uri: &Url) -> Result<OidcConfig, Box<dyn Error>> {
        let paths = get_paths(issuer_uri);
        for path in paths {
            if let Ok(response) = reqwest::get(path).await {
                if let Ok(oidc_config) = response.json().await {
                    return Ok(oidc_config);
                }
            }
        }
        Err("Failed to fetch OIDC configuration".into())
    }
}

fn get_paths(issuer_uri: &Url) -> Vec<Url> {
    vec![
        ".well-known/openid-configuration",
        ".well-known/openid-configuration/issuer",
        ".well-known/oauth-authorization-server/issuer",
    ]
    .into_iter()
    .map(|path| format!("{}{}", issuer_uri, path).parse::<Url>().unwrap())
    .collect()
}
