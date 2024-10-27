use std::error::Error;

use serde::Deserialize;
use url::Url;

#[cfg(test)]
use mockall::automock;

use crate::error::StartupError;

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
        let paths = get_paths(issuer_uri)?;
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

fn get_paths(issuer_uri: &Url) -> Result<Vec<Url>, Box<dyn Error>> {
    let mut first = issuer_uri.clone();
    first.path_segments_mut()
        .map_err(|_| {
            StartupError::InvalidParameter(format!("Could not parse issuer: {}", issuer_uri))
        })?
        .pop_if_empty()
        .extend(&[".well-known", "openid-configuration"]);

    let mut second = issuer_uri.clone();
    let mut x = vec![".well-known", "openid-configuration"];
    x.extend(issuer_uri.path_segments().unwrap().filter(|p| *p != ""));
    second.path_segments_mut()
        .map_err(|_| {
            StartupError::InvalidParameter(format!("Could not parse issuer: {}", issuer_uri))
        })?
        .clear()
        .extend(x);

    let mut third = issuer_uri.clone();
    let mut x = vec![".well-known", "oauth-authorization-server"];
    x.extend(issuer_uri.path_segments().unwrap().filter(|p| *p != ""));
    third.path_segments_mut()
        .map_err(|_| {
            StartupError::InvalidParameter(format!("Could not parse issuer: {}", issuer_uri))
        })?
        .clear()
        .extend(x);

    Ok(vec![
        &first.to_string(),
        &second.to_string(),
        &third.to_string(),
    ]
    .into_iter()
    .map(|path| path.parse::<Url>().unwrap())
    .collect())
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::get_paths;

    #[test]
    fn test_get_paths_with_path() {
        let result = get_paths(
            &"https://authorization-server.com/issuer"
                .parse::<Url>()
                .unwrap(),
        );
        let paths = result.unwrap().into_iter().map(|p| p.to_string()).collect::<Vec<_>>();

        assert_eq!(
            paths,
            vec![
                "https://authorization-server.com/issuer/.well-known/openid-configuration",
                "https://authorization-server.com/.well-known/openid-configuration/issuer",
                "https://authorization-server.com/.well-known/oauth-authorization-server/issuer"
            ]
        )
    }

    #[test]
    fn test_get_paths_with_path_trailing_slash() {
        let result = get_paths(
            &"https://authorization-server.com/issuer/"
                .parse::<Url>()
                .unwrap(),
        );
        let paths = result.unwrap().into_iter().map(|p| p.to_string()).collect::<Vec<_>>();

        assert_eq!(
            paths,
            vec![
                "https://authorization-server.com/issuer/.well-known/openid-configuration",
                "https://authorization-server.com/.well-known/openid-configuration/issuer",
                "https://authorization-server.com/.well-known/oauth-authorization-server/issuer",
            ]
        )
    }

    #[test]
    fn test_get_paths_no_path() {
        let result = get_paths(
            &"https://authorization-server.com"
                .parse::<Url>()
                .unwrap(),
        );
        let paths = result.unwrap().into_iter().map(|p| p.to_string()).collect::<Vec<_>>();

        assert_eq!(
            paths,
            vec![
                "https://authorization-server.com/.well-known/openid-configuration",
                "https://authorization-server.com/.well-known/openid-configuration",
                "https://authorization-server.com/.well-known/oauth-authorization-server",
            ]
        )
    }

    #[test]
    fn test_get_paths_no_path_trailing_slash() {
        let result = get_paths(
            &"https://authorization-server.com/"
                .parse::<Url>()
                .unwrap(),
        );
        let paths = result.unwrap().into_iter().map(|p| p.to_string()).collect::<Vec<_>>();

        assert_eq!(
            paths,
            vec![
                "https://authorization-server.com/.well-known/openid-configuration",
                "https://authorization-server.com/.well-known/openid-configuration",
                "https://authorization-server.com/.well-known/oauth-authorization-server",
            ]
        )
    }
}
