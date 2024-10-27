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
    let build_url = |base: &Url, segments: &[&str]| -> Result<Url, Box<dyn Error>> {
        let mut url = base.clone();
        url.path_segments_mut()
            .map_err(|_| {
                StartupError::InvalidParameter(format!("Could not parse issuer: {}", base))
            })?
            .clear()
            .extend(segments);
        Ok(url)
    };

    let base_segments: Vec<_> = issuer_uri
        .path_segments()
        .ok_or(StartupError::InvalidParameter(format!(
            "Could not parse issuer: {}",
            issuer_uri
        )))?
        .filter(|p| !p.is_empty())
        .collect();

    let paths = vec![
        {
            let mut first = issuer_uri.clone();
            first
                .path_segments_mut()
                .map_err(|_| {
                    StartupError::InvalidParameter(format!(
                        "Could not parse issuer: {}",
                        issuer_uri
                    ))
                })?
                .pop_if_empty()
                .extend(&[".well-known", "openid-configuration"]);
            Ok(first)
        },
        {
            let mut segments = vec![".well-known", "openid-configuration"];
            segments.extend(base_segments.clone());
            build_url(issuer_uri, &segments)
        },
        {
            let mut segments = vec![".well-known", "oauth-authorization-server"];
            segments.extend(base_segments.clone());
            build_url(issuer_uri, &segments)
        },
    ];

    paths.into_iter().collect()
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
        let paths = result
            .unwrap()
            .into_iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>();

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
        let paths = result
            .unwrap()
            .into_iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>();

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
        let result = get_paths(&"https://authorization-server.com".parse::<Url>().unwrap());
        let paths = result
            .unwrap()
            .into_iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>();

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
        let result = get_paths(&"https://authorization-server.com/".parse::<Url>().unwrap());
        let paths = result
            .unwrap()
            .into_iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>();

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
