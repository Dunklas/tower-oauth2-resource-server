use std::{collections::HashSet, error::Error};

use reqwest::Client;
use serde::Deserialize;
use url::Url;

#[cfg(test)]
use mockall::automock;

use crate::error::StartupError;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct OidcConfig {
    pub jwks_uri: Url,
    pub issuer: String,
    pub claims_supported: Option<Vec<String>>,
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) struct OidcDiscovery {}

#[cfg_attr(test, automock)]
impl OidcDiscovery {
    #[cfg_attr(test, allow(dead_code))]
    pub async fn discover(
        issuer: &str,
        http_client: Client,
    ) -> Result<OidcConfig, Box<dyn Error>> {
        let issuer_url = Url::parse(issuer)?;
        let paths = get_paths(&issuer_url)?;
        for path in paths {
            if let Ok(response) = http_client.get(path).send().await
                && let Ok(oidc_config) = response.json::<OidcConfig>().await
            {
                if oidc_config.issuer != issuer {
                    return Err(format!(
                        "OIDC issuer mismatch: expected {}, got {}",
                        issuer, oidc_config.issuer
                    )
                    .into());
                }
                return Ok(oidc_config);
            }
        }
        Err("Failed to fetch OIDC configuration".into())
    }
}

fn get_paths(issuer_url: &Url) -> Result<HashSet<Url>, Box<dyn Error>> {
    let path_err =
        || StartupError::InvalidParameter(format!("Could not parse issuer: {}", issuer_url));
    let build_url = |base: &Url, segments: &[&str]| -> Result<Url, Box<dyn Error>> {
        let mut url = base.clone();
        url.path_segments_mut()
            .map_err(|_| path_err())?
            .clear()
            .extend(segments);
        Ok(url)
    };

    let base_segments: Vec<_> = issuer_url
        .path_segments()
        .ok_or(path_err())?
        .filter(|p| !p.is_empty())
        .collect();

    let paths = vec![
        {
            let mut segments = base_segments.clone();
            segments.extend(&[".well-known", "openid-configuration"]);
            build_url(issuer_url, &segments)
        },
        {
            let mut segments = vec![".well-known", "openid-configuration"];
            segments.extend(base_segments.clone());
            build_url(issuer_url, &segments)
        },
        {
            let mut segments = vec![".well-known", "oauth-authorization-server"];
            segments.extend(base_segments.clone());
            build_url(issuer_url, &segments)
        },
    ];

    paths.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use reqwest::Client;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::{OidcDiscovery, get_paths};

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
            .collect::<HashSet<_>>();
        assert_eq!(paths.len(), 3);
        assert!(
            paths.contains(
                "https://authorization-server.com/issuer/.well-known/openid-configuration"
            )
        );
        assert!(
            paths.contains(
                "https://authorization-server.com/.well-known/openid-configuration/issuer"
            )
        );
        assert!(paths.contains(
            "https://authorization-server.com/.well-known/oauth-authorization-server/issuer"
        ));
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
            .collect::<HashSet<_>>();

        assert!(
            paths.contains(
                "https://authorization-server.com/issuer/.well-known/openid-configuration"
            )
        );
        assert!(
            paths.contains(
                "https://authorization-server.com/.well-known/openid-configuration/issuer"
            )
        );
        assert!(paths.contains(
            "https://authorization-server.com/.well-known/oauth-authorization-server/issuer"
        ));
    }

    #[test]
    fn test_get_paths_no_path() {
        let result = get_paths(&"https://authorization-server.com".parse::<Url>().unwrap());
        let paths = result
            .unwrap()
            .into_iter()
            .map(|p| p.to_string())
            .collect::<HashSet<_>>();

        assert_eq!(paths.len(), 2);
        assert!(
            paths.contains("https://authorization-server.com/.well-known/openid-configuration")
        );
        assert!(
            paths.contains(
                "https://authorization-server.com/.well-known/oauth-authorization-server"
            )
        );
    }

    #[test]
    fn test_get_paths_no_path_trailing_slash() {
        let result = get_paths(&"https://authorization-server.com/".parse::<Url>().unwrap());
        let paths = result
            .unwrap()
            .into_iter()
            .map(|p| p.to_string())
            .collect::<HashSet<_>>();

        assert_eq!(paths.len(), 2);
        assert!(
            paths.contains("https://authorization-server.com/.well-known/openid-configuration")
        );
        assert!(
            paths.contains(
                "https://authorization-server.com/.well-known/oauth-authorization-server"
            )
        );
    }

    #[tokio::test]
    async fn test_discover_accepts_matching_issuer() {
        let mock_server = MockServer::start().await;
        let issuer_url = mock_server.uri().parse::<Url>().unwrap();
        mock_discovery_document(&mock_server, issuer_url.as_str()).await;

        let result = OidcDiscovery::discover(issuer_url.as_str(), Client::new()).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().issuer, issuer_url.as_str());
    }

    #[tokio::test]
    async fn test_discover_accepts_root_issuer_without_trailing_slash() {
        let mock_server = MockServer::start().await;
        let issuer = mock_server.uri();
        mock_discovery_document(&mock_server, &issuer).await;

        let result = OidcDiscovery::discover(&issuer, Client::new()).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().issuer, issuer);
    }

    #[tokio::test]
    async fn test_discover_rejects_mismatched_issuer() {
        let mock_server = MockServer::start().await;
        let issuer = mock_server.uri();
        mock_discovery_document(&mock_server, "https://other-issuer.example.com").await;

        let result = OidcDiscovery::discover(&issuer, Client::new()).await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            format!(
                "OIDC issuer mismatch: expected {}, got https://other-issuer.example.com",
                issuer
            )
        );
    }

    async fn mock_discovery_document(mock_server: &MockServer, issuer: &str) {
        for well_known_path in [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
        ] {
            Mock::given(method("GET"))
                .and(path(well_known_path))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "issuer": issuer,
                    "jwks_uri": format!("{}/jwks", mock_server.uri())
                })))
                .mount(mock_server)
                .await;
        }
    }
}
