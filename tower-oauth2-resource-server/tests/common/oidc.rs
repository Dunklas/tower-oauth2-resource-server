use serde::Serialize;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[derive(Serialize)]
pub struct OpenIdConfig {
    pub issuer: String,
    pub jwks_uri: String,
}

pub async fn mock_oidc(mock_server: &MockServer, issuer_path: &str) {
    Mock::given(method("GET"))
        .and(path(format!(
            "{}/.well-known/openid-configuration",
            issuer_path
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(OpenIdConfig {
            issuer: format!("{}{}", &mock_server.uri(), issuer_path),
            jwks_uri: format!("{}{}/jwks", &mock_server.uri(), issuer_path),
        }))
        .mount(mock_server)
        .await;
}
