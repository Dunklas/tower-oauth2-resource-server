use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use common::{jwt_from, mock_jwks, mock_oidc_config, rsa_key_pair};
use http::{header::AUTHORIZATION, HeaderName, Request, Response, StatusCode};
use http_body_util::Full;
use tokio::time::sleep;
use tower::{BoxError, Service, ServiceBuilder, ServiceExt};

use tower_oauth2_resource_server::{
    claims::DefaultClaims, layer::OAuth2ResourceServerLayer, server::OAuth2ResourceServer,
    tenant::TenantConfiguration,
};
use wiremock::MockServer;

mod common;

#[tokio::test]
async fn unauthorized_on_missing_authorization() {
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "").await;
    let mut service = ServiceBuilder::new()
        .layer(default_auth_layer(&mock_server, &Vec::<String>::new()).await)
        .service_fn(echo);

    let request = request_with_headers(Vec::new());

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get("WWW-Authenticate")
            .map(|v| v.to_str().unwrap()),
        Some("Bearer")
    );
}

#[tokio::test]
async fn unauthorized_on_invalid_authorization() {
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "").await;
    let mut service = ServiceBuilder::new()
        .layer(default_auth_layer(&mock_server, &Vec::<String>::new()).await)
        .service_fn(echo);

    let request = request_with_headers(vec![(AUTHORIZATION, "NotAJWT")]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get("WWW-Authenticate")
            .map(|v| v.to_str().unwrap()),
        Some("Bearer")
    );
}

#[tokio::test]
async fn unauthorized_on_token_validation_failure() {
    let (private_key, public_key) = rsa_key_pair();
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "https://auth-server.com").await;
    mock_jwks(&mock_server, [("good_key".to_owned(), public_key)].to_vec()).await;
    let mut service = ServiceBuilder::new()
        .layer(default_auth_layer(&mock_server, &["https://some-resource-server.com"]).await)
        .service_fn(echo);

    let token = jwt_from(
        &private_key,
        "good_key",
        serde_json::json!({
            "iss": "https://auth-server.com",
            "sub": "Some dude",
            "aud": "https://some-resource-server.com",
            "nbf": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - (10 * 60),
            "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - (2 * 60)
        }),
    );
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ok() {
    let (private_key, public_key) = rsa_key_pair();
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "https://auth-server.com").await;
    mock_jwks(&mock_server, [("good_key".to_owned(), public_key)].to_vec()).await;
    let mut service = ServiceBuilder::new()
        .layer(default_auth_layer(&mock_server, &["https://some-resource-server.com"]).await)
        .service_fn(echo);
    // Needed for initial jwks fetch
    sleep(Duration::from_millis(100)).await;

    let token = jwt_from(
        &private_key,
        "good_key",
        serde_json::json!({
            "iss": mock_server.uri(),
            "sub": "Some dude",
            "aud": vec!["https://some-resource-server.com"],
            "nbf": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 10,
            "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10
        }),
    );
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

async fn default_auth_layer(
    mock_server: &MockServer,
    audiences: &[impl ToString],
) -> OAuth2ResourceServerLayer<DefaultClaims> {
    <OAuth2ResourceServer>::builder()
        .add_tenant(
            TenantConfiguration::builder(mock_server.uri())
                .audiences(audiences)
                .build()
                .await
                .unwrap(),
        )
        .build()
        .await
        .expect("Failed to build OAuth2ResourceServer")
        .into_layer()
}

async fn echo(req: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>, BoxError> {
    let b = req.into_body();
    let mut response = Response::new(b);
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}

fn request_with_headers(headers: Vec<(HeaderName, &str)>) -> Request<Full<Bytes>> {
    let mut request = Request::get("/");
    let request_headers = request.headers_mut().unwrap();
    headers.into_iter().for_each(|(name, value)| {
        request_headers.insert(name, value.parse().unwrap());
    });
    request.body(Full::<Bytes>::default()).unwrap()
}
