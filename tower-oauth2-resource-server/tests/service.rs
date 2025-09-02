use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use common::{jwt_from, mock_jwks, mock_oidc_config, rsa_keys};
use http::{header::AUTHORIZATION, HeaderName, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tower::{BoxError, Service, ServiceBuilder, ServiceExt};

use tower_oauth2_resource_server::{
    auth_resolver::KidAuthorizerResolver, claims::DefaultClaims, error::AuthError,
    error_handler::ErrorHandler, layer::OAuth2ResourceServerLayer, server::OAuth2ResourceServer,
    tenant::TenantConfiguration, validation::ClaimsValidationSpec,
};
use wiremock::MockServer;

mod common;

// Needed for initial jwks fetch
const START_UP_DELAY_MS: Duration = Duration::from_millis(500);

#[tokio::test]
async fn unauthorized_on_missing_authorization() {
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "").await;
    let mut service = ServiceBuilder::new()
        .layer(default_auth_layer(&mock_server, &Vec::<String>::new()).await)
        .service_fn(echo);
    sleep(START_UP_DELAY_MS).await;

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
    sleep(START_UP_DELAY_MS).await;

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
    let [rsa_key, ..] = rsa_keys();
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "https://auth-server.com").await;
    mock_jwks(&mock_server, &[("good_key".to_owned(), &rsa_key)]).await;
    let mut service = ServiceBuilder::new()
        .layer(default_auth_layer(&mock_server, &["https://some-resource-server.com"]).await)
        .service_fn(echo);
    sleep(START_UP_DELAY_MS).await;

    let token = jwt_from(
        &rsa_key,
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
    let [rsa_key, ..] = rsa_keys();
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "https://auth-server.com").await;
    mock_jwks(&mock_server, &[("good_key".to_owned(), &rsa_key)]).await;
    let mut service = ServiceBuilder::new()
        .layer(default_auth_layer(&mock_server, &["https://some-resource-server.com"]).await)
        .service_fn(echo);
    sleep(START_UP_DELAY_MS).await;

    let token = jwt_from(
        &rsa_key,
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

#[tokio::test]
async fn ok_static() {
    let [rsa_key, ..] = rsa_keys();
    let jwks = common::jwks(&[("good_key".to_string(), &rsa_key)]);
    let layer = <OAuth2ResourceServer>::builder()
        .add_tenant(
            TenantConfiguration::static_builder(serde_json::to_string(&jwks).unwrap())
                .audiences(&["https://some-resource-server.com"])
                .build()
                .unwrap(),
        )
        .build()
        .await
        .expect("Failed to build OAuth2ResourceServer")
        .into_layer();

    let mut service = ServiceBuilder::new().layer(layer).service_fn(echo);
    sleep(START_UP_DELAY_MS).await;

    let token = jwt_from(
        &rsa_key,
        "good_key",
        serde_json::json!({
            "sub": "Some dude",
            "aud": ["https://some-resource-server.com"],
            "nbf": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 10,
            "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10
        }),
    );
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ok_mixed() {
    let [static_key, oidc_key] = rsa_keys();
    let jwks = common::jwks(&[("good_static".to_string(), &static_key)]);

    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "https://auth-server.com").await;
    mock_jwks(&mock_server, &[("good_oidc".to_owned(), &oidc_key)]).await;

    let layer = <OAuth2ResourceServer>::builder()
        .add_tenant(
            TenantConfiguration::static_builder(serde_json::to_string(&jwks).unwrap())
                .audiences(&["https://some-resource-server.com"])
                .build()
                .unwrap(),
        )
        .add_tenant(
            TenantConfiguration::builder(mock_server.uri())
                .audiences(&["https://some-resource-server.com"])
                .build()
                .await
                .unwrap(),
        )
        .build()
        .await
        .expect("Failed to build OAuth2ResourceServer")
        .into_layer();

    let mut service = ServiceBuilder::new().layer(layer).service_fn(echo);
    sleep(START_UP_DELAY_MS).await;

    let token = jwt_from(
        &oidc_key,
        "good_oidc",
        serde_json::json!({
            "iss": mock_server.uri(),
            "sub": "Some dude",
            "aud": ["https://some-resource-server.com"],
            "nbf": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 10,
            "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10
        }),
    );
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    sleep(START_UP_DELAY_MS).await;
    assert_eq!(response.status(), StatusCode::OK, "OIDC request failed");

    let token = jwt_from(
        &static_key,
        "good_static",
        serde_json::json!({
            "iss": "static",
            "aud": ["https://some-resource-server.com"],
            "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10
        }),
    );
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Static request failed");
}

#[tokio::test]
async fn ok_mixed_kid() {
    let [static_key, oidc_key] = rsa_keys();
    let jwks = common::jwks(&[("good_static".to_string(), &static_key)]);

    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "https://auth-server.com").await;
    mock_jwks(&mock_server, &[("good_oidc".to_owned(), &oidc_key)]).await;

    let layer = <OAuth2ResourceServer>::builder()
        .add_tenant(
            TenantConfiguration::static_builder(serde_json::to_string(&jwks).unwrap())
                .claims_validation(ClaimsValidationSpec::new().exp(true))
                .build()
                .unwrap(),
        )
        .add_tenant(
            TenantConfiguration::builder(mock_server.uri())
                .audiences(&["https://some-resource-server.com"])
                .claims_validation(
                    ClaimsValidationSpec::new()
                        .aud(&vec!["https://some-resource-server.com".to_string()])
                        .exp(true),
                )
                .build()
                .await
                .unwrap(),
        )
        .auth_resolver(Arc::new(KidAuthorizerResolver {}))
        .build()
        .await
        .expect("Failed to build OAuth2ResourceServer")
        .into_layer();

    let mut service = ServiceBuilder::new().layer(layer).service_fn(echo);
    sleep(START_UP_DELAY_MS).await;

    let token = jwt_from(
        &oidc_key,
        "good_oidc",
        serde_json::json!({
            "sub": "Some dude",
            "aud": ["https://some-resource-server.com"],
            "nbf": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 10,
            "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10
        }),
    );
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    sleep(START_UP_DELAY_MS).await;
    assert_eq!(response.status(), StatusCode::OK, "OIDC request failed");

    let token = jwt_from(
        &static_key,
        "good_static",
        serde_json::json!({
            "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10
        }),
    );
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Static request failed");
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CustomJwtClaims {
    sub: String,
    role: String,
}

#[tokio::test]
async fn propagates_jwt_claims() {
    let [rsa_key, ..] = rsa_keys();
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "https://auth-server.com").await;
    mock_jwks(&mock_server, &[("good_key".to_owned(), &rsa_key)]).await;

    let auth_layer = OAuth2ResourceServer::<CustomJwtClaims>::builder()
        .add_tenant(
            TenantConfiguration::builder(mock_server.uri())
                .audiences(&["https://some-resource-server.com"])
                .build()
                .await
                .unwrap(),
        )
        .build()
        .await
        .expect("Failed to build OAuth2ResourceServer")
        .into_layer();

    let mut service = ServiceBuilder::new()
        .layer(auth_layer)
        .service_fn(echo_claims::<CustomJwtClaims>);
    sleep(START_UP_DELAY_MS).await;

    let token = jwt_from(
        &rsa_key,
        "good_key",
        serde_json::json!({
            "iss": mock_server.uri(),
            "sub": "Some dude",
            "aud": vec!["https://some-resource-server.com"],
            "nbf": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 10,
            "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10,
            "role": "superuser"
        }),
    );
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body();
    assert_eq!(body, "{\"sub\":\"Some dude\",\"role\":\"superuser\"}");
}

struct TeapotErrorHandler {}

impl ErrorHandler<Full<Bytes>> for TeapotErrorHandler {
    fn handle_error(&self, _: &AuthError) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::IM_A_TEAPOT)
            .body(Full::new("With a body".into()))
            .unwrap()
    }
}

#[tokio::test]
async fn custom_error_handler() {
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "").await;
    let mut service = ServiceBuilder::new()
        .layer(
            <OAuth2ResourceServer>::builder()
                .add_tenant(
                    TenantConfiguration::builder(mock_server.uri())
                        .audiences(&Vec::<String>::new())
                        .build()
                        .await
                        .unwrap(),
                )
                .build()
                .await
                .expect("Failed to build OAuth2ResourceServer")
                .into_layer_with_error_handler(Arc::new(TeapotErrorHandler {})),
        )
        .service_fn(echo);
    sleep(START_UP_DELAY_MS).await;

    let request = request_with_headers(Vec::new());

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    let body = response.into_body().collect().await.unwrap();
    assert_eq!(
        String::from_utf8(body.to_bytes().into()).unwrap(),
        "With a body".to_owned()
    );
}

async fn default_auth_layer<T>(
    mock_server: &MockServer,
    audiences: &[impl ToString],
) -> OAuth2ResourceServerLayer<T, DefaultClaims>
where
    T: Default,
{
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

async fn echo_claims<T>(req: Request<Full<Bytes>>) -> Result<Response<String>, BoxError>
where
    T: Clone + Send + Sync + Serialize + 'static,
{
    let claims = req
        .extensions()
        .get::<T>()
        .expect("Claims extension not found");

    let json = serde_json::to_string(claims).unwrap();
    let mut response = Response::new(json);
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
