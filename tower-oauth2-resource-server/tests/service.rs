use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use common::{jwt_from, rsa_keys};
use http::{header::AUTHORIZATION, HeaderName, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tower::{BoxError, Service, ServiceBuilder, ServiceExt};

use tower_oauth2_resource_server::{
    auth_resolver::KidAuthorizerResolver, error::AuthError, error_handler::ErrorHandler,
    server::OAuth2ResourceServer, validation::ClaimsValidationSpec,
};

use crate::common::context::{TenantInput, TestContext, START_UP_DELAY_MS};

mod common;

#[tokio::test]
async fn unauthorized_on_missing_authorization() {
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(
            "/auth-server",
            vec![],
            ("good_key", &rsa_keys()[0]),
            None,
        ))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(ctx.create_service().await.into_layer())
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
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(
            "/auth-server",
            vec![],
            ("good_key", &rsa_keys()[0]),
            None,
        ))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(ctx.create_service().await.into_layer())
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
    let [rsa_key, ..] = rsa_keys();
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(
            "/auth-server",
            vec![],
            ("good_key", &rsa_key),
            None,
        ))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(ctx.create_service().await.into_layer())
        .service_fn(echo);

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
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(
            "/auth-server",
            vec!["https://some-resource-server.com"],
            ("good_key", &rsa_key),
            None,
        ))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(ctx.create_service().await.into_layer())
        .service_fn(echo);

    let token = jwt_from(
        &rsa_key,
        "good_key",
        serde_json::json!({
            "iss": format!("{}{}", &ctx.mock_server_uri(), "/auth-server"),
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
    let jwks = common::jwks(&[("good_key", &rsa_key)]);
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Static(
            &jwks,
            vec!["https://some-resource-server.com"],
            None,
        ))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(ctx.create_service().await.into_layer())
        .service_fn(echo);

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
    let jwks = common::jwks(&[("good_static", &static_key)]);

    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Static(
            &jwks,
            vec!["https://some-resource-server.com"],
            None,
        ))
        .with_tenant_configuration(TenantInput::Oidc(
            "/auth-server",
            vec!["https://some-resource-server.com"],
            ("good_oidc", &oidc_key),
            None,
        ))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(ctx.create_service().await.into_layer())
        .service_fn(echo);

    let token = jwt_from(
        &oidc_key,
        "good_oidc",
        serde_json::json!({
            "iss": format!("{}{}", ctx.mock_server_uri(), "/auth-server"),
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
    let jwks = common::jwks(&[("good_static", &static_key)]);

    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Static(
            &jwks,
            vec!["https://some-resource-server.com"],
            Some(ClaimsValidationSpec::new().exp(true)),
        ))
        .with_tenant_configuration(TenantInput::Oidc(
            "/auth-server",
            vec!["https://some-resource-server.com"],
            ("good_oidc", &oidc_key),
            Some(
                ClaimsValidationSpec::new()
                    .aud(&vec!["https://some-resource-server.com".to_string()])
                    .exp(true),
            ),
        ))
        .build()
        .await;

    let mut service = ServiceBuilder::new()
        .layer(
            <OAuth2ResourceServer>::builder()
                .add_tenants(ctx.tenant_configurations().clone())
                .auth_resolver(Arc::new(KidAuthorizerResolver {}))
                .build()
                .await
                .unwrap()
                .into_layer(),
        )
        .service_fn(echo);
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
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(
            "",
            vec!["https://some-resource-server.com"],
            ("good_key", &rsa_key),
            None,
        ))
        .build()
        .await;

    let mut service = ServiceBuilder::new()
        .layer(
            OAuth2ResourceServer::<CustomJwtClaims>::builder()
                .add_tenants(ctx.tenant_configurations().clone())
                .build()
                .await
                .unwrap()
                .into_layer(),
        )
        .service_fn(echo_claims::<CustomJwtClaims>);
    sleep(START_UP_DELAY_MS).await;

    let token = jwt_from(
        &rsa_key,
        "good_key",
        serde_json::json!({
            "iss": ctx.mock_server_uri(),
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
    fn map_error(&self, _: AuthError) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::IM_A_TEAPOT)
            .body(Full::new("With a body".into()))
            .unwrap()
    }
}

#[tokio::test]
async fn custom_error_handler() {
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(
            "",
            vec![],
            ("default_key", &rsa_keys()[0]),
            None,
        ))
        .build()
        .await;

    let mut service = ServiceBuilder::new()
        .layer(
            ctx.create_service()
                .await
                .into_layer_with_error_handler(Arc::new(TeapotErrorHandler {})),
        )
        .service_fn(echo);

    let request = request_with_headers(Vec::new());

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    let body = response.into_body().collect().await.unwrap();
    assert_eq!(
        String::from_utf8(body.to_bytes().into()).unwrap(),
        "With a body".to_owned()
    );
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
