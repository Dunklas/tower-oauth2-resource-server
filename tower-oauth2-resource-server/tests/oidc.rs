use std::time::{SystemTime, UNIX_EPOCH};

use http::{header::AUTHORIZATION, StatusCode};
use tower::{Service, ServiceBuilder, ServiceExt};

use crate::common::{
    context::{OidcOptions, TenantInput, TestContext},
    echo, request_with_headers,
};

mod common;

#[tokio::test]
async fn unauthorized_on_missing_authorization() {
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(OidcOptions::default()))
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
        .with_tenant_configuration(TenantInput::Oidc(OidcOptions::default()))
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
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(OidcOptions::default()))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(ctx.create_service().await.into_layer())
        .service_fn(echo);

    let two_min_ago = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - (2 * 60);
    let token = ctx.valid_jwt().exp(two_min_ago).build();
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ok() {
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(
            OidcOptions::default().audiences(vec!["https://some-resource-server.com"]),
        ))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(ctx.create_service().await.into_layer())
        .service_fn(echo);

    let token = ctx
        .valid_jwt()
        .aud("https://some-resource-server.com")
        .build();
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
