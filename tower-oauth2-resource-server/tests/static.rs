use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use http::{header::AUTHORIZATION, StatusCode};
use http_body_util::BodyExt;
use tokio::time::sleep;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_oauth2_resource_server::{
    auth_resolver::KidAuthorizerResolver, server::OAuth2ResourceServer,
    validation::ClaimsValidationSpec,
};

use crate::common::{
    context::{OidcOptions, StaticOptions, TenantInput, TestContext, START_UP_DELAY_MS},
    jwks::build_jwks,
    jwt::JwtBuilder,
    rsa::rsa_keys,
    util::{echo, request_with_headers, DetailedErrorHandler},
};

pub mod common;

#[tokio::test]
async fn ok() {
    let [rsa_key, ..] = rsa_keys();
    let jwks = build_jwks(&[("good_key", &rsa_key)]);
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Static(
            StaticOptions::default()
                .jwks(jwks)
                .audiences(vec!["https://some-resource-server.com"]),
        ))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(ctx.create_service().await.into_layer())
        .service_fn(echo);

    let token = ctx
        .valid_jwt()
        .encoding_key(("good_key".to_owned(), rsa_key.clone()))
        .aud("https://some-resource-server.com")
        .build();
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ok_mixed_oidc() {
    let [static_key, oidc_key] = rsa_keys();
    let jwks = build_jwks(&[("good_static", &static_key)]);

    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Static(
            StaticOptions::default()
                .jwks(jwks)
                .audiences(vec!["https://some-resource-server.com"]),
        ))
        .with_tenant_configuration(TenantInput::Oidc(
            OidcOptions::default()
                .audiences(vec!["https://some-resource-server.com"])
                .rsa(("good_oidc", oidc_key.clone())),
        ))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(ctx.create_service().await.into_layer())
        .service_fn(echo);

    let token = ctx
        .valid_jwt()
        .encoding_key(("good_static".to_owned(), static_key.clone()))
        .aud("https://some-resource-server.com")
        .iss("static")
        .build();
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Static request failed");
}

#[tokio::test]
async fn ok_mixed_oidc_kid_resolver() {
    let [static_key, oidc_key] = rsa_keys();
    let jwks = build_jwks(&[("good_static", &static_key)]);

    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Static(
            StaticOptions::default()
                .jwks(jwks)
                .audiences(vec!["https://some-resource-server.com"])
                .claims_validation(ClaimsValidationSpec::new().exp(true)),
        ))
        .with_tenant_configuration(TenantInput::Oidc(
            OidcOptions::default()
                .audiences(vec!["https://some-resource-server.com"])
                .rsa(("good_oidc", oidc_key.clone()))
                .claims_validation(
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

    let token = JwtBuilder::new()
        .encoding_key(("good_oidc".to_owned(), oidc_key.clone()))
        .aud("https://some-resource-server.com")
        .exp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 10,
        )
        .build();
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "OIDC request failed");

    let token = JwtBuilder::new()
        .encoding_key(("good_static".to_owned(), static_key.clone()))
        .exp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 10,
        )
        .build();
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Static request failed");
}

#[tokio::test]
async fn unauthorized_on_missing_authorization() {
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Static(StaticOptions::default()))
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
async fn unauthorized_on_invalid_key() {
    let [valid_key, invalid_key] = rsa_keys();
    let jwks = build_jwks(&[("good_key", &valid_key)]);
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Static(StaticOptions::default().jwks(jwks)))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(
            ctx.create_service()
                .await
                .into_layer_with_error_handler(Arc::new(DetailedErrorHandler {})),
        )
        .service_fn(echo);

    let token = ctx
        .valid_jwt()
        .encoding_key(("good_key".to_owned(), invalid_key))
        .build();
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response.into_body().collect().await.unwrap();
    assert_eq!(
        String::from_utf8(body.to_bytes().into()).unwrap(),
        "ValidationFailed { reason: InvalidSignature }".to_owned()
    );
}
