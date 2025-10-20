use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use http::{StatusCode, header::AUTHORIZATION};
use http_body_util::BodyExt;
use tower::{Service, ServiceBuilder, ServiceExt};

use crate::common::{
    context::{OidcOptions, StaticOptions, TenantInput, TestContext},
    jwks::build_jwks,
    rsa::rsa_keys,
    util::{DetailedErrorHandler, echo, request_with_headers},
};

pub mod common;

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

#[tokio::test]
async fn ok_mixed_static() {
    let [oidc_key, static_key] = rsa_keys();
    let jwks = build_jwks(&[("good_static", &static_key)]);

    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(
            OidcOptions::default()
                .audiences(vec!["https://some-resource-server.com"])
                .rsa(("good_oidc", oidc_key.clone())),
        ))
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
        .encoding_key(("good_oidc".to_owned(), oidc_key.clone()))
        .aud("https://some-resource-server.com")
        .build();
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Static request failed");
}

#[tokio::test]
async fn ok_mixed_oidc() {
    let [auth_server_key, another_auth_server_key] = rsa_keys();
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(
            OidcOptions::default()
                .rsa(("auth_server_key", auth_server_key.clone()))
                .issuer_path("/auth-server"),
        ))
        .with_tenant_configuration(TenantInput::Oidc(
            OidcOptions::default()
                .rsa(("another_auth_server_key", another_auth_server_key.clone()))
                .issuer_path("/another-auth-server"),
        ))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(
            ctx.create_service()
                .await
                .into_layer_with_error_handler(Arc::new(DetailedErrorHandler {})),
        )
        .service_fn(echo);

    let invalid_iss_token = ctx
        .valid_jwt()
        .encoding_key(("auth_server_key".to_owned(), auth_server_key.clone()))
        .iss(format!(
            "{}{}",
            ctx.mock_server_url(),
            "/another-auth-server"
        ))
        .build();
    let request = request_with_headers(vec![(
        AUTHORIZATION,
        &format!("Bearer {}", invalid_iss_token),
    )]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response.into_body().collect().await.unwrap();
    assert_eq!(
        String::from_utf8(body.to_bytes().into()).unwrap(),
        "InvalidKeyId".to_owned()
    );

    let valid_token = ctx
        .valid_jwt()
        .encoding_key(("auth_server_key".to_owned(), auth_server_key.clone()))
        .iss(format!("{}{}", ctx.mock_server_url(), "/auth-server"))
        .build();
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", valid_token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let valid_token = ctx
        .valid_jwt()
        .encoding_key((
            "another_auth_server_key".to_owned(),
            another_auth_server_key.clone(),
        ))
        .iss(format!(
            "{}{}",
            ctx.mock_server_url(),
            "/another-auth-server"
        ))
        .build();
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", valid_token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

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
async fn unauthorized_on_expired_token() {
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(OidcOptions::default()))
        .build()
        .await;
    let mut service = ServiceBuilder::new()
        .layer(
            ctx.create_service()
                .await
                .into_layer_with_error_handler(Arc::new(DetailedErrorHandler {})),
        )
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
    let body = response.into_body().collect().await.unwrap();
    assert_eq!(
        String::from_utf8(body.to_bytes().into()).unwrap(),
        "ValidationFailed { reason: ExpiredSignature }".to_owned()
    );
}
