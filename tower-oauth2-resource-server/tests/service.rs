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

use crate::common::{
    context::{OidcOptions, StaticOptions, TenantInput, TestContext, START_UP_DELAY_MS},
    jwt::JwtBuilder,
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

#[tokio::test]
async fn ok_static() {
    let [rsa_key, ..] = rsa_keys();
    let jwks = common::jwks(&[("good_key", &rsa_key)]);
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
async fn ok_mixed() {
    let [static_key, oidc_key] = rsa_keys();
    let jwks = common::jwks(&[("good_static", &static_key)]);

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
        .encoding_key(("good_oidc".to_owned(), oidc_key.clone()))
        .aud("https://some-resource-server.com")
        .build();
    let request = request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {}", token))]);

    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "OIDC request failed");

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
async fn ok_mixed_kid() {
    let [static_key, oidc_key] = rsa_keys();
    let jwks = common::jwks(&[("good_static", &static_key)]);

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CustomJwtClaims {
    sub: String,
    role: String,
}

#[tokio::test]
async fn propagates_jwt_claims() {
    let ctx = TestContext::builder()
        .with_tenant_configuration(TenantInput::Oidc(
            OidcOptions::default().audiences(vec!["https://some-resource-server.com"]),
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

    let token = ctx
        .valid_jwt()
        .sub("Some dude")
        .aud("https://some-resource-server.com")
        .custom_claim("role".to_owned(), "superuser".to_owned())
        .build();
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
        .with_tenant_configuration(TenantInput::Oidc(OidcOptions::default()))
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
