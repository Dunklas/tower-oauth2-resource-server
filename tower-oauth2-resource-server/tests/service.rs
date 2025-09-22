use std::sync::Arc;

use bytes::Bytes;
use http::{header::AUTHORIZATION, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tower::{BoxError, Service, ServiceBuilder, ServiceExt};

use tower_oauth2_resource_server::{
    error::AuthError, error_handler::ErrorHandler, server::OAuth2ResourceServer,
};

use crate::common::{
    context::{OidcOptions, TenantInput, TestContext, START_UP_DELAY_MS},
    echo, request_with_headers,
};

mod common;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CustomJwtClaims {
    sub: String,
    role: String,
}

// Add alt. tests for both static and oidc?
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

// If I use a custom error handler (for detailed errors) in some tests, I've no need for this
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
