use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::poll;
use http::{Request, StatusCode, header::AUTHORIZATION};
use http_body_util::Full;
use tokio::time::timeout;
use tower::{Layer, Service, ServiceExt, limit::ConcurrencyLimit, service_fn};
use tower_oauth2_resource_server::{
    claims::DefaultClaims, layer::OAuth2ResourceServerService, server::OAuth2ResourceServer,
    tenant::TenantConfiguration, validation::ClaimsValidationSpec,
};

use common::{
    context::DEFAULT_KID,
    jwks::build_jwks,
    jwt::JwtBuilder,
    rsa::rsa_keys,
    util::{echo, request_with_headers},
};

pub mod common;

type Body = Full<Bytes>;
const ISSUER: &str = "https://test-issuer.example";
const AUDIENCE: &str = "test-resource-server";
const DEADLINE: Duration = Duration::from_secs(2);

async fn limited_service<S>(
    inner: S,
) -> OAuth2ResourceServerService<ConcurrencyLimit<S>, Body, DefaultClaims> {
    let [key, ..] = rsa_keys();
    let jwks = build_jwks(&[(DEFAULT_KID, &key)]);
    let tenant = TenantConfiguration::static_builder(serde_json::to_string(&jwks).unwrap())
        .claims_validation(ClaimsValidationSpec::recommended(
            ISSUER,
            &vec![AUDIENCE.to_owned()],
        ))
        .build()
        .unwrap();
    let server = OAuth2ResourceServer::builder()
        .add_tenant(tenant)
        .build()
        .await
        .unwrap();
    server.into_layer().layer(ConcurrencyLimit::new(inner, 1))
}

fn authorized_request() -> Request<Body> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = JwtBuilder::new()
        .iss(ISSUER)
        .aud(AUDIENCE)
        .nbf(now - 120)
        .exp(now + 600)
        .build();
    request_with_headers(vec![(AUTHORIZATION, &format!("Bearer {token}"))])
}

#[tokio::test]
async fn successive_valid_requests_succeed_with_a_concurrency_limit() {
    let mut service = limited_service(service_fn(echo)).await;

    for _ in 0..2 {
        let response = timeout(DEADLINE, async {
            service
                .ready()
                .await
                .unwrap()
                .call(authorized_request())
                .await
                .unwrap()
        })
        .await
        .expect("completed request must release capacity for the next request");

        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn rejected_request_is_not_forwarded_and_releases_capacity() {
    let inner = service_fn(|request: Request<Body>| async move {
        assert!(
            request.extensions().get::<DefaultClaims>().is_some(),
            "the application must only receive authenticated requests"
        );
        echo(request).await
    });
    let mut service = limited_service(inner).await;
    let next_service = service.clone();

    let rejection = service
        .ready()
        .await
        .unwrap()
        .call(request_with_headers(Vec::new()))
        .await
        .unwrap();
    assert_eq!(rejection.status(), StatusCode::UNAUTHORIZED);

    let response = timeout(DEADLINE, next_service.oneshot(authorized_request()))
        .await
        .expect("rejected request must release capacity")
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn cancelling_before_authorization_releases_reserved_capacity() {
    let mut service = limited_service(service_fn(echo)).await;
    let mut next_service = service.clone();

    let unpolled = service.ready().await.unwrap().call(authorized_request());
    let mut next_ready = Box::pin(next_service.ready());
    assert!(poll!(next_ready.as_mut()).is_pending());

    drop(unpolled);
    let response = timeout(DEADLINE, async {
        next_ready
            .await
            .unwrap()
            .call(authorized_request())
            .await
            .unwrap()
    })
    .await
    .expect("cancellation before authorization must release reserved capacity");
    assert_eq!(response.status(), StatusCode::OK);
}
