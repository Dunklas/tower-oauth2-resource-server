use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use common::{jwt_from, mock_jwks, mock_oidc_config, DEFAULT_RSA_PRIVATE_KEY};
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
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "https://auth-server.com").await;
    mock_jwks(&mock_server, ["good_key".to_owned()].to_vec()).await;
    let mut service = ServiceBuilder::new()
        .layer(default_auth_layer(&mock_server, &["https://some-resource-server.com"]).await)
        .service_fn(echo);

    let token = jwt_from(
        &DEFAULT_RSA_PRIVATE_KEY,
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
async fn unauthorized_when_jwt_signed_with_unknown_key() {
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "https://auth-server.com").await;
    mock_jwks(&mock_server, ["good_key".to_owned()].to_vec()).await;
    let mut service = ServiceBuilder::new()
        .layer(default_auth_layer(&mock_server, &["https://some-resource-server.com"]).await)
        .service_fn(echo);
    // Needed for initial jwks fetch
    sleep(Duration::from_millis(100)).await;

    let another_rsa_key = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsIkvGz6hM9C4G
+7wfu5KzOWxDW4PR8W12huS4aquB32UfCDZmY0HSeLqt/ulRa+z+P6KBx+LE03AH
9/ICMfoujL4q+TQ9SDyYWeJYDyIarUkgNXbGi8ofK5D3I1uE8Aim6nyi9A/tip+h
eLSL2Nsl+305y/pf/deYL+7pAOmQhXlE+j1cdqFyRoy8O0sOJFGczVRm0b6JVhp8
+eTZTssvGR8sqb1HX9gh3q62m5WRuv5pvLT2HnX1pa6BiVVy6dnT4wf8DVGStzXK
dcf2OxEpRy2SZvjNKkNvxY6jeQgn1IfzacQMc+2gezd2G8bMYMqzjNM8TqdGDAhP
pvRZCVwfAgMBAAECggEABuoPwiooOAMc8DHfciTeNS3Kz//WkTHR9E9h05iRUBOx
o6f4S2+UPsiTsxaIt7kOmX3j4LOvQ7m8h81pXrY0Nvd3UhGVjBqhOHtv0Jq3A3xP
cihDn6EQ2uSsm4jDjdj4d//2RrNoCmIlnF5VXkK1NtbdxlsPsRhotxfB0IE1YJUy
+lLkCmR2rPny2wL32wXQZ1TzcHnLNI0Vr/fWkf6lS1jro96XFsfmBiAV7rJsevnr
4s03tnlE55WskNDYDLHqkI5Uk76WZ8y8PRY3XWD+Q6WFP7/AhTrTEeXOGjJT9t5E
2YJfvHI4IQbcvDMHXA0JcwG2D+NigloJoVTlDLQ80QKBgQDrkfS46jUWu+vSV3DX
cFhGmoji6qlVgX7kilC96IoswjW1JQVmegYv1T5PHDl9r03JUE51BAG+Yw6XRiWa
CMueJZsA+u1UCxaIkkyv4dkcJXWmLSmfYW/NmyczZQQtdgqxgsBMsVMZFO/Sx6og
6N0uXFhcdu1JxQ/p2kNnnHpEzwKBgQC7D/Pt1Vlouw8J2Pfg34TRR3jVHuBVWni2
jPBhjCVmK1Lb+VMLpMBRy/Wampd2zmdJ79kStTB4R5scoU/oMUf5mteljoEsUOnA
1OznTTAnOpbA/Mwg+Kcgt/3mjHRaNqcAnia+aWENzI3lbdjR+2Xm7I8jnbWKps8Y
ig0cEUfnsQKBgQCBI19L66C02Mn7YlIK2Jyb/+VguBGiPT4p3SVMJmlxBfpZVnUy
a1xu5nCk/60ImIyE+tA31714+GasSRkd6wpspOLnU6e89eMhdUoy9RWHF4X6VjHG
HK0kwpRn2U3D+jz8eNggculCC7c5DpnWNrHh01/hOJT2ZuBFa5CeASsKAwKBgGfo
cKMIA+Y9IhliQC7Vej2V6fTYddxzqOIeX9iPtKaQIjK2x/6LwZiuJvt+K+x+srlL
VdUieI4XmH3KzUw5M7Xe4TLBeddYCsBmhkHlin3/+YWx5uHZvVxbV9oc4vTJrvKU
5wiWGKdFnPx4jBv3/Z7MgKZUEGe4SQlkheu1Xa/BAoGANz6WUrXSL1jLkw71nDd/
CX4iVdeW+740CyxNIh0Ps6AkVdQdNtlnAyjuwahWL/zJcXfdthct+B8vT07F68NE
k7ZGOcHSWi3KlQZy3d498IZOaZDxMzfVgp0fx0mk2pKt0i7B5n/kbTReBMWyR9SK
hyvdAY5huggrF/dBOhXOWt8=
-----END PRIVATE KEY-----"#;

    let token = jwt_from(
        another_rsa_key,
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
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ok() {
    let mock_server = MockServer::start().await;
    mock_oidc_config(&mock_server, "https://auth-server.com").await;
    mock_jwks(&mock_server, ["good_key".to_owned()].to_vec()).await;
    let mut service = ServiceBuilder::new()
        .layer(default_auth_layer(&mock_server, &["https://some-resource-server.com"]).await)
        .service_fn(echo);
    // Needed for initial jwks fetch
    sleep(Duration::from_millis(100)).await;

    let token = jwt_from(
        DEFAULT_RSA_PRIVATE_KEY,
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
            TenantConfiguration::builder()
                .issuer_url(mock_server.uri())
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
