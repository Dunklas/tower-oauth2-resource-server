use std::sync::Arc;

use axum::{
    body::Body,
    http::{Response, StatusCode},
    routing::get,
    Extension, Router,
};
use log::info;
use tokio::signal;
use tower::ServiceBuilder;
use tower_oauth2_resource_server::{
    claims::DefaultClaims, error::AuthError, error_handler::ErrorHandler,
    server::OAuth2ResourceServer, tenant::TenantConfiguration,
};

struct TeapotErrorHandler;

impl ErrorHandler<Body> for TeapotErrorHandler {
    fn map_error(&self, error: AuthError) -> Response<Body> {
        Response::builder()
            .status(StatusCode::IM_A_TEAPOT)
            .body(error.to_string().into())
            .unwrap()
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let oidc_provider = examples_util::start_oidc_provider().await;
    let oidc_provider_host = oidc_provider.get_host().await.unwrap();
    let oidc_provider_port = oidc_provider.get_host_port_ipv4(8080).await.unwrap();
    info!("Running OIDC provider on port: {}", oidc_provider_port);

    let oauth2_resource_server = <OAuth2ResourceServer>::builder()
        .add_tenant(
            TenantConfiguration::builder(format!(
                "http://{}:{}/realms/tors",
                oidc_provider_host, oidc_provider_port
            ))
            .audiences(&["tors-example"])
            .build()
            .await
            .expect("Failed to build tenant configuration"),
        )
        .build()
        .await
        .expect("Failed to build OAuth2 resource server");

    let app = Router::new()
        .route("/", get(root))
        .layer(ServiceBuilder::new().layer(
            oauth2_resource_server.into_layer_with_error_handler(Arc::new(TeapotErrorHandler {})),
        ));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("Running axum on port: 3000");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn root(claims: Extension<DefaultClaims>) -> Result<(StatusCode, String), StatusCode> {
    let sub = claims
        .sub
        .as_ref()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::OK, format!("Hello, {}", sub)))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
