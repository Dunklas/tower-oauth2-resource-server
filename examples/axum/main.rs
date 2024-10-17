use axum::{routing::get, Router};
use log::info;
use tokio::signal;
use tower::ServiceBuilder;
use tower_oauth2_resource_server::server::OAuth2ResourceServer;

#[path = "../util/lib.rs"]
mod util;

#[tokio::main]
async fn main() {
    env_logger::init();
    let oidc_provider = util::start_oidc_provider().await;
    let oidc_provider_host = oidc_provider.get_host().await.unwrap();
    let oidc_provider_port = oidc_provider.get_host_port_ipv4(8080).await.unwrap();
    info!(
        "Running local OIDC provider on: {}:{}",
        oidc_provider_host, oidc_provider_port
    );

    let auth_manager = <OAuth2ResourceServer>::builder()
        .audiences(vec![])
        .issuer_uri(&format!(
            "http://{}:{}/realms/tors",
            oidc_provider_host, oidc_provider_port
        ))
        .build()
        .expect("Failed to build OAuth2ResourceServer");

    let app = Router::new()
        .route("/", get(root))
        .layer(ServiceBuilder::new().layer(auth_manager.into_layer()));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn root() -> &'static str {
    "Hello, World!"
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
