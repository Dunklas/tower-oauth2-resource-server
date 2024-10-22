use log::info;
use salvo::{prelude::*, server::ServerHandle};
use tokio::signal;
use tower_oauth2_resource_server::{claims::DefaultClaims, server::OAuth2ResourceServer};

#[tokio::main]
async fn main() {
    env_logger::init();
    let oidc_provider = examples_util::start_oidc_provider().await;
    let oidc_provider_host = oidc_provider.get_host().await.unwrap();
    let oidc_provider_port = oidc_provider.get_host_port_ipv4(8080).await.unwrap();
    info!("Running OIDC provider on port: {}", oidc_provider_port);

    let oauth2_resource_server = <OAuth2ResourceServer>::builder()
        .audiences(vec!["tors-example".to_owned()])
        .issuer_uri(&format!(
            "http://{}:{}/realms/tors",
            oidc_provider_host, oidc_provider_port
        ))
        .build()
        .expect("Failed to build OAuth2ResourceServer");

    let router = Router::new()
        .hoop(oauth2_resource_server.into_layer().compat())
        .get(hello);
    let acceptor = TcpListener::new("127.0.0.1:3000").bind().await;
    let server = Server::new(acceptor);
    let handle = server.handle();

    tokio::spawn(listen_shutdown_signal(handle));

    info!("Running salvo on port: 3000");
    server.serve(router).await;
}

#[handler]
async fn hello(req: &mut Request, res: &mut Response) {
    let sub = match req.extensions().get::<DefaultClaims>() {
        Some(claims) => match claims.sub.as_ref() {
            Some(sub) => sub,
            None => {
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                return;
            }
        },
        None => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            return;
        }
    };
    res.status_code(StatusCode::OK);
    res.render(format!("Hello, {}", sub));
}

async fn listen_shutdown_signal(handle: ServerHandle) {
    // Wait Shutdown Signal
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

    #[cfg(windows)]
    let terminate = async {
        signal::windows::ctrl_c()
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => println!("ctrl_c signal received"),
        _ = terminate => println!("terminate signal received"),
    };

    // Graceful Shutdown Server
    handle.stop_graceful(None);
}
