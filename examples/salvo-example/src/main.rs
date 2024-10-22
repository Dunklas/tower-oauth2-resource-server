use log::info;
use salvo::prelude::*;
use tower_oauth2_resource_server::server::OAuth2ResourceServer;

#[tokio::main]
async fn main() {
    env_logger::init();
    let oidc_provider = examples_util::start_oidc_provider().await;
    let oidc_provider_host = oidc_provider.get_host().await.unwrap();
    let oidc_provider_port = oidc_provider.get_host_port_ipv4(8080).await.unwrap();
    info!(
        "Running local OIDC provider on: {}:{}",
        oidc_provider_host, oidc_provider_port
    );

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
    Server::new(acceptor).serve(router).await;
}

#[handler]
async fn hello() -> &'static str {
    "Hello World"
}
