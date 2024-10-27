use log::info;
use tokio::signal;
use tonic::{transport::Server, Request, Response, Status};
use tower::ServiceBuilder;

use hello_world::greeter_server::{Greeter, GreeterServer};
use hello_world::{HelloReply, HelloRequest};
use tower_oauth2_resource_server::claims::DefaultClaims;
use tower_oauth2_resource_server::server::OAuth2ResourceServer;
use url::Url;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let oidc_provider = examples_util::start_oidc_provider().await;
    let oidc_provider_host = oidc_provider.get_host().await.unwrap();
    let oidc_provider_port = oidc_provider.get_host_port_ipv4(8080).await.unwrap();
    info!("Running OIDC provider on port: {}", oidc_provider_port);

    let oauth2_resource_server = <OAuth2ResourceServer>::builder()
        .audiences(&["tors-example"])
        .issuer_uri(
            format!(
                "http://{}:{}/realms/tors",
                oidc_provider_host, oidc_provider_port
            )
            .parse::<Url>()
            .unwrap(),
        )
        .build()
        .await
        .expect("Failed to build OAuth2ResourceServer");

    let addr = "[::1]:50051".parse()?;
    let greeter = MyGreeter::default();

    info!("Running tonic on port: 50051");
    Server::builder()
        .layer(
            ServiceBuilder::new()
                .layer(oauth2_resource_server.into_layer())
                .into_inner(),
        )
        .add_service(GreeterServer::new(greeter))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    Ok(())
}

#[derive(Debug, Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let claims = request
            .extensions()
            .get::<DefaultClaims>()
            .ok_or(Status::internal("Failed to obtain JWT claims"))?;
        let sub = claims
            .sub
            .as_ref()
            .ok_or(Status::internal("Missing sub claim in JWT"))?;
        println!("Got a request: {:?}", request);

        let reply = HelloReply {
            message: format!("Hello {}!", sub),
        };

        Ok(Response::new(reply))
    }
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
