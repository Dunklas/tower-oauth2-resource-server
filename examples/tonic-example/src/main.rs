use log::info;
use tonic::{transport::Server, Request, Response, Status};
use tower::ServiceBuilder;

use hello_world::greeter_server::{Greeter, GreeterServer};
use hello_world::{HelloReply, HelloRequest};
use tower_oauth2_resource_server::server::OAuth2ResourceServer;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let addr = "[::1]:50051".parse()?;
    let greeter = MyGreeter::default();

    info!("Starting tonic on port 50051");
    Server::builder()
        .layer(
            ServiceBuilder::new()
                .layer(oauth2_resource_server.into_layer())
                .into_inner(),
        )
        .add_service(GreeterServer::new(greeter))
        .serve(addr)
        .await?;

    Ok(())
}

#[derive(Debug, Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>, // Accept request of type HelloRequest
    ) -> Result<Response<HelloReply>, Status> {
        // Return an instance of type HelloReply
        println!("Got a request: {:?}", request);

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name), // We must use .into_inner() as the fields of gRPC requests and responses are private
        };

        Ok(Response::new(reply)) // Send back our formatted greeting
    }
}
