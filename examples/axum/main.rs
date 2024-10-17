use axum::{routing::get, Router};

#[path = "../util/lib.rs"]
mod util;

#[tokio::main]
async fn main() {
    let oidc_provider = util::start_oidc_provider().await;
    let app = Router::new().route("/", get(root));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> &'static str {
    "Hello, World!"
}
