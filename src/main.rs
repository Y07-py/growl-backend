#![recursion_limit = "256"]
use axum::Router;
use dotenv;

pub mod application;
pub mod domain;
pub mod infra;
pub mod presentation;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    let app = Router::new();

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await
}
