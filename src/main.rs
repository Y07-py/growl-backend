#![recursion_limit = "256"]
use dotenv;
use std::sync::Arc;

pub mod application;
pub mod domain;
pub mod infra;
pub mod presentation;

use crate::infra::repository::postgres::PostgresHandler;
use crate::infra::services::{
    auth::CognitoAuthenticationService, ses::SESService, sns::SNSService,
};
use crate::infra::utils::logger::init_logger;
use crate::presentation::handlers::auth::AppState;
use crate::presentation::routes::create_router;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    // 1. Initialize Global Logger
    let root_logger = init_logger();
    slog::info!(root_logger, "Growl Backend starting up...");

    // 2. Initialize Infrastructure Services (DI)
    let auth_service = CognitoAuthenticationService::new(&root_logger).await;
    let ses_service = SESService::new(&root_logger).await;
    let sns_service = SNSService::new(&root_logger).await;

    // 3. Initialize Repositories (Postgres)
    // Connecting to the database endpoint defined in environment variables.
    let postgres_handler = PostgresHandler::new(10, &root_logger).await;

    // 4. Construct AppState with shared generic services
    let state = Arc::new(AppState::new(
        auth_service,
        postgres_handler,
        ses_service,
        sns_service,
    ));

    // 5. Build Routing
    let app = create_router(state);

    // 6. Start the Axum Server
    let addr = "0.0.0.0:8080";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    slog::info!(root_logger, "Server listening on http://{}", addr);

    axum::serve(listener, app).await
}
