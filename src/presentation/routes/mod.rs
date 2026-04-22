use axum::Router;
use std::sync::Arc;

use crate::presentation::handlers::auth::AppState;

mod auth;

use crate::presentation::handlers::health::get_health;

/// Main entry point for application routing.
/// Nests sub-routers for different features (e.g., auth) under its versioned API prefix.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", axum::routing::get(get_health))
        .nest("/api/v1/auth", auth::auth_routes(state))
}
