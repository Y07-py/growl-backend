use axum::Router;
use std::sync::Arc;

use crate::presentation::handlers::auth::AppState;

mod auth;

/// Main entry point for application routing.
/// Nests sub-routers for different features (e.g., auth) under its versioned API prefix.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new().nest("/api/v1/auth", auth::auth_routes(state))
}
