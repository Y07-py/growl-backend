use axum::{Router, routing};
use std::sync::Arc;

use crate::presentation::handlers::auth::{post_login_status, post_sign_up, AppState};

/// Defines routing for authentication-related endpoints.
pub fn auth_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/signup", routing::post(post_sign_up))
        .route("/login_status", routing::post(post_login_status))
        .with_state(state)
}
