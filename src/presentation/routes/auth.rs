use axum::{Router, routing::post};
use std::sync::Arc;

use crate::presentation::handlers::auth::{AppState, post_sign_up};

/// Defines routing for authentication-related endpoints.
pub fn auth_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/signup", post(post_sign_up))
        .with_state(state)
}
