use axum::{Router, routing};
use std::sync::Arc;

use crate::presentation::handlers::auth::{
    AppState, post_login_status, post_sign_up, post_verification_code,
};

/// Defines routing for authentication-related endpoints.
pub fn auth_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/signup", routing::post(post_sign_up))
        .route("/verification_code", routing::post(post_verification_code))
        .route("/login_status", routing::post(post_login_status))
        .with_state(state)
}
