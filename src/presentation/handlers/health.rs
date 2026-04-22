use axum::http::StatusCode;
use axum::response::IntoResponse;

#[axum::debug_handler]
pub async fn get_health() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}
