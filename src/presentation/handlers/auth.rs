use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use std::sync::Arc;

use crate::application::auth::sign_up;
use crate::domain::interface::{auth as auth_interface, repository};
use crate::presentation::dto::auth::{SignUpRequest, SignUpResponse};

/// Represents the shared application state containing services and repositories.
pub struct AppState {
    pub auth_service: Arc<dyn auth_interface::AuthenticationService + Send + Sync>,
    pub auth_repo: Arc<dyn repository::AuthenticationRepository + Send + Sync>,
    pub otp_service_ses: Arc<dyn auth_interface::OTPService + Send + Sync>, // For Email
    pub otp_service_sns: Arc<dyn auth_interface::OTPService + Send + Sync>, // For SMS
}

/// HTTP handler for guest sign-up requests.
/// It identifies the auth method (Email or Phone), selects the appropriate OTP service,
/// and orchestrates the sign-up flow using the application layer.
#[axum::debug_handler]
pub async fn post_sign_up(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SignUpRequest>,
) -> impl IntoResponse {
    // 1. Determine authentication method from payload.
    let method = if let Some(email) = payload.email {
        auth_interface::AuthenticationMethod::Email {
            email,
            otp: None,
            session_id: None,
        }
    } else if let Some(phone_number) = payload.phone_number {
        auth_interface::AuthenticationMethod::PhoneNumber {
            phone_number,
            otp: None,
            session_id: None,
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(SignUpResponse::new(
                None,
                "Email or Phone number is required".to_string(),
            )),
        )
            .into_response();
    };

    // 2. Select the corresponding OTP service based on the method.
    let otp_service = match &method {
        auth_interface::AuthenticationMethod::Email { .. } => state.otp_service_ses.as_ref(),
        _ => state.otp_service_sns.as_ref(),
    };

    // 3. Call the sign_up use case from the application layer.
    match sign_up(
        state.auth_service.as_ref(),
        state.auth_repo.as_ref(),
        otp_service,
        &method,
    )
    .await
    {
        Ok(challenge) => (
            StatusCode::OK,
            Json(SignUpResponse::new(
                challenge.map(|c| c.session_id()),
                "Confirmation code sent successfully".to_string(),
            )),
        )
            .into_response(),
        Err(e) => {
            // Map validation errors to 400 Bad Request, others to 500 Internal Server Error.
            let status = if e.to_string().contains("Invalid format") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            (
                status,
                Json(SignUpResponse::new(None, format!("Sign up failed: {}", e))),
            )
                .into_response()
        }
    }
}
