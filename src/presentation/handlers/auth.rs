use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use std::sync::Arc;

use crate::application::auth::{get_login_status, sign_up};
use crate::domain::interface::{auth as auth_interface, repository};
use crate::presentation::dto::auth::{
    AuthenticationMethodDTO, AuthenticationSessionDTO, LoginStatusDTO, LoginStatusResponse,
    SignUpRequest, SignUpResponse, UserIdentityDTO,
};

/// Represents the shared application state containing services and repositories.
pub struct AppState {
    pub auth_service: Arc<dyn auth_interface::AuthenticationService + Send + Sync>,
    pub auth_repo: Arc<dyn repository::AuthenticationRepository + Send + Sync>,
    pub otp_service_ses: Arc<dyn auth_interface::OTPService + Send + Sync>, // For Email
    pub otp_service_sns: Arc<dyn auth_interface::OTPService + Send + Sync>, // For SMS
}

impl AppState {
    pub fn new(
        auth_service: Arc<dyn auth_interface::AuthenticationService + Send + Sync>,
        auth_repo: Arc<dyn repository::AuthenticationRepository + Send + Sync>,
        otp_service_ses: Arc<dyn auth_interface::OTPService + Send + Sync>,
        otp_service_sns: Arc<dyn auth_interface::OTPService + Send + Sync>,
    ) -> Self {
        Self {
            auth_service,
            auth_repo,
            otp_service_ses,
            otp_service_sns,
        }
    }
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
    let method = match payload.method {
        AuthenticationMethodDTO::Email => auth_interface::AuthenticationMethod::Email {
            email: payload.user_name,
            otp: None,
            session_id: None,
        },
        AuthenticationMethodDTO::PhoneNumber => auth_interface::AuthenticationMethod::PhoneNumber {
            phone_number: payload.user_name,
            otp: None,
            session_id: None,
        },
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SignUpResponse::new(
                    None,
                    "Email or Phone number is required".to_string(),
                )),
            )
                .into_response();
        }
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

/// HTTP handler for checking login status.
/// It uses the provided session identity to verify if the user exists and is authenticated.
#[axum::debug_handler]
pub async fn post_login_status(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthenticationSessionDTO>,
) -> impl IntoResponse {
    match get_login_status(state.auth_repo.as_ref(), &payload.identity.sub_id).await {
        Ok(Some(user)) => {
            let response = LoginStatusResponse {
                login_status: LoginStatusDTO::Authenticated,
                identity: Some(UserIdentityDTO {
                    sub_id: user.sub_id,
                    email: user.email,
                    phone_number: user.phone_number,
                    authentication_method: user.authentication_method,
                    role: user.role,
                }),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(None) => {
            let response = LoginStatusResponse {
                login_status: LoginStatusDTO::Unauthenticated,
                identity: None,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(format!("Failed to check login status: {}", e)),
        )
            .into_response(),
    }
}
