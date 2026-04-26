use serde::Deserialize;

use crate::presentation::dto::auth::AuthenticationMethodDTO;

#[derive(Debug, Deserialize)]
pub struct SignUpRequest {
    pub user_name: String,
    pub method: AuthenticationMethodDTO,
}

impl SignUpRequest {
    pub fn new(user_name: String, method: AuthenticationMethodDTO) -> Self {
        Self { user_name, method }
    }
}

#[derive(Debug, Deserialize)]
pub struct VerificationCodeRequest {
    otp: String,
    user_name: String,
    session_id: String,
    method: AuthenticationMethodDTO,
}

impl VerificationCodeRequest {
    pub fn otp(&self) -> String {
        self.otp.clone()
    }

    pub fn user_name(&self) -> String {
        self.user_name.clone()
    }

    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }

    pub fn method(&self) -> AuthenticationMethodDTO {
        self.method.clone()
    }
}
