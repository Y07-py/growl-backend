use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct SignUpRequest {
    pub email: Option<String>,
    pub phone_number: Option<String>,
}

impl SignUpRequest {
    pub fn new(email: Option<String>, phone_number: Option<String>) -> Self {
        Self {
            email,
            phone_number,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SignUpResponse {
    pub session_id: Option<String>,
    pub message: String,
}

impl SignUpResponse {
    pub fn new(session_id: Option<String>, message: String) -> Self {
        Self {
            session_id,
            message,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserIdentityDTO {
    pub sub_id: String,
    pub email: String,
    pub phone_number: String,
    pub authentication_method: String,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationSessionDTO {
    pub identity: UserIdentityDTO,
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub expired_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoginStatusDTO {
    Authenticated,
    Unauthenticated,
}

#[derive(Debug, Serialize)]
pub struct LoginStatusResponse {
    #[serde(rename = "login_status")]
    pub login_status: LoginStatusDTO,
    pub identity: Option<UserIdentityDTO>,
}
