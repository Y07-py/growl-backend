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
