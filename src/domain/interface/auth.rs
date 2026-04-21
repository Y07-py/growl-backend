use async_trait::async_trait;
use std::fmt;

use crate::domain::entities::auth::{AuthenticationSession, AuthenticationUser};

#[derive(Debug)]
pub enum AuthenticationError {
    InvalidCredential,
    UserNotFound,
    NetWorkError,
    Unexpected(String),
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthenticationError::InvalidCredential => write!(f, "Invalid credential"),
            AuthenticationError::UserNotFound => write!(f, "User not found"),
            AuthenticationError::NetWorkError => write!(f, "Network error"),
            AuthenticationError::Unexpected(msg) => write!(f, "Unexpected error: {}", msg),
        }
    }
}

impl std::error::Error for AuthenticationError {}

#[derive(Debug)]
pub enum AuthenticationResponse {
    Authenticated(AuthenticationSession),
    OtpSent { session: String },
}

pub enum AuthenticationMethod {
    Email {
        email: String,
        otp: Option<String>,
        session_id: Option<String>,
    },
    PhoneNumber {
        phone_number: String,
        otp: Option<String>,
        session_id: Option<String>,
    },
    Google {
        id_token: String,
    },
    Apple {
        id_token: String,
    },
}

#[async_trait]
pub trait AuthenticationService {
    async fn sign_out(&self, session: &AuthenticationSession) -> Result<(), AuthenticationError>;
    async fn sign_in(
        &self,
        method: &AuthenticationMethod,
    ) -> Result<AuthenticationResponse, AuthenticationError>;
    async fn sign_up(
        &self,
        method: &AuthenticationMethod,
    ) -> Result<AuthenticationUser, AuthenticationError>;
    async fn refresh_token(
        &self,
        session: &AuthenticationSession,
    ) -> Result<AuthenticationSession, AuthenticationError>;
    async fn request_otp_with_email(&self, email: &str) -> Result<(), AuthenticationError>;
    async fn request_otp_with_phonenumber(
        &self,
        phone_number: &str,
    ) -> Result<(), AuthenticationError>;
}
