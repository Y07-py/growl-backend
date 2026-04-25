use async_trait::async_trait;
use std::fmt;

use crate::domain::entities::auth::{AuthenticationSession, UserIdentity};

#[derive(Debug)]
pub enum AuthenticationError {
    InvalidFormat(String),
    InvalidCredential,
    UserNotFound,
    NetWorkError,
    Unexpected(String),
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthenticationError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
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
pub trait AuthenticationService: Send + Sync {
    async fn sign_out(&self, session: &AuthenticationSession) -> Result<(), AuthenticationError>;
    async fn sign_in(
        &self,
        method: &AuthenticationMethod,
    ) -> Result<AuthenticationResponse, AuthenticationError>;
    async fn sign_up(
        &self,
        method: &AuthenticationMethod,
    ) -> Result<UserIdentity, AuthenticationError>;
    async fn refresh_token(
        &self,
        session: &AuthenticationSession,
    ) -> Result<AuthenticationSession, AuthenticationError>;
}

#[async_trait]
pub trait OTPService: Send + Sync {
    fn validation_user_name(&self, user_name: &str) -> Result<(), AuthenticationError>;
}
