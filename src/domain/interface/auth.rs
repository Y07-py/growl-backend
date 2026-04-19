use async_trait::async_trait;

use crate::domain::entities::auth::{AuthenticationSession, AuthenticationUser};

#[derive(Debug)]
pub enum AuthenticationError {
    InvalidCredential,
    UserNotFound,
    NetWorkError,
    Unexpected(String),
}

#[derive(Debug)]
pub enum AuthenticationResponse {
    Authenticated(AuthenticationSession),
    OtpSent { session: String },
}

pub enum AuthenticationMethod {
    Email {
        email: String,
        otp: Option<String>,
        session: Option<String>,
    },
    PhoneNumber {
        phone_number: String,
        otp: Option<String>,
        session: Option<String>,
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
}
