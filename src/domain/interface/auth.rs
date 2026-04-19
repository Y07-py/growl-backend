use async_trait::async_trait;

use crate::domain::entities::auth::{AuthenticationSession, AuthenticationUser};

pub enum AuthenticationError {
    InvalidCredential,
    UserNotFound,
    NetWorkError,
    Unexpected(String),
}

pub enum AuthenticationResponse {
    Authenticated(AuthenticationSession),
    OtpSent { session: String },
}

#[derive(Debug)]
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
    async fn sign_out(&self) -> Result<(), AuthenticationError>;
    async fn sign_in(
        &self,
        method: &AuthenticationMethod,
    ) -> Result<AuthenticationResponse, AuthenticationError>;
    async fn sign_up(
        &self,
        method: &AuthenticationMethod,
    ) -> Result<AuthenticationUser, AuthenticationError>;
}
