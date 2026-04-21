use chrono;
use serde::{Deserialize, Serialize};

use crate::domain::interface;

#[derive(Debug, Clone)]
pub struct AuthenticationSession {
    user: AuthenticationUser,
    access_token: String,
    id_token: String,
    refresh_token: Option<String>,
    expired_at: chrono::DateTime<chrono::Utc>,
}

impl AuthenticationSession {
    pub fn new(
        user: AuthenticationUser,
        access_token: String,
        id_token: String,
        refresh_token: Option<String>,
        expires_in: i32,
    ) -> Self {
        let expired_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64);
        Self {
            user,
            access_token,
            id_token,
            refresh_token,
            expired_at,
        }
    }

    pub fn user(&self) -> AuthenticationUser {
        self.user.clone()
    }

    pub fn access_token(&self) -> String {
        self.access_token.clone()
    }

    pub fn refresh_token(&self) -> Option<String> {
        if let Some(refresh_token) = self.refresh_token.clone() {
            return Some(refresh_token.clone());
        }

        None
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticationUser {
    pub sub_id: String,
    pub email: String,
    pub phone_number: String,
    pub authentication_method: String,
    pub role: String,
}

impl AuthenticationUser {
    pub fn new(
        sub_id: String,
        email: String,
        phone_number: String,
        authentication_method: String,
        role: String,
    ) -> Self {
        Self {
            sub_id,
            email,
            phone_number,
            authentication_method,
            role,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationClaims {
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub nbf: usize,
    pub sub: String,
}

impl AuthenticationClaims {
    pub fn sub_id(&self) -> String {
        self.sub.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    session_id: String,
    created_at: chrono::DateTime<chrono::Utc>,
    authentication_method: String,
}

impl AuthenticationChallenge {
    pub fn new(session_id: &str, method: &interface::auth::AuthenticationMethod) -> Self {
        let authentication_method: String = match method {
            interface::auth::AuthenticationMethod::Email { .. } => "email".to_string(),
            &interface::auth::AuthenticationMethod::PhoneNumber { .. } => {
                "phone_number".to_string()
            }
            _ => {
                panic!(
                    "AuthenticationChallenge does not accept attributes other than the email or phone number methods"
                )
            }
        };

        Self {
            session_id: session_id.to_string(),
            created_at: chrono::Utc::now(),
            authentication_method,
        }
    }
}
