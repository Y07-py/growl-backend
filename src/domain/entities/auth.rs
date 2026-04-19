use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct AuthenticationSession {
    pub user: AuthenticationUser,
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: i32,
}

impl AuthenticationSession {
    pub fn new(
        user: AuthenticationUser,
        access_token: String,
        id_token: String,
        refresh_token: Option<String>,
        expires_in: i32,
    ) -> Self {
        Self {
            user,
            access_token,
            id_token,
            refresh_token,
            expires_in,
        }
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
