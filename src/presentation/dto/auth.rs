use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethodDTO {
    Email,
    PhoneNumber,
    Google,
    Apple,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserIdentityDTO {
    pub sub_id: String,
    pub email: String,
    pub phone_number: String,
    pub authentication_method: String,
    pub role: String,
}

impl UserIdentityDTO {
    pub fn new(
        sub_id: &str,
        email: &str,
        phone_number: &str,
        authentication_method: &str,
        role: &str,
    ) -> Self {
        Self {
            sub_id: sub_id.to_string(),
            email: email.to_string(),
            phone_number: phone_number.to_string(),
            authentication_method: authentication_method.to_string(),
            role: role.to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationSessionDTO {
    pub identity: UserIdentityDTO,
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub expired_at: chrono::DateTime<chrono::Utc>,
}

impl AuthenticationSessionDTO {
    pub fn new(
        identity: &UserIdentityDTO,
        access_token: &str,
        id_token: &str,
        refresh_token: &Option<String>,
        expires_at: &chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            identity: identity.clone(),
            access_token: access_token.to_string(),
            id_token: id_token.to_string(),
            refresh_token: refresh_token.clone(),
            expired_at: expires_at.clone(),
        }
    }
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
