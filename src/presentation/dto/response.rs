use serde::Serialize;

use crate::domain::entities::auth::AuthenticationSession;
use crate::presentation::dto::auth::{AuthenticationSessionDTO, UserIdentityDTO};

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

#[derive(Debug, Serialize)]
pub struct VerificationCodeResponse {
    pub session: AuthenticationSessionDTO,
}

impl VerificationCodeResponse {
    pub fn new(session: AuthenticationSession) -> Self {
        let identity = session.identity();
        let identity_dto = UserIdentityDTO::new(
            &identity.sub_id,
            &identity.email,
            &identity.phone_number,
            &identity.authentication_method,
            &identity.role,
        );
        let session_dto = AuthenticationSessionDTO::new(
            &identity_dto,
            &session.access_token(),
            &session.id_token(),
            &session.refresh_token(),
            &session.expired_at(),
        );

        Self {
            session: session_dto,
        }
    }
}
