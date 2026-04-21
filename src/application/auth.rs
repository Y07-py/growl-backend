use crate::domain::entities;
use crate::domain::interface::{auth, repository};

pub async fn sign_up(
    auth_service: &dyn auth::AuthenticationService,
    repo: &dyn repository::AuthenticationRepository,
    method: &auth::AuthenticationMethod,
) -> Result<Option<entities::auth::AuthenticationChallenge>, Box<dyn std::error::Error>> {
    // 1. sign up with guest user.
    let guest = auth_service.sign_up(method).await?;

    // 2. insert guest user in DB, if not exist.
    repo.upsert_guest_user(&guest).await?;

    // 3.Request transimission OTP based on the method.
    let session_id: Option<String> = match method {
        auth::AuthenticationMethod::Email { email, .. } => {
            // Generate session id via sign in.
            let response = auth_service.sign_in(method).await?;
            let session_id: Option<String> = match response {
                auth::AuthenticationResponse::OtpSent { session } => Some(session),
                _ => None,
            };

            // Request otp to aws sms.
            auth_service.request_otp_with_email(email).await?;

            session_id
        }
        auth::AuthenticationMethod::PhoneNumber { phone_number, .. } => {
            // Generate session id via sign in.
            let response = auth_service.sign_in(method).await?;
            let session_id: Option<String> = match response {
                auth::AuthenticationResponse::OtpSent { session } => Some(session),
                _ => None,
            };

            // Request otp to aws sns.
            auth_service
                .request_otp_with_phonenumber(phone_number)
                .await?;

            session_id
        }
        _ => None,
    };

    if let Some(session_id) = session_id {
        let challenge_response = entities::auth::AuthenticationChallenge::new(&session_id, method);
        return Ok(Some(challenge_response));
    }

    Ok(None)
}
