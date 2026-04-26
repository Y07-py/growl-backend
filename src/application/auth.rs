use crate::domain::entities;
use crate::domain::interface::{auth, repository};

/// Handles the sign-up process for a new user or a guest user.
/// If the user does not exist, it registers them as a guest user in the database
/// and initiates an OTP (One-Time Password) challenge based on the provided authentication method.
pub async fn sign_up(
    auth_service: &(dyn auth::AuthenticationService + Send + Sync),
    repo: &(dyn repository::AuthenticationRepository + Send + Sync),
    otp_service: &(dyn auth::OTPService + Send + Sync),
    method: &auth::AuthenticationMethod,
) -> Result<Option<entities::auth::AuthenticationChallenge>, Box<dyn std::error::Error + Send + Sync>>
{
    if !already_exist_user(method, repo).await? {
        // 1. sign up with guest user.
        let guest = auth_service.sign_up(method).await?;
        // 2. insert guest user in DB, if not exist.
        repo.insert_guest_user(&guest).await?;
    }

    // 3.Request transimission OTP based on the method.
    let session_id: Option<String> = match method {
        auth::AuthenticationMethod::Email { email, .. } => {
            // Validation email format.
            otp_service.validation_user_name(email)?;
            // Generate session id via sign in.
            let response = auth_service.sign_in(method).await?;
            let session_id: Option<String> = match response {
                auth::AuthenticationResponse::OtpSent { session } => Some(session),
                _ => None,
            };

            session_id
        }
        auth::AuthenticationMethod::PhoneNumber { phone_number, .. } => {
            // Validation phone number format.
            otp_service.validation_user_name(phone_number)?;
            // Generate session id via sign in.
            let response = auth_service.sign_in(method).await?;
            let session_id: Option<String> = match response {
                auth::AuthenticationResponse::OtpSent { session } => Some(session),
                _ => None,
            };

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

/// Performs the sign-in process by verifying the authentication method.
/// For email and phone number methods, it expects an OTP and session ID.
/// If authentication is successful, it returns an AuthenticationSession.
pub async fn sign_in(
    auth_service: &(dyn auth::AuthenticationService + Send + Sync),
    method: &auth::AuthenticationMethod,
) -> Result<Option<entities::auth::AuthenticationSession>, Box<dyn std::error::Error + Send + Sync>>
{
    // Validation method.
    match method {
        auth::AuthenticationMethod::Email {
            otp, session_id, ..
        }
        | auth::AuthenticationMethod::PhoneNumber {
            otp, session_id, ..
        } => {
            if otp.is_none() || session_id.is_none() {
                return Ok(None);
            }
        }
        _ => {}
    }

    let response = auth_service.sign_in(method).await?;

    match response {
        auth::AuthenticationResponse::Authenticated(session) => Ok(Some(session)),
        _ => Ok(None),
    }
}

/// Checks if a user already exists in the system based on the provided authentication method
/// (e.g., email or phone number).
async fn already_exist_user(
    method: &auth::AuthenticationMethod,
    repo: &(dyn repository::AuthenticationRepository + Send + Sync),
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let identity = repo.find_user_by_username(method).await?;
    Ok(identity.is_some())
}

/// Retrieves the login status and identity information for a user with a specific sub_id.
/// Returns the user identity only if the user has an 'authenticated' role.
pub async fn get_login_status(
    repo: &(dyn repository::AuthenticationRepository + Send + Sync),
    sub_id: &str,
) -> Result<Option<entities::auth::UserIdentity>, sqlx::Error> {
    let user = repo.find_user_by_sub_id(sub_id).await?;
    if let Some(user) = user {
        if user.role == "authenticated" {
            return Ok(Some(user));
        }
    }
    Ok(None)
}
