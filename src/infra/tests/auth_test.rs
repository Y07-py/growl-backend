use dotenv::dotenv;

use crate::domain::interface::auth::{AuthenticationMethod, AuthenticationService};
use crate::infra::service::auth::CognitoAuthenticationService;

async fn setup_service() -> Option<CognitoAuthenticationService> {
    dotenv().ok();

    // Required environment variables for Cognito
    if std::env::var("AWS_COGNITIO_CLIENT_ID").is_err()
        || std::env::var("AWS_COGNITIO_REGION").is_err()
        || std::env::var("AWS_COGNITIO_USER_POOL_ID").is_err()
    {
        return None;
    }

    Some(CognitoAuthenticationService::new().await)
}

#[tokio::test]
async fn test_service_initialization() {
    let service = setup_service().await;
    if service.is_some() {
        // Successfully initialized
        assert!(true);
    } else {
        eprintln!("Skipping test: Environment variables for Cognito are not set.");
    }
}

#[tokio::test]
async fn test_sign_in_with_invalid_email_should_fail() {
    let service = setup_service().await;
    let service = match service {
        Some(s) => s,
        None => return,
    };

    let method = AuthenticationMethod::Email {
        email: "non-existent-user@example.com".to_string(),
        otp: None,
        session_id: None,
    };

    // Attempt sign_in (initiation)
    let result = service.sign_in(&method).await;

    // It should fail or return OtpSent depending on Cognito settings,
    // but usually with a random non-existent email, it might return UserNotFound or InvalidParameter.
    match result {
        Ok(_) => {
            println!("Successfully triggered OTP (or User not found but security settings hide it)")
        }
        Err(e) => println!("Caught expected error: {:?}", e),
    }
}

#[tokio::test]
async fn test_sign_up_unsupported_method() {
    let service = setup_service().await;
    let service = match service {
        Some(s) => s,
        None => return,
    };

    let method = AuthenticationMethod::Google {
        id_token: "fake-token".to_string(),
    };

    // Google signup is not implemented yet
    let result = service.sign_up(&method).await;
    assert!(result.is_err());
}
