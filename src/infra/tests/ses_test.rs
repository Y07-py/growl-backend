use std::sync::Arc;

use crate::domain::interface::auth::OTPService;
use crate::infra::services::ses::SESService;
use slog::Logger;

async fn setup_ses_service() -> Arc<SESService> {
    let drain = slog::Discard;
    let logger = Logger::root(drain, slog::o!());
    SESService::new(&logger).await
}

#[tokio::test]
async fn test_valid_emails() {
    let service = setup_ses_service().await;
    let valid_emails = vec![
        "test@example.com",
        "user.name@domain.co.jp",
        "a@b.c",
        "someone+label@gmail.com",
    ];

    for email in valid_emails {
        assert!(
            service.validation_user_name(email).is_ok(),
            "Expected email {} to be valid",
            email
        );
    }
}

#[tokio::test]
async fn test_invalid_emails() {
    let service = setup_ses_service().await;
    let invalid_cases = vec![
        ("", "empty string"),
        ("noat.example.com", "missing @"),
        ("too@many@ats.com", "multiple @"),
        ("@no-local.com", "missing local part"),
        ("no-domain@", "missing domain part"),
        ("no-dot@domain", "missing dot in domain"),
        ("has space@example.com", "contains space"),
        ("a@b", "no dot in domain"),
    ];

    for (email, reason) in invalid_cases {
        let result = service.validation_user_name(email);
        assert!(
            result.is_err(),
            "Expected email '{}' to be invalid because {}",
            email,
            reason
        );
    }
}

#[tokio::test]
async fn test_email_length() {
    let service = setup_ses_service().await;

    // Too short
    assert!(service.validation_user_name("a@").is_err());

    // Too long (over 254 chars)
    let long_domain = "a".repeat(250) + ".com";
    let long_email = format!("test@{}", long_domain);
    assert!(service.validation_user_name(&long_email).is_err());
}
