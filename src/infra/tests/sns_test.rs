use std::sync::Arc;

use crate::domain::interface::auth::OTPService;
use crate::infra::services::sns::SNSService;
use slog::Logger;

async fn setup_sns_service() -> Arc<SNSService> {
    let drain = slog::Discard;
    let logger = Logger::root(drain, slog::o!());
    SNSService::new(&logger).await
}

#[tokio::test]
async fn test_valid_phone_numbers() {
    let service = setup_sns_service().await;
    let valid_numbers = vec!["+819012345678", "+12065550100", "+441234567890"];

    for num in valid_numbers {
        assert!(
            service.validation_user_name(num).is_ok(),
            "Expected phone number {} to be valid",
            num
        );
    }
}

#[tokio::test]
async fn test_invalid_phone_numbers() {
    let service = setup_sns_service().await;
    let invalid_cases = vec![
        ("", "empty string"),
        ("819012345678", "missing + prefix"),
        ("+81-90-1234-5678", "contains non-digits (hyphens)"),
        ("+81 90 1234 5678", "contains spaces"),
        ("+ABCDEFGHIJKL", "contains alphabets"),
    ];

    for (num, reason) in invalid_cases {
        let result = service.validation_user_name(num);
        assert!(
            result.is_err(),
            "Expected phone number '{}' to be invalid because {}",
            num,
            reason
        );
    }
}

#[tokio::test]
async fn test_phone_number_length() {
    let service = setup_sns_service().await;

    // Too short
    assert!(service.validation_user_name("+123").is_err());

    // Too long (over 16 chars including +)
    assert!(service.validation_user_name("+1234567890123456").is_err()); // 17 chars
}
