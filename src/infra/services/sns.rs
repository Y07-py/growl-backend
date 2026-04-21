use async_trait::async_trait;
use aws_config;
use aws_sdk_sns;
use slog;

use crate::domain::interface::auth;

pub struct SNSService {
    client: aws_sdk_sns::Client,
    sub_logger: slog::Logger,
}

impl SNSService {
    pub async fn new(root_logger: &slog::Logger) -> Self {
        let sub_logger = root_logger.new(slog::o!("infra" => "sns"));

        let config = aws_config::load_from_env().await;
        let client = aws_sdk_sns::Client::new(&config);

        Self { client, sub_logger }
    }
}

#[async_trait]
impl auth::OTPService for SNSService {
    async fn request_otp(&self, user_name: &str) -> Result<(), auth::AuthenticationError> {
        let sub_logger = self
            .sub_logger
            .new(slog::o!("method" => "request_otp", "phone_number" => user_name.to_string()));

        slog::info!(sub_logger, "Initiating OTP request to phone number via SNS");

        // Identify the application source.
        let app_name = std::env::var("APP_NAME").unwrap_or_else(|_| "GROWL".to_string());

        // Prepare the SMS message.
        let message = format!(
            "[{}] Your verification request for {} has been received.",
            app_name, user_name
        );

        // Send real SMS via SNS direct publish to phone number.
        self.client
            .publish()
            .phone_number(user_name)
            .message(message)
            .send()
            .await
            .map_err(|e| {
                slog::error!(sub_logger, "Failed to send SMS via SNS"; "error" => ?e);
                auth::AuthenticationError::NetWorkError
            })?;

        slog::info!(sub_logger, "Successfully sent OTP message via SNS");

        Ok(())
    }

    fn validation_user_name(&self, user_name: &str) -> Result<(), auth::AuthenticationError> {
        // 1. Minimum length check
        if user_name.len() < 5 || user_name.len() > 16 {
            return Err(auth::AuthenticationError::InvalidFormat(
                "Phone number length is invalid".to_string(),
            ));
        }

        // 2. Must start with '+'
        if user_name.starts_with('+') {
            return Err(auth::AuthenticationError::InvalidFormat(
                "Phone number must start with '+' (E.164 format)".to_string(),
            ));
        }

        // 3. Rest must be digits.
        if !user_name[1..].chars().all(|c| c.is_ascii_digit()) {
            return Err(auth::AuthenticationError::InvalidFormat(
                "Phone number must contain only digits after '+'".to_string(),
            ));
        }

        Ok(())
    }
}
