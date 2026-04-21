use async_trait::async_trait;
use aws_config;
use aws_sdk_sns;
use slog;

use crate::domain::interface::auth;

pub struct SMSService {
    client: aws_sdk_sns::Client,
    sub_logger: slog::Logger,
}

impl SMSService {
    pub async fn new(root_logger: &slog::Logger) -> Self {
        let config = aws_config::load_from_env().await;
        let client = aws_sdk_sns::Client::new(&config);

        let sub_logger = root_logger.new(slog::o!("infra" => "sms"));

        Self { client, sub_logger }
    }
}

#[async_trait]
impl auth::OTPService for SMSService {
    async fn request_otp(&self, user_name: &str) -> Result<(), auth::AuthenticationError> {
        let sub_logger = self
            .sub_logger
            .new(slog::o!("method" => "request_otp", "user_name" => user_name.to_string()));
        slog::info!(sub_logger, "Initiating OTP request forwarding to email");

        // Identify the application source for better traceability.
        let app_name = std::env::var("APP_NAME").unwrap_or_else(|_| "GROWL".to_string());

        // Prepare the message for email forwarding.
        let message = format!(
            "[{}] OTP request received for identifier: {}. Please verify the identity if needed.",
            app_name, user_name
        );

        // Fetch the SNS Topic ARN from environment variables.
        let topic_arn = std::env::var("AWS_SNS_TOPIC_ARN").map_err(|_| {
            slog::error!(
                sub_logger,
                "AWS_SNS_TOPIC_ARN is not set for email forwarding"
            );
            auth::AuthenticationError::Unexpected("Forwarding configuration missing".into())
        })?;

        // Publish to SNS Topic to "forward" the information to email.
        self.client
            .publish()
            .topic_arn(topic_arn)
            .message(message)
            .subject(format!("[{}] OTP Forwarding Notification", app_name))
            .send()
            .await
            .map_err(|e| {
                slog::error!(sub_logger, "Failed to forward notification via SNS"; "error" => ?e);
                auth::AuthenticationError::NetWorkError
            })?;

        slog::info!(
            sub_logger,
            "Successfully forwarded OTP request information to email"
        );

        Ok(())
    }
}
