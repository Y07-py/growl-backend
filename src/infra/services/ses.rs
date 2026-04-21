use async_trait::async_trait;
use aws_config;
use aws_sdk_ses;
use slog;

use crate::domain::interface::auth;

pub struct SESService {
    client: aws_sdk_ses::Client,
    sub_logger: slog::Logger,
}

impl SESService {
    pub async fn new(root_logger: &slog::Logger) -> Self {
        let config = aws_config::load_from_env().await;
        let client = aws_sdk_ses::Client::new(&config);

        let sub_logger = root_logger.new(slog::o!("infra" => "ses"));

        Self { client, sub_logger }
    }
}

#[async_trait]
impl auth::OTPService for SESService {
    async fn request_otp(&self, user_name: &str) -> Result<(), auth::AuthenticationError> {
        let sub_logger = self
            .sub_logger
            .new(slog::o!("method" => "request_otp", "email" => user_name.to_string()));
        slog::info!(sub_logger, "Initiating OTP delivery via AWS SES");

        // Identify the application source for better traceability.
        let app_name = std::env::var("APP_NAME").unwrap_or_else(|_| "GROWL".to_string());

        // The source email must be a verified identity in AWS SES.
        let source_email =
            std::env::var("SES_SOURCE_EMAIL").unwrap_or_else(|_| "no-reply@growl.com".to_string());

        let subject = format!("[{}] Verification Code", app_name);
        let body = format!(
            "Your verification request for {} has been received. Identifier: {}",
            app_name, user_name
        );

        // Build the email structure for SES.
        let dest = aws_sdk_ses::types::Destination::builder()
            .to_addresses(user_name)
            .build();

        let subject_content = aws_sdk_ses::types::Content::builder()
            .data(subject)
            .build()
            .map_err(|e| {
                auth::AuthenticationError::Unexpected(format!("Failed to build subject: {:?}", e))
            })?;

        let body_content = aws_sdk_ses::types::Content::builder()
            .data(body)
            .build()
            .map_err(|e| {
                auth::AuthenticationError::Unexpected(format!("Failed to build body: {:?}", e))
            })?;

        let ses_body = aws_sdk_ses::types::Body::builder()
            .text(body_content)
            .build();

        let msg = aws_sdk_ses::types::Message::builder()
            .subject(subject_content)
            .body(ses_body)
            .build();

        // Send the email directly to the user's email address.
        self.client
            .send_email()
            .source(source_email)
            .destination(dest)
            .message(msg)
            .send()
            .await
            .map_err(|e| {
                slog::error!(sub_logger, "Failed to send email via SES"; "error" => ?e);
                auth::AuthenticationError::NetWorkError
            })?;

        slog::info!(sub_logger, "Successfully sent OTP email via SES");

        Ok(())
    }

    fn validation_user_name(&self, user_name: &str) -> Result<(), auth::AuthenticationError> {
        // 1. Basic length check
        if user_name.len() < 3 || user_name.len() > 254 {
            return Err(auth::AuthenticationError::InvalidFormat(
                "Email length is invalid".to_string(),
            ));
        }

        // 2. Space check
        if user_name.contains(' ') {
            return Err(auth::AuthenticationError::InvalidFormat(
                "Email cannot contain spaces".to_string(),
            ));
        }

        // 3. Simple '@' and split check
        let parts: Vec<&str> = user_name.split('@').collect();
        if parts.len() != 2 {
            return Err(auth::AuthenticationError::InvalidFormat(
                "Email must contain exactly one '@'".to_string(),
            ));
        }

        let local_part = parts[0];
        let domain_part = parts[1];

        // 4. Local and Domain and existance.
        if local_part.is_empty() || domain_part.is_empty() {
            return Err(auth::AuthenticationError::InvalidFormat(
                "Email local or domain parts is empty".to_string(),
            ));
        }

        // 5. Dot in domain.
        if !domain_part.contains('.') {
            return Err(auth::AuthenticationError::InvalidFormat(
                "Email domain must contain a dot.".to_string(),
            ));
        }

        Ok(())
    }
}
