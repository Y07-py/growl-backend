use std::sync::Arc;

use async_trait::async_trait;
use slog;

use crate::domain::interface::auth;

pub struct SNSService {
    sub_logger: slog::Logger,
}

impl SNSService {
    pub async fn new(root_logger: &slog::Logger) -> Arc<Self> {
        let sub_logger = root_logger.new(slog::o!("infra" => "sns"));

        slog::info!(sub_logger, "Initialize SNS Service.");

        Arc::new(Self { sub_logger })
    }

    pub fn sub_logger(&self) -> &slog::Logger {
        &self.sub_logger
    }
}

#[async_trait]
impl auth::OTPService for SNSService {
    fn validation_user_name(&self, user_name: &str) -> Result<(), auth::AuthenticationError> {
        // 1. Minimum length check
        if user_name.len() < 5 || user_name.len() > 16 {
            return Err(auth::AuthenticationError::InvalidFormat(
                "Phone number length is invalid".to_string(),
            ));
        }

        // 2. Must start with '+'
        if !user_name.starts_with('+') {
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
