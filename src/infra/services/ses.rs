use std::sync::Arc;

use async_trait::async_trait;
use slog;

use crate::domain::interface::auth;

pub struct SESService {
    sub_logger: slog::Logger,
}

impl SESService {
    pub async fn new(root_logger: &slog::Logger) -> Arc<Self> {
        let sub_logger = root_logger.new(slog::o!("infra" => "ses"));

        slog::info!(sub_logger, "Initialize SES Service.");

        Arc::new(Self { sub_logger })
    }

    pub fn sub_logger(&self) -> &slog::Logger {
        &self.sub_logger
    }
}

#[async_trait]
impl auth::OTPService for SESService {
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
