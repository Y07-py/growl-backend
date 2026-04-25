use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_cognitoidentityprovider as cognitio;
use base64::Engine;
use cognitio::error::SdkError;
use cognitio::types::{AttributeType, AuthFlowType, ChallengeNameType, MessageActionType};
use hmac::{self, KeyInit, Mac};
use jsonwebtoken;
use reqwest;
use sha2;

use crate::domain::entities::auth::{AuthenticationClaims, AuthenticationSession, UserIdentity};
use crate::domain::interface::auth::{
    AuthenticationError, AuthenticationMethod, AuthenticationResponse, AuthenticationService,
};
use crate::domain::values::auth::JwkSet;

pub struct CognitoAuthenticationService {
    client: cognitio::Client,
    client_id: String,
    client_secret: String,
    region: String,
    pool_id: String,
    logger: slog::Logger,
}

impl CognitoAuthenticationService {
    pub async fn new(root_logger: &slog::Logger) -> Arc<Self> {
        let sub_logger = root_logger.new(slog::o!("service" => "auth"));

        let config = aws_config::load_from_env().await;
        let client = cognitio::Client::new(&config);

        let client_id =
            std::env::var("AWS_COGNITIO_CLIENT_ID").expect("AWS_COGNITIO_CLIENT_ID must be set");
        let client_secret = std::env::var("AWS_COGNITIO_CLIENT_SECRET")
            .expect("AWS_COGNITIO_CLIENT_SECRET must be set");
        let region = std::env::var("AWS_COGNITIO_REGION").expect("AWS_COGNITIO_REGION must be set");
        let pool_id = std::env::var("AWS_COGNITIO_USER_POOL_ID")
            .expect("AWS_COGNITIO_USER_POOL_ID must be set");

        slog::info!(sub_logger, "Initialize Cognitio Authentication Service.");

        Arc::new(Self {
            client,
            client_id,
            client_secret,
            region,
            pool_id,
            logger: sub_logger,
        })
    }

    pub fn logger(&self) -> &slog::Logger {
        &self.logger
    }

    pub fn client_secret(&self) -> String {
        self.client_secret.clone()
    }

    pub fn client_id(&self) -> String {
        self.client_id.clone()
    }

    fn map_error<E>(&self, err: SdkError<E>) -> AuthenticationError
    where
        E: std::fmt::Debug,
    {
        eprintln!("Cognito SDK Error: {:?}", err);

        match err {
            SdkError::ServiceError(service_err) => {
                let err_str = format!("{:?}", service_err.err());

                if err_str.contains("NotAuthorizedException")
                    || err_str.contains("CodeMismatchException")
                    || err_str.contains("ExpiredCodeException")
                {
                    AuthenticationError::InvalidCredential
                } else if err_str.contains("UserNotFoundException") {
                    AuthenticationError::UserNotFound
                } else {
                    AuthenticationError::Unexpected(err_str)
                }
            }
            SdkError::DispatchFailure(_) | SdkError::TimeoutError(_) => {
                AuthenticationError::NetWorkError
            }
            _ => AuthenticationError::Unexpected(format!("{:?}", err)),
        }
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, AuthenticationError> {
        let endpoint = format!(
            "https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json",
            self.region, self.pool_id
        );

        let jwks = reqwest::get(endpoint)
            .await
            .map_err(|_| AuthenticationError::NetWorkError)?
            .json::<JwkSet>()
            .await
            .map_err(|e| {
                AuthenticationError::Unexpected(format!("Failed to parse JWKS: {:?}", e))
            })?;

        Ok(jwks)
    }

    async fn extract_sub_id_from_token(
        &self,
        id_token: &str,
    ) -> Result<String, AuthenticationError> {
        let header = jsonwebtoken::decode_header(id_token).map_err(|e| {
            AuthenticationError::Unexpected(format!("Failed to decode JWT header: {:?}", e))
        })?;

        let kid = header.kid.ok_or(AuthenticationError::InvalidCredential)?;
        let jwks = self.fetch_jwks().await?;

        let jwk = jwks
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or(AuthenticationError::InvalidCredential)?;

        let decoding_key =
            jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|_| {
                AuthenticationError::Unexpected("Failed to construct decoding key".into())
            })?;

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[&self.client_id]);
        let issuer = format!(
            "https://cognito-idp.{}.amazonaws.com/{}",
            self.region, self.pool_id
        );
        validation.set_issuer(&[issuer]);

        let token_data =
            jsonwebtoken::decode::<AuthenticationClaims>(id_token, &decoding_key, &validation)
                .map_err(|e| {
                    eprintln!("JWT validation failed: {:?}", e);
                    AuthenticationError::InvalidCredential
                })?;

        Ok(token_data.claims.sub_id())
    }

    /// Internal method to initiate a custom passwordless authentication flow (OTP request).
    async fn initiate_custom_auth(
        &self,
        username: &str,
    ) -> Result<AuthenticationResponse, AuthenticationError> {
        let request = self
            .client
            .initiate_auth()
            .auth_flow(AuthFlowType::CustomAuth)
            .client_id(&self.client_id)
            .auth_parameters("USERNAME", username)
            .auth_parameters("SECRET_HASH", self.compute_secret_hash(username));

        let output = request.send().await.map_err(|e| self.map_error(e))?;

        Ok(AuthenticationResponse::OtpSent {
            session: output.session.unwrap_or_default(),
        })
    }

    /// Internal method to respond to a custom auth challenge (OTP verification).
    async fn respond_to_custom_challenge(
        &self,
        username: &str,
        code: &str,
        auth_method: &str,
        session_id: Option<&str>,
    ) -> Result<AuthenticationResponse, AuthenticationError> {
        let output = self
            .client
            .respond_to_auth_challenge()
            .challenge_name(ChallengeNameType::CustomChallenge)
            .client_id(&self.client_id)
            .challenge_responses("USERNAME", username)
            .challenge_responses("ANSWER", code)
            .challenge_responses("SECRET_HASH", self.compute_secret_hash(username))
            .set_session(session_id.map(|s| s.to_string()))
            .send()
            .await
            .map_err(|e| self.map_error(e))?;

        let auth_result = output
            .authentication_result
            .ok_or(AuthenticationError::InvalidCredential)?;

        let id_token = auth_result
            .id_token
            .clone()
            .ok_or(AuthenticationError::InvalidCredential)?;
        let sub_id = self.extract_sub_id_from_token(&id_token).await?;

        let user = UserIdentity::new(
            sub_id,
            if auth_method == "email" {
                username.to_string()
            } else {
                "".to_string()
            },
            if auth_method == "phone_number" {
                username.to_string()
            } else {
                "".to_string()
            },
            auth_method.to_string(),
            "authenticated".to_string(),
        );

        let session = AuthenticationSession::new(
            user,
            auth_result.access_token.unwrap_or_default(),
            auth_result.id_token.unwrap_or_default(),
            auth_result.refresh_token,
            auth_result.expires_in,
        );

        Ok(AuthenticationResponse::Authenticated(session))
    }

    /// Internal method to create a user using AdminCreateUser API without password.
    async fn admin_create_custom_user(
        &self,
        username: &str,
        is_email: bool,
    ) -> Result<UserIdentity, AuthenticationError> {
        let attr_name = if is_email { "email" } else { "phone_number" };
        let verified_attr_name = if is_email {
            "email_verified"
        } else {
            "phone_number_verified"
        };

        let user_attr = AttributeType::builder()
            .name(attr_name)
            .value(username)
            .build()
            .unwrap();

        let verified_attr = AttributeType::builder()
            .name(verified_attr_name)
            .value("true")
            .build()
            .unwrap();

        let output = self
            .client
            .admin_create_user()
            .user_pool_id(&self.pool_id)
            .username(username)
            .user_attributes(user_attr)
            .user_attributes(verified_attr)
            .message_action(MessageActionType::Suppress)
            .send()
            .await
            .map_err(|e| self.map_error(e))?;

        let user_data = output.user.ok_or(AuthenticationError::Unexpected(
            "User creation failed".into(),
        ))?;

        // Extract `sub` attributes from user_data
        let sub_id = user_data
            .attributes()
            .iter()
            .find(|attr| attr.name() == "sub")
            .and_then(|attr| attr.value())
            .unwrap_or_default()
            .to_string();

        Ok(UserIdentity::new(
            sub_id,
            if is_email {
                username.to_string()
            } else {
                "".to_string()
            },
            if !is_email {
                username.to_string()
            } else {
                "".to_string()
            },
            "AdminCreate".into(),
            "guest".into(),
        ))
    }

    fn compute_secret_hash(&self, user_name: &str) -> String {
        type Hmac256 = hmac::Hmac<sha2::Sha256>;
        let mut mac = Hmac256::new_from_slice(self.client_secret().as_bytes())
            .expect("HMAC can take key of any size");

        // Injection client id and user_name
        mac.update(user_name.as_bytes());
        mac.update(self.client_id().as_bytes());

        // Compute with sha256
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        base64::engine::general_purpose::STANDARD.encode(code_bytes)
    }
}

#[async_trait]
impl AuthenticationService for CognitoAuthenticationService {
    async fn sign_out(&self, session: &AuthenticationSession) -> Result<(), AuthenticationError> {
        // Sign out of all sessions regardless of device.
        self.client
            .global_sign_out()
            .access_token(session.access_token())
            .send()
            .await
            .map_err(|e| self.map_error(e))?;
        Ok(())
    }

    async fn sign_in(
        &self,
        method: &AuthenticationMethod,
    ) -> Result<AuthenticationResponse, AuthenticationError> {
        match method {
            AuthenticationMethod::Email {
                email,
                otp,
                session_id,
            } => match otp {
                None => self.initiate_custom_auth(email).await,
                Some(code) => {
                    self.respond_to_custom_challenge(email, code, "email", session_id.as_deref())
                        .await
                }
            },
            AuthenticationMethod::PhoneNumber {
                phone_number,
                otp,
                session_id,
            } => match otp {
                None => self.initiate_custom_auth(phone_number).await,
                Some(code) => {
                    self.respond_to_custom_challenge(
                        phone_number,
                        code,
                        "phone_number",
                        session_id.as_deref(),
                    )
                    .await
                }
            },
            AuthenticationMethod::Google { id_token: _ }
            | AuthenticationMethod::Apple { id_token: _ } => Err(AuthenticationError::Unexpected(
                "Social login not yet implemented".into(),
            )),
        }
    }

    async fn sign_up(
        &self,
        method: &AuthenticationMethod,
    ) -> Result<UserIdentity, AuthenticationError> {
        match method {
            AuthenticationMethod::Email { email, .. } => {
                self.admin_create_custom_user(email, true).await
            }
            AuthenticationMethod::PhoneNumber { phone_number, .. } => {
                self.admin_create_custom_user(phone_number, false).await
            }
            _ => Err(AuthenticationError::Unexpected(
                "Method not supported for sign_up".into(),
            )),
        }
    }

    async fn refresh_token(
        &self,
        session: &AuthenticationSession,
    ) -> Result<AuthenticationSession, AuthenticationError> {
        let refresh_token_opt = session.refresh_token();
        let refresh_token = refresh_token_opt
            .as_ref()
            .ok_or(AuthenticationError::InvalidCredential)?;

        let output = self
            .client
            .initiate_auth()
            .auth_flow(AuthFlowType::RefreshTokenAuth)
            .client_id(&self.client_id)
            .auth_parameters("REFRESH_TOKEN", refresh_token)
            .auth_parameters(
                "SECRET_HASH",
                self.compute_secret_hash(&session.identity().sub_id),
            )
            .send()
            .await
            .map_err(|e| self.map_error(e))?;

        let auth_result = output
            .authentication_result()
            .ok_or(AuthenticationError::InvalidCredential)?;

        Ok(AuthenticationSession::new(
            session.identity(),
            auth_result.access_token().unwrap_or_default().to_string(),
            auth_result.id_token().unwrap_or_default().to_string(),
            Some(auth_result.refresh_token().unwrap_or_default().to_string()),
            auth_result.expires_in(),
        ))
    }
}
