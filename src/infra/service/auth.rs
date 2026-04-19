use async_trait::async_trait;
use aws_sdk_cognitoidentityprovider as cognitio;
use cognitio::error::SdkError;
use cognitio::types::{AuthFlowType, ChallengeNameType};
use jsonwebtoken;
use reqwest;

use crate::domain::entities::auth::{
    AuthenticationClaims, AuthenticationSession, AuthenticationUser,
};
use crate::domain::interface::auth::{
    AuthenticationError, AuthenticationMethod, AuthenticationResponse, AuthenticationService,
};
use crate::domain::values::auth::JwkSet;

pub struct CognitoAuthenticationService {
    client: cognitio::Client,
    client_id: String,
    region: String,
    pool_id: String,
}

impl CognitoAuthenticationService {
    pub async fn new() -> Self {
        let config = aws_config::load_from_env().await;
        let client = cognitio::Client::new(&config);

        let client_id =
            std::env::var("AWS_COGNITIO_CLIENT_ID").expect("AWS_COGNITIO_CLIENT_ID must be set");
        let region = std::env::var("AWS_COGNITIO_REGION").expect("AWS_COGNITIO_REGION must be set");
        let pool_id = std::env::var("AWS_COGNITIO_USER_POOL_ID")
            .expect("AWS_COGNITIO_USER_POOL_ID must be set");

        Self {
            client,
            client_id,
            region,
            pool_id,
        }
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
        let output = self
            .client
            .initiate_auth()
            .auth_flow(AuthFlowType::CustomAuth)
            .client_id(&self.client_id)
            .auth_parameters("USERNAME", username)
            .send()
            .await
            .map_err(|e| self.map_error(e))?;

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
        session: Option<&str>,
    ) -> Result<AuthenticationResponse, AuthenticationError> {
        let output = self
            .client
            .respond_to_auth_challenge()
            .challenge_name(ChallengeNameType::CustomChallenge)
            .client_id(&self.client_id)
            .challenge_responses("USERNAME", username)
            .challenge_responses("ANSWER", code)
            .set_session(session.map(|s| s.to_string()))
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

        let user = AuthenticationUser::new(
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
}

#[async_trait]
impl AuthenticationService for CognitoAuthenticationService {
    async fn sign_out(&self) -> Result<(), AuthenticationError> {
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
                session,
            } => match otp {
                None => self.initiate_custom_auth(email).await,
                Some(code) => {
                    self.respond_to_custom_challenge(email, code, "email", session.as_deref())
                        .await
                }
            },
            AuthenticationMethod::PhoneNumber {
                phone_number,
                otp,
                session,
            } => match otp {
                None => self.initiate_custom_auth(phone_number).await,
                Some(code) => {
                    self.respond_to_custom_challenge(
                        phone_number,
                        code,
                        "phone_number",
                        session.as_deref(),
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
    ) -> Result<AuthenticationUser, AuthenticationError> {
        match method {
            AuthenticationMethod::Email { email, .. } => {
                self.client
                    .sign_up()
                    .client_id(&self.client_id)
                    .username(email)
                    .password("TempPassword123!".to_string())
                    .send()
                    .await
                    .map_err(|e| self.map_error(e))?;

                Ok(AuthenticationUser::new(
                    "pending".into(),
                    email.clone(),
                    "".into(),
                    "Email".into(),
                    "User".into(),
                ))
            }
            _ => Err(AuthenticationError::Unexpected(
                "Only Email sign_up is currently supported".into(),
            )),
        }
    }
}
