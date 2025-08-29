use color_eyre::eyre::{eyre, Context, Report, Result};
use lazy_static::lazy_static;
use regex::Regex;
use secrecy::{ExposeSecret, Secret};
use thiserror::Error;
use uuid::Uuid;

use super::User;
use crate::domain::{Email, Password};

#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn user_exists(&self, email: &Email) -> bool;
    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<User, UserStoreError>;
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error. Please try again.")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn add_token(&mut self, token: Secret<String>) -> Result<()>;
    async fn get_token(&self, token: &str) -> Option<&String>;
    async fn token_exists(&self, token: &Secret<String>) -> bool;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Invalid token")]
    InvalidToken,
    #[error("Token already exists in banned token store")]
    TokenAlreadyExists,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for BannedTokenStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::InvalidToken, Self::InvalidToken)
                | (Self::TokenAlreadyExists, Self::TokenAlreadyExists)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(Secret<String>);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self> {
        let parsed_id = Uuid::parse_str(&id).wrap_err("Invalid login attempt id")?;
        Ok(Self(Secret::new(parsed_id.to_string())))
    }

    // Alias to LoginAttemptId::default()
    pub fn generate_random() -> Self {
        LoginAttemptId::default()
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(Secret::new(Uuid::new_v4().to_string()))
    }
}

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl AsRef<Secret<String>> for LoginAttemptId {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct TwoFACode(Secret<String>);

lazy_static! {
    static ref TWO_FA_CODE_REGEX: Regex = Regex::new(r"^\d{6}$").unwrap();
}

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}
/// `code` is a valid 6-digit String
impl TwoFACode {
    pub fn parse(code: String) -> Result<Self> {
        if TWO_FA_CODE_REGEX.is_match(&code) {
            Ok(Self(Secret::new(code)))
        } else {
            Err(eyre!("Invalid 2FA code"))
        }
    }

    // Alias to TwoFACode::default()
    pub fn generate_random() -> Self {
        TwoFACode::default()
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        let mut range = rand::thread_rng();
        let code = rand::Rng::gen_range(&mut range, 100_000..=999_999);
        Self(Secret::new(code.to_string()))
    }
}

impl AsRef<Secret<String>> for TwoFACode {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}
