use core::fmt;

use color_eyre::eyre::Report;
use lazy_static::lazy_static;
use rand::Rng;
use regex::Regex;
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
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn get_token(&self, token: &str) -> Option<&String>;
    async fn token_exists(&self, token: &str) -> bool;
}

#[derive(Debug, Error, PartialEq)]
pub enum BannedTokenStoreError {
    #[error("Invalid token")]
    InvalidToken,
    #[error("Token already exists in banned token store")]
    TokenAlreadyExists,
    #[error("Unexpected error. Please try again.")]
    UnexpectedError,
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

#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    LoginAttemptIdNotFound,
    UnexpectedError,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(pub String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self, String> {
        Uuid::parse_str(&id)
            .map(|uuid| Self(uuid.to_string()))
            .map_err(|_| "Invalid UUID".into())
    }

    // Alias to LoginAttemptId::default()
    pub fn generate_random() -> Self {
        LoginAttemptId(Uuid::new_v4().to_string())
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        LoginAttemptId(Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LoginAttemptId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LoginAttemptId: {}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(pub String);

lazy_static! {
    static ref TWO_FA_CODE_REGEX: Regex = Regex::new(r"^\d{6}$").unwrap();
}

/// `code` is a valid 6-digit String
impl TwoFACode {
    pub fn parse(code: String) -> Result<Self, String> {
        if TWO_FA_CODE_REGEX.is_match(&code) {
            Ok(Self(code))
        } else {
            Err("Invalid 2FA code".into())
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
        Self(code.to_string())
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
