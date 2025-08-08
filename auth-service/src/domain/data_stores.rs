use thiserror::Error;

use super::User;
use crate::domain::{Email, Password};

#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<&User, UserStoreError>;
    async fn user_exists(&self, email: &Email) -> bool;
    async fn validate_user(&self, email: &Email, password: &Password)
        -> Result<(), UserStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[async_trait::async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn get_token(&self, token: &str) -> Option<&String>;
    fn token_exists(&self, token: &str) -> bool;
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
