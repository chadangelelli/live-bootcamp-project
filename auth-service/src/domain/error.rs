use color_eyre::eyre::Report;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthApiError {
    #[error("Incorrect credentials")]
    IncorrectCredentials,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Missing token")]
    MissingToken,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
    #[error("User already exists")]
    UserAlreadyExists,
}
