pub enum AuthApiError {
    UserAlreadyExists,
    Unauthorized,
    InvalidCredentials,
    IncorrectCredentials,
    InvalidToken,
    MissingToken,
    UnexpectedError,
}
