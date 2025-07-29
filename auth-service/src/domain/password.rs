use core::fmt;

use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum PasswordError {
    #[error("Password cannot be empty")]
    EmptyPassword,
    #[error("Password must be at least 8 characters long")]
    TooShort,
    #[error("Password must contain at least one digit")]
    MissingDigit,
    #[error("Password must contain at least one lowercase letter")]
    MissingLowercase,
    #[error("Password must contain at least one uppercase letter")]
    MissingUppercase,
    #[error("Password must contain at least one special character")]
    MissingSpecialCharacter,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Self, PasswordError> {
        let password = password.trim().to_string();

        if password.is_empty() {
            Err(PasswordError::EmptyPassword)
        } else if password.chars().count() < 8 {
            Err(PasswordError::TooShort)
        } else if !password.chars().any(|c| c.is_lowercase()) {
            Err(PasswordError::MissingLowercase)
        } else if !password.chars().any(|c| c.is_uppercase()) {
            Err(PasswordError::MissingUppercase)
        } else if !password.chars().any(|c| c.is_digit(10)) {
            Err(PasswordError::MissingDigit)
        } else if !password.chars().any(|c| !c.is_alphanumeric()) {
            Err(PasswordError::MissingSpecialCharacter)
        } else {
            Ok(Password(password))
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_valid_password() {
        let valid_passwords = vec!["Valid1@Password", "AnotherValid2#Password"];

        for password in valid_passwords {
            let result = Password::parse(password.to_string());
            assert!(
                result.is_ok(),
                "Failed to parse valid password: {}",
                password
            );
        }
    }

    #[tokio::test]
    async fn test_parse_invalid_passwords() {
        let invalid_passwords = vec![
            "",
            "short",
            "NoDigits@Password",
            "nouppercase1@",
            "NOLOWERCASE1@",
            "NoSpecialChar1",
        ];

        for password in invalid_passwords {
            let result = Password::parse(password.to_string());
            assert!(
                result.is_err(),
                "Expected error for invalid password: {}",
                password
            );
        }
    }
}
