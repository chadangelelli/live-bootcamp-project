use color_eyre::eyre::{eyre, Result};
use core::fmt;

use thiserror::Error;

use email_address::EmailAddress;

#[derive(Debug, Error)]
pub enum EmailError {
    #[error("Email cannot be empty")]
    EmptyEmail,
    #[error("Email format is invalid")]
    InvalidFormat,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Self> {
        let email = email.trim().to_string();

        if email.is_empty() {
            Err(eyre!(EmailError::EmptyEmail))
        } else if !EmailAddress::is_valid(&email) {
            Err(eyre!(EmailError::InvalidFormat))
        } else {
            Ok(Email(email))
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for Email {
    fn from(s: String) -> Self {
        Email::parse(s).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::Email;

    #[tokio::test]
    async fn test_parse_valid_email() {
        let valid_emails = vec![
            "email@example.com",
            "firstname.lastname@example.com",
            "email@subdomain.example.com",
            "firstname+lastname@example.com",
            "email@123.123.123.123",
            "email@[123.123.123.123]",
            "1234567890@example.com",
            "email@example-one.com",
            "_______@example.com",
            "email@example.name",
            "email@example.museum",
            "email@example.co.jp",
            "firstname-lastname@example.com",
            "Joe Smith <email@example.com>",
            "あいうえお@example.com",
        ];

        for email in valid_emails {
            let parsed_email = Email::parse(email.to_string());
            assert!(
                parsed_email.is_ok(),
                "Failed to parse valid email: {}",
                email
            );
            assert_eq!(parsed_email.unwrap().as_ref(), email);
        }
    }

    #[tokio::test]
    async fn test_parse_invalid_email() {
        let invalid_emails = vec![
            "plainaddress",
            "#@%^%#$@#$@#.com",
            "@example.com",
            "email.example.com",
            "email@example@example.com",
            ".email@example.com",
            "email.@example.com",
            "email..email@example.com",
            "email@example.com (Joe Smith)",
            "email@-example.com",
            "email@example..com",
            "Abc..123@example.com",
        ];

        for email in invalid_emails {
            let parsed_email = Email::parse(email.to_string());
            assert!(
                parsed_email.is_err(),
                "Parsed invalid email as valid: {}",
                email
            );
        }

        let empty_email = Email::parse("".to_string());
        assert!(empty_email.is_err());
        // assert_eq!(empty_email.unwrap_err(), EmailError::EmptyEmail);
    }
}
