use std::hash::Hash;

use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

use thiserror::Error;

use email_address::EmailAddress;

#[derive(Debug, Error)]
pub enum EmailError {
    #[error("Email cannot be empty")]
    EmptyEmail,
    #[error("Email format is invalid")]
    InvalidFormat,
}

#[derive(Clone, Debug)]
pub struct Email(Secret<String>);

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Eq for Email {}

impl Email {
    pub fn parse(email: Secret<String>) -> Result<Self> {
        let email_str = email.expose_secret().trim().to_string();

        if email_str.is_empty() {
            Err(eyre!(EmailError::EmptyEmail))
        } else if !EmailAddress::is_valid(&email_str) {
            Err(eyre!(EmailError::InvalidFormat))
        } else {
            Ok(Email(email))
        }
    }
}

impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

impl From<String> for Email {
    fn from(s: String) -> Self {
        Email::parse(Secret::new(s)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret, Secret};

    use super::Email;

    #[tokio::test]
    async fn test_parse_valid_email() {
        let valid_emails = vec![
            "email@example.com".to_string(),
            "firstname.lastname@example.com".to_string(),
            "email@subdomain.example.com".to_string(),
            "firstname+lastname@example.com".to_string(),
            "email@123.123.123.123".to_string(),
            "email@[123.123.123.123]".to_string(),
            "1234567890@example.com".to_string(),
            "email@example-one.com".to_string(),
            "_______@example.com".to_string(),
            "email@example.name".to_string(),
            "email@example.museum".to_string(),
            "email@example.co.jp".to_string(),
            "firstname-lastname@example.com".to_string(),
            "Joe Smith <email@example.com>".to_string(),
            "あいうえお@example.com".to_string(),
        ];

        for email in valid_emails {
            let parsed_email = Email::parse(Secret::new(email.clone())).unwrap();
            assert_eq!(parsed_email.as_ref().expose_secret(), &email);
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
            let parsed_email = Email::parse(Secret::new(email.to_string()));
            assert!(
                parsed_email.is_err(),
                "Parsed invalid email as valid: {}",
                email
            );
        }

        let empty_email = Email::parse(Secret::new("".to_string()));
        assert!(empty_email.is_err());
        // assert_eq!(empty_email.unwrap_err(), EmailError::EmptyEmail);
    }
}
