use color_eyre::eyre::{eyre, Result};
use lazy_static::lazy_static;
use regex::Regex;
use secrecy::{ExposeSecret, Secret};
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
    #[error("Hash passed without allow_hash flag")]
    HashWithoutAllowFlag,
}

lazy_static! {
    pub static ref ARGON2_REGEX: Regex =
        Regex::new(r"^\$argon2i\$v=19\$m=65536,t=4,p=1\$.{22}\$.{43}$").unwrap();
}

#[derive(Clone, Debug)]
pub struct Password(Secret<String>);

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret() // Updated!
    }
}

impl Password {
    pub fn parse(password: Secret<String>, allow_hash: bool) -> Result<Self> {
        let pw_str = password.expose_secret().trim().to_string();

        if ARGON2_REGEX.is_match(&pw_str) {
            if allow_hash {
                return Ok(Password(password));
            } else {
                return Err(eyre!(PasswordError::HashWithoutAllowFlag));
            }
        }

        if pw_str.is_empty() {
            Err(eyre!(PasswordError::EmptyPassword))
        } else if pw_str.chars().count() < 8 {
            Err(eyre!(PasswordError::TooShort))
        } else if !pw_str.chars().any(|c| c.is_lowercase()) {
            Err(eyre!(PasswordError::MissingLowercase))
        } else if !pw_str.chars().any(|c| c.is_uppercase()) {
            Err(eyre!(PasswordError::MissingUppercase))
        } else if !pw_str.chars().any(|c| c.is_digit(10)) {
            Err(eyre!(PasswordError::MissingDigit))
        } else if !pw_str.chars().any(|c| !c.is_alphanumeric()) {
            Err(eyre!(PasswordError::MissingSpecialCharacter))
        } else {
            Ok(Password(password))
        }
    }
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    // TODO: implment quickcheck, fake for password tests
    // use fake::faker::internet::en::Password as FakePassword;
    // use fake::Fake;
    use secrecy::Secret;

    use super::*;

    #[tokio::test]
    async fn test_parse_valid_password() {
        let valid_passwords = vec![
            Secret::new("Valid1@Password".to_string()),
            Secret::new("AnotherValid2#Password".to_string()),
        ];

        for password in valid_passwords {
            let result = Password::parse(password, false);
            assert!(result.is_ok(), "Failed to parse valid password");
        }
    }

    #[tokio::test]
    async fn test_parse_invalid_passwords() {
        let invalid_passwords = vec![
            Secret::new("".to_string()),
            Secret::new("short".to_string()),
            Secret::new("NoDigits@Password".to_string()),
            Secret::new("nouppercase1@".to_string()),
            Secret::new("NOLOWERCASE1@".to_string()),
            Secret::new("NoSpecialChar1".to_string()),
        ];

        for password in invalid_passwords {
            let result = Password::parse(password, false);
            assert!(result.is_err(), "Expected error for invalid password");
        }
    }

    // TODO: implement quickcheck, fake for password tests
    // NOTE: Most of these test cases are covered in Password::parse
    /*
    #[test]
    fn empty_string_is_rejected() {
        let password = Secret::new("".to_string());
        assert!(Password::parse(password, false).is_err());
    }

    #[test]
    fn string_less_than_8_characters_is_rejected() {
        let password = Secret::new("1234567".to_string());
        assert!(Password::parse(password, false).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub Secret<String>); // Updated!

    use fake::FakeRng;

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            // Use quickcheck's Gen to seed a FakeRng
            let mut rng = FakeRng::from_seed(g.next_u64());
            let password = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(Secret::new(password))
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        Password::parse(valid_password.0, false).is_ok()
    }
     */
}
