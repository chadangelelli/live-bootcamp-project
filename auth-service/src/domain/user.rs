use crate::domain::{Email, Password};

#[derive(Clone, Debug, PartialEq, sqlx::FromRow)]
pub struct User {
    pub email: Email,
    #[sqlx(rename = "password_hash")]
    pub password: Password,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> User {
        User {
            email,
            password: password,
            requires_2fa,
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret, Secret};

    use super::*;

    #[tokio::test]
    async fn test_user_create() {
        let correct_email = "test@example.com";
        let correct_password = "Valid1@Password";

        let user = User::new(
            Email::parse(Secret::new(correct_email.to_string())).unwrap(),
            Password::parse(Secret::new(correct_password.to_string()), false).unwrap(),
            true,
        );

        assert_eq!(user.email.as_ref().expose_secret(), correct_email);
        assert!(user.requires_2fa);
        assert_eq!(user.password.as_ref().expose_secret(), correct_password);
    }
}
