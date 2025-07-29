use crate::domain::{Email, Password};

#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub email: Email,
    password: Password,
    requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> User {
        User {
            email,
            password,
            requires_2fa,
        }
    }

    pub fn get_password(&self) -> &Password {
        &self.password
    }

    pub fn requires_2fa(&self) -> &bool {
        &self.requires_2fa
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_user_create() {
        let correct_email = "test@example.com";
        let correct_password = "Valid1@Password";

        let user = User::new(
            Email::parse(correct_email.to_string()).unwrap(),
            Password::parse(correct_password.to_string()).unwrap(),
            true,
        );

        assert_eq!(user.email.as_ref(), correct_email);
        assert_eq!(user.get_password().as_ref(), correct_password);
        assert!(user.requires_2fa());
    }
}
