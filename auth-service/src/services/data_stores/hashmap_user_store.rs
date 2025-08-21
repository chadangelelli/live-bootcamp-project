use core::fmt;
use std::collections::HashMap;

use crate::domain::{Email, Password, User, UserStore, UserStoreError};

impl fmt::Display for UserStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                UserStoreError::UserAlreadyExists => "[UserStoreError] User already exists",
                UserStoreError::UserNotFound => "[UserStoreError] User not found",
                UserStoreError::InvalidCredentials => "[UserStoreError] Invalid credentials",
                UserStoreError::UnexpectedError => "[UserStoreError] An unexpected error occurred",
            }
        )
    }
}

#[derive(Default, Debug)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.user_exists(&user.email).await {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.to_owned(), user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    /// NOTES: The following responses allow fishing and time-based attacks.
    ///     - Return `UserStoreError::UserNotFound` if the user can not be found.
    ///     - Return `UserStoreError::InvalidCredentials` if the password is incorrect.
    /// SOLUTIONS:
    ///     1. Add time delays to responses to prevent timing attacks.
    ///     2. Return a generic error message for both cases to prevent user enumeration.
    ///     3. Use a constant time comparison for passwords.
    /// (Purposefully not implemented!)
    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<User, UserStoreError> {
        let user = self.get_user(email).await?;

        if user.password.as_ref() == password.as_ref() {
            Ok(user)
        } else {
            Err(UserStoreError::InvalidCredentials)
        }
    }

    async fn user_exists(&self, email: &Email) -> bool {
        self.users.contains_key(&email)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user1() -> User {
        User::new(
            Email::parse("test@example.com".to_string()).unwrap(),
            Password::parse("PaSSword@123!".to_string(), false).unwrap(),
            true,
        )
    }

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::default();
        let user1 = user1();
        let user1_created = user_store.add_user(user1).await;
        assert_eq!(user1_created, Ok(()));
    }

    #[tokio::test]
    async fn test_get_user() {
        let user1 = user1();
        let correct = user1.clone();

        let mut user_store = HashmapUserStore::default();
        // Either add the user to the store or use the existing one if created elsewhere.
        // This is a no-op if the user already exists.
        let _ = user_store.add_user(user1).await;

        let user1_result = user_store.get_user(&correct.email).await;

        assert_eq!(user1_result, Ok(correct));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let user1 = user1();
        let correct = user1.clone();

        let mut user_store = HashmapUserStore::default();
        let _ = user_store.add_user(user1).await;

        let valid_result = user_store
            .validate_user(&correct.email, &correct.password)
            .await;
        assert_eq!(valid_result, Ok(correct));
    }
}
