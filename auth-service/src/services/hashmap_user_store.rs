use core::fmt;
use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,   
    InvalidCredentials, 
    UnexpectedError,
}

impl fmt::Display for UserStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            UserStoreError::UserAlreadyExists => "[UserStoreError] User already exists",
            UserStoreError::UserNotFound => "[UserStoreError] User not found",
            UserStoreError::InvalidCredentials => "[UserStoreError] Invalid credentials",
            UserStoreError::UnexpectedError => "[UserStoreError] An unexpected error occurred",
        })
    }
}

#[derive(Default, Debug)]
pub struct HashmapUserStore {
    users: HashMap<String, User>, 
}

impl HashmapUserStore { 
    pub fn add_user(&mut self, user: User) -> Result<(),  UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    pub fn get_user(&self, email: &str) -> Result<&User, UserStoreError> {
        self.users.get(email).ok_or(UserStoreError::UserNotFound)
    }

    /// NOTES: The following responses allow fishing and time-based attacks.
    ///     - Return `UserStoreError::UserNotFound` if the user can not be found.
    ///     - Return `UserStoreError::InvalidCredentials` if the password is incorrect.
    /// SOLUTIONS:
    ///     1. Add time delays to responses to prevent timing attacks.
    ///     2. Return a generic error message for both cases to prevent user enumeration.
    ///     3. Use a constant time comparison for passwords.
    /// (Purposefully not implemented!)
    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        let user = self.get_user(email);
        if let Ok(user) = user {
            if user.get_password() == password {
                return Ok(());
            }
        }
        Err(UserStoreError::InvalidCredentials)
    }   
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user1() -> User {
        User::new(
            "test@example.com".to_owned(),
            "password123".to_owned(),
            true
        )
    }

    #[tokio::test]
    async fn test_add_user() {
        let user1 = user1();
        let user1_created = HashmapUserStore::default().add_user(user1);
        assert_eq!(user1_created, Ok(()));
    }

    #[tokio::test]
    async fn test_get_user() {
        let user1 = user1();
        // Clone the email to avoid ownership issues
        // and to ensure we can use it after the user is added.
        // This is necessary because `user1` will be moved into the store.
        // We need to use `user1.email` to retrieve the user later.
        let user1_email = user1.email.clone();
        let correct = user1.clone();

        let mut user_store = HashmapUserStore::default();
        // Either add the user to the store or use the existing one if created elsewhere.
        // This is a no-op if the user already exists.
        let _ = user_store.add_user(user1); 

        let user1_result = user_store.get_user(user1_email.as_str());

        assert_eq!(user1_result, Ok(&correct));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let user1 = user1();
        let user1_email = user1.email.clone();
        let correct = user1.clone();

        let mut user_store = HashmapUserStore::default();
        let _ = user_store.add_user(user1);

        // Validate the user with correct credentials.
        let valid_result = user_store.validate_user(
            user1_email.as_str(), 
            correct.get_password()
        );
        assert_eq!(valid_result, Ok(()));

        // Validate with incorrect password.
        let invalid_result = user_store.validate_user(
            user1_email.as_str(), 
            "__INVALID_PASSWORD__"
        );
        assert_eq!(invalid_result, Err(UserStoreError::InvalidCredentials));
    }
}