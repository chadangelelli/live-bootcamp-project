use async_trait::async_trait;
use std::collections::HashMap;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

#[async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email);
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes
            .get(email)
            .cloned()
            .ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        domain::{data_stores::TwoFACodeStore, Email, LoginAttemptId, TwoFACode},
        services::HashmapTwoFACodeStore,
    };

    async fn add_code() -> (HashmapTwoFACodeStore, Email) {
        let mut store = HashmapTwoFACodeStore::default();

        let email = Email::parse("test@example.com".to_string()).unwrap();
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::parse("123456".to_string()).unwrap();

        let result = store.add_code(email.clone(), login_attempt_id, code).await;
        assert!(result.is_ok());

        (store, email)
    }

    #[tokio::test]
    async fn test_add_code() {
        add_code().await;
    }

    #[tokio::test]
    async fn test_remove_code() {
        let (mut store, email) = add_code().await;
        let result = store.remove_code(&email).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_code() {
        let (store, email) = add_code().await;
        let result = store.get_code(&email).await;
        assert!(result.is_ok());
    }
}
