use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default, Debug)]
pub struct HashSetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        if self.token_exists(&token).await {
            Err(BannedTokenStoreError::TokenAlreadyExists)
        } else {
            self.tokens.insert(token);
            Ok(())
        }
    }

    async fn get_token(&self, token: &str) -> Option<&String> {
        self.tokens.get(token)
    }

    async fn token_exists(&self, token: &str) -> bool {
        self.tokens.contains(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_TOKEN: &str = "0HUgokFFS9P9g9G3bWRLqN8hXmjFvEhfQvGEkwtrvDhuNNgzg13E7utIhtw";

    #[tokio::test]
    async fn test_add_token() {
        let mut store = HashSetBannedTokenStore::default();
        let result = store.add_token(FAKE_TOKEN.to_string()).await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn test_get_token() {
        let mut store = HashSetBannedTokenStore::default();
        let add_result = store.add_token(FAKE_TOKEN.to_string()).await;
        let get_result = store.get_token(FAKE_TOKEN).await;
        assert_eq!(add_result, Ok(()));
        assert_eq!(get_result, Some(&FAKE_TOKEN.to_string()))
    }

    #[tokio::test]
    async fn test_token_exists() {
        let mut store = HashSetBannedTokenStore::default();
        let add_result = store.add_token(FAKE_TOKEN.to_string()).await;
        let exists_result = store.token_exists(FAKE_TOKEN).await;
        assert_eq!(add_result, Ok(()));
        assert!(exists_result)
    }
}
