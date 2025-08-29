use std::collections::HashSet;

use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default, Debug)]
pub struct HashSetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_token(&mut self, token: Secret<String>) -> Result<()> {
        if self.token_exists(&token).await {
            Err(eyre!(BannedTokenStoreError::TokenAlreadyExists))
        } else {
            self.tokens.insert(token.expose_secret().to_owned());
            Ok(())
        }
    }

    async fn get_token(&self, token: &str) -> Option<&String> {
        self.tokens.get(token)
    }

    async fn token_exists(&self, token: &Secret<String>) -> bool {
        self.tokens.contains(token.expose_secret())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_token() -> Secret<String> {
        Secret::new("0HUgokFFS9P9g9G3bWRLqN8hXmjFvEhfQvGEkwtrvDhuNNgzg13E7utIhtw".to_string())
    }

    #[tokio::test]
    async fn test_add_token() {
        let mut store = HashSetBannedTokenStore::default();
        let result = store.add_token(fake_token()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_token() {
        let mut store = HashSetBannedTokenStore::default();
        let token = fake_token();
        let add_result = store.add_token(token.clone()).await;
        let get_result = store.get_token(token.expose_secret()).await;
        assert!(add_result.is_ok());
        assert_eq!(get_result, Some(token.expose_secret()))
    }

    #[tokio::test]
    async fn test_token_exists() {
        let mut store = HashSetBannedTokenStore::default();
        let token = fake_token();
        let add_result = store.add_token(token.clone()).await;
        let exists_result = store.token_exists(&token).await;
        assert!(add_result.is_ok());
        assert!(exists_result)
    }
}
