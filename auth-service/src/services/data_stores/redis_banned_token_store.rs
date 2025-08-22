use std::sync::Arc;

use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::{
    domain::data_stores::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let key = make_token_key(&token);
        let mut conn = self.conn.write().await;
        conn.set_ex::<_, _, ()>(key, true, TOKEN_TTL_SECONDS as u64)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;
        Ok(())
    }

    async fn get_token(&self, token: &str) -> Option<&String> {
        let key = make_token_key(token);
        let mut conn = self.conn.write().await;
        match conn.get::<_, String>(&key) {
            Ok(value) => Some(Box::leak(Box::new(value))),
            Err(_) => None,
        }
    }

    async fn token_exists(&self, token: &str) -> bool {
        let key = make_token_key(token);
        let mut conn = self.conn.write().await;
        match conn.exists::<_, bool>(key) {
            Ok(exists) => exists,
            Err(_) => false,
        }
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn make_token_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
