use std::sync::Arc;

use color_eyre::eyre::{Result, WrapErr};
use redis::{Commands, Connection};
use secrecy::{ExposeSecret, Secret};
use tokio::sync::RwLock;

use crate::{
    domain::data_stores::{BannedTokenStore, BannedTokenStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    #[tracing::instrument(name = "Create Redis Banned Token Store", skip_all)]
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    #[tracing::instrument(name = "Add Banned Token", skip_all)]
    async fn add_token(&mut self, token: Secret<String>) -> Result<()> {
        let key = make_token_key(token.expose_secret());
        let value = true;

        let mut conn = self.conn.write().await;
        let _: () = conn
            .set_ex(key, value, TOKEN_TTL_SECONDS as u64)
            .wrap_err("failed to set banned token in Redis")
            .map_err(BannedTokenStoreError::UnexpectedError)?;
        Ok(())
    }

    #[tracing::instrument(name = "Get Banned Token", skip_all)]
    async fn get_token(&self, token: &str) -> Option<&String> {
        let key = make_token_key(token);
        let mut conn = self.conn.write().await;
        match conn.get::<_, String>(&key) {
            // TODO: fix the leak call
            Ok(value) => Some(Box::leak(Box::new(value))),
            Err(_) => None,
        }
    }

    #[tracing::instrument(name = "Check if Token is Banned", skip_all)]
    async fn token_exists(&self, token: &Secret<String>) -> bool {
        let key = make_token_key(token.expose_secret());
        let mut conn = self.conn.write().await;
        match conn.exists::<_, bool>(key) {
            Ok(exists) => exists,
            Err(_) => false,
        }
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

#[tracing::instrument(name = "Make Token Key", skip_all)]
fn make_token_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
