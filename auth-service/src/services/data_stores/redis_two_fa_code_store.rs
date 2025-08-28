use std::sync::Arc;

use color_eyre::eyre::Context;
use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    #[tracing::instrument(name = "Create Redis 2FA Code Store", skip_all)]
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

#[tracing::instrument(name = "Make 2FA Key", skip_all)]
fn make_2fa_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "Add 2FA Code", skip_all)]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = make_2fa_key(&email);
        let value = serde_json::to_string(&TwoFATuple(login_attempt_id.0, code.0))
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        let mut conn = self.conn.write().await;
        let _: () = conn
            .set_ex(key, value, TEN_MINUTES_IN_SECONDS)
            .wrap_err("failed to set 2FA code in Redis")
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        Ok(())
    }

    #[tracing::instrument(name = "Remove 2FA Code", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = make_2fa_key(email);
        let mut conn = self.conn.write().await;
        let _: () = conn
            .del(key)
            .wrap_err("failed to delete 2FA code from Redis")
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        Ok(())
    }

    #[tracing::instrument(name = "Get 2FA Code", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = make_2fa_key(email);
        let value = {
            let mut conn = self.conn.write().await;
            let value: String = conn
                .get(key)
                .wrap_err("failed to deserialize 2FA tuple")
                .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;
            value
        };
        let tuple: TwoFATuple = serde_json::from_str(&value)
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        let login_attempt_id =
            LoginAttemptId::parse(tuple.0).map_err(TwoFACodeStoreError::UnexpectedError)?;
        let two_fa_code =
            TwoFACode::parse(tuple.1).map_err(TwoFACodeStoreError::UnexpectedError)?;

        Ok((login_attempt_id, two_fa_code))
    }
}
