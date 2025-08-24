use std::sync::Arc;

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
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn make_2fa_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = make_2fa_key(&email);
        let value = serde_json::to_string(&TwoFATuple(login_attempt_id.0, code.0))
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let mut conn = self.conn.write().await;
        let _: () = conn
            .set_ex(key, value, TEN_MINUTES_IN_SECONDS)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = make_2fa_key(email);
        let mut conn = self.conn.write().await;
        let _: () = conn
            .del(key)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = make_2fa_key(email);
        let value = {
            let mut conn = self.conn.write().await;
            let value: String = conn
                .get(key)
                .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;
            value
        };
        let tuple: TwoFATuple =
            serde_json::from_str(&value).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let login_attempt_id = LoginAttemptId(tuple.0);
        let two_fa_code = TwoFACode(tuple.1);
        Ok((login_attempt_id, two_fa_code))
    }
}
