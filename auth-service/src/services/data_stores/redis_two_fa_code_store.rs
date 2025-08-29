use std::sync::Arc;
use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use secrecy::ExposeSecret;
use color_eyre::eyre::{Context, eyre};
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

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "Adding 2FA code to Redis", skip_all)]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(&email);
        let two_fa_tuple = TwoFATuple(
            login_attempt_id.as_ref().expose_secret().clone(),
            code.as_ref().expose_secret().clone(),
        );
        
        let serialized_tuple = serde_json::to_string(&two_fa_tuple)
            .wrap_err("failed to serialize 2FA tuple")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        
        let mut conn = self.conn.write().await;
        conn.set_ex::<String, String, ()>(key, serialized_tuple, TEN_MINUTES_IN_SECONDS)
            .wrap_err("failed to set 2FA code in Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        
        Ok(())
    }

    #[tracing::instrument(name = "Removing 2FA code from Redis", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);
        let mut conn = self.conn.write().await;
        conn.del::<String, ()>(key)
            .wrap_err("failed to delete 2FA code from Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        
        Ok(())
    }

    #[tracing::instrument(name = "Getting 2FA code from Redis", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(email);
        let mut conn = self.conn.write().await;
        let serialized_tuple: String = conn.get(&key)
            .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;
        
        let two_fa_tuple: TwoFATuple = serde_json::from_str(&serialized_tuple)
            .wrap_err("failed to deserialize 2FA tuple")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        
        let login_attempt_id = LoginAttemptId::parse(two_fa_tuple.0)
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        let two_fa_code = TwoFACode::parse(two_fa_tuple.1)
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        
        Ok((login_attempt_id, two_fa_code))
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref().expose_secret())
}