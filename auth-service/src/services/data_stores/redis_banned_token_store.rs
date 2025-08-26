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
        // 1. Create a new key using the get_key helper function
        let key = get_key(&token);
        
        // 2. Cast TOKEN_TTL_SECONDS to u64
        let ttl = TOKEN_TTL_SECONDS as u64;
        
        // 3. Get connection and call set_ex command
        let mut conn = self.conn.write().await;
        conn.set_ex::<String, bool, ()>(key, true, ttl)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;
        
        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        // Create key and check if it exists
        let key = get_key(token);
        
        let mut conn = self.conn.write().await;
        let exists: bool = conn.exists(&key)
            .map_err(|_| BannedTokenStoreError::UnexpectedError)?;
        
        Ok(exists)
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}