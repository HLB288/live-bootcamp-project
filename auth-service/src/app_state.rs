use std::sync::Arc;
use tokio::sync::RwLock;
use crate::domain::data_stores::{UserStore, BannedTokenStore}; 

#[derive(Clone)]
pub struct AppState {
    pub user_store: Arc<RwLock<Box<dyn UserStore + Send + Sync>>>,
    pub banned_token_store: Arc<RwLock<Box<dyn BannedTokenStore + Send + Sync>>>,
}

impl AppState {
    pub fn new(
        user_store: Box<dyn UserStore + Send + Sync>,
        banned_token_store: Box<dyn BannedTokenStore + Send + Sync>,
    ) -> Self {
        Self {
            user_store: Arc::new(RwLock::new(user_store)),
            banned_token_store: Arc::new(RwLock::new(banned_token_store)),
        }
    }
}