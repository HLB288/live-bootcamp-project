use std::sync::Arc;
use tokio::sync::RwLock;
use crate::services::hashmap_user_store::HashmapUserStore;
use crate::domain::data_stores::UserStore;

#[derive(Clone)]
pub struct AppState {
    pub user_store: Arc<RwLock<Box<dyn UserStore + Send + Sync>>>,
}

impl AppState {
    pub fn new(user_store: Box<dyn UserStore + Send + Sync>) -> Self {
        Self {
            user_store: Arc::new(RwLock::new(user_store)),
        }
    }
}