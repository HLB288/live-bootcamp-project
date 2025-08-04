// src/main.rs
use std::sync::Arc;
use tokio::sync::RwLock;
use auth_service::{
    Application,
    app_state::AppState,
    services::hashmap_user_store::HashmapUserStore,
    domain::data_stores::UserStore,
};

#[tokio::main]
async fn main() {
    // Create an instance of HashmapUserStore
    let user_store = HashmapUserStore::default();

    // Wrap the user_store in a Box
    let boxed_user_store = Box::new(user_store) as Box<dyn UserStore + Send + Sync>;

    // Create an AppState instance with the boxed user_store
    let app_state = AppState::new(boxed_user_store);

    // Build and run the application
    let app = Application::build(app_state, "0.0.0.0:3000")
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
