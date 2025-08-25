use auth_service::{
    Application,
    app_state::AppState,
    services::{
        hashmap_user_store::HashmapUserStore, 
        hashset_banned_token_store::HashsetBannedTokenStore,
        hashmap_two_fa_code_store::HashmapTwoFACodeStore,
        mock_email_client::MockEmailClient, // AJOUT
    },
    domain::data_stores::{UserStore, BannedTokenStore, TwoFACodeStore}, // AJOUT: TwoFACodeStore
    utils::constants::prod,
};
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    // Create an instance of HashmapUserStore
    let user_store = HashmapUserStore::default();
    let boxed_user_store = Arc::new(RwLock::new(Box::new(user_store) as Box<dyn UserStore + Send + Sync>));

    // Create an instance of HashsetBannedTokenStore
    let banned_token_store = HashsetBannedTokenStore::new();
    let boxed_banned_token_store = Arc::new(RwLock::new(Box::new(banned_token_store) as Box<dyn BannedTokenStore + Send + Sync>));

    // Create an instance of HashmapTwoFACodeStore
    let two_fa_code_store = HashmapTwoFACodeStore::new();
    let boxed_two_fa_code_store = Arc::new(RwLock::new(Box::new(two_fa_code_store) as Box<dyn TwoFACodeStore + Send + Sync>));

    // AJOUT: Create an instance of MockEmailClient
    let email_client = Arc::new(MockEmailClient);

    // Create an AppState instance with all stores and email client
    let app_state = AppState::new(
        boxed_user_store, 
        boxed_banned_token_store,
        boxed_two_fa_code_store,
        email_client, // AJOUT
    );

    // Build and run the application using the production address
    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}