use auth_service::{
    Application,
    app_state::AppState,
    services::{hashmap_user_store::HashmapUserStore, hashset_banned_token_store::HashsetBannedTokenStore},
    domain::data_stores::{UserStore, BannedTokenStore},
    utils::constants::prod,
};

#[tokio::main]
async fn main() {
    // Create an instance of HashmapUserStore
    let user_store = HashmapUserStore::default();
    let boxed_user_store = Box::new(user_store) as Box<dyn UserStore + Send + Sync>;

    // Create an instance of HashsetBannedTokenStore
    let banned_token_store = HashsetBannedTokenStore::new();
    let boxed_banned_token_store = Box::new(banned_token_store) as Box<dyn BannedTokenStore + Send + Sync>;

    // Create an AppState instance with the boxed user_store and banned_token_store
    let app_state = AppState::new(boxed_user_store, boxed_banned_token_store);

    // Build and run the application using the production address
    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}