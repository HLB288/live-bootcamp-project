use auth_service::{
    Application,
    app_state::AppState,
    get_postgres_pool,
    get_redis_client,
    services::data_stores::{ 
        RedisTwoFACodeStore, // Changé de HashmapTwoFACodeStore
        PostgresUserStore,
        RedisBannedTokenStore,
    },
    services::MockEmailClient,
    domain::data_stores::{UserStore, BannedTokenStore, TwoFACodeStore},
    utils::constants::{prod, DATABASE_URL},
};
use std::sync::Arc;
use tokio::sync::RwLock;
use sqlx::PgPool;
use redis::Connection;

#[tokio::main]
async fn main() {
    // Configure PostgreSQL and get the pool
    let pg_pool = configure_postgresql().await;

    // Configure Redis and get the connection
    let redis_conn = configure_redis();

    // Create PostgresUserStore
    let user_store = PostgresUserStore::new(pg_pool);
    let boxed_user_store = Arc::new(RwLock::new(Box::new(user_store) as Box<dyn UserStore + Send + Sync>));

    // Create RedisBannedTokenStore
    let banned_token_store = RedisBannedTokenStore::new(Arc::new(RwLock::new(redis_conn)));
    let boxed_banned_token_store = Arc::new(RwLock::new(Box::new(banned_token_store) as Box<dyn BannedTokenStore + Send + Sync>));

    // Configure another Redis connection for 2FA code store
    let redis_conn_2fa = configure_redis();
    
    // Create RedisTwoFACodeStore instead of HashmapTwoFACodeStore
    let two_fa_code_store = RedisTwoFACodeStore::new(Arc::new(RwLock::new(redis_conn_2fa)));
    let boxed_two_fa_code_store = Arc::new(RwLock::new(Box::new(two_fa_code_store) as Box<dyn TwoFACodeStore + Send + Sync>));

    // Create an instance of MockEmailClient
    let email_client = Arc::new(MockEmailClient);

    // Create an AppState instance with all stores and email client
    let app_state = AppState::new(
        boxed_user_store, 
        boxed_banned_token_store,
        boxed_two_fa_code_store,
        email_client,
    );

    // Build and run the application using the production address
    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

// Helper function to configure PostgreSQL
async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our database! 
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

// Corrected helper function to configure Redis
fn configure_redis() -> Connection {
    get_redis_client(prod::REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}