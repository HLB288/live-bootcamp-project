use auth_service::{
    Application,
    app_state::AppState,
    get_postgres_pool,
    get_redis_client,
    services::data_stores::{ 
        RedisTwoFACodeStore,
        PostgresUserStore,
        RedisBannedTokenStore,
    },
    services::PostmarkEmailClient, // CHANGÉ ICI
    domain::{data_stores::{UserStore, BannedTokenStore, TwoFACodeStore}, Email},
    utils::constants::{prod, DATABASE_URL, POSTMARK_AUTH_TOKEN},
    utils::init_tracing,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use sqlx::PgPool;
use redis::Connection;
use reqwest::Client;
use secrecy::Secret;

#[tokio::main]
async fn main() {
    color_eyre::install().expect("Failed to install color_eyre");
    init_tracing();

    let pg_pool = configure_postgresql().await;
    let redis_conn = configure_redis();

    let user_store = PostgresUserStore::new(pg_pool);
    let boxed_user_store = Arc::new(RwLock::new(Box::new(user_store) as Box<dyn UserStore + Send + Sync>));

    let banned_token_store = RedisBannedTokenStore::new(Arc::new(RwLock::new(redis_conn)));
    let boxed_banned_token_store = Arc::new(RwLock::new(Box::new(banned_token_store) as Box<dyn BannedTokenStore + Send + Sync>));

    let redis_conn_2fa = configure_redis();
    let two_fa_code_store = RedisTwoFACodeStore::new(Arc::new(RwLock::new(redis_conn_2fa)));
    let boxed_two_fa_code_store = Arc::new(RwLock::new(Box::new(two_fa_code_store) as Box<dyn TwoFACodeStore + Send + Sync>));

    let email_client = Arc::new(configure_postmark_email_client()); // CHANGÉ ICI

    let app_state = AppState::new(
        boxed_user_store, 
        boxed_banned_token_store,
        boxed_two_fa_code_store,
        email_client,
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}

// NOUVELLE FONCTION
fn configure_postmark_email_client() -> PostmarkEmailClient {
    let http_client = Client::builder()
        .timeout(prod::email_client::TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    PostmarkEmailClient::new(
        prod::email_client::BASE_URL.to_owned(),
        Email::parse(Secret::new(prod::email_client::SENDER.to_owned())).unwrap(),
        POSTMARK_AUTH_TOKEN.clone(),
        http_client,
    )
}

async fn configure_postgresql() -> PgPool {
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}

fn configure_redis() -> Connection {
    get_redis_client(prod::REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}