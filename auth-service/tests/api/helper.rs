use auth_service::{
    Application,
    app_state::{AppState, BannedTokenStoreType, TwoFACodeStoreType},
    get_postgres_pool,
    get_redis_client,
    services::data_stores::{
        PostgresUserStore,
        RedisBannedTokenStore,
        RedisTwoFACodeStore, // Changé de HashmapTwoFACodeStore
    },
    services::MockEmailClient,
    domain::data_stores::{UserStore, BannedTokenStore, TwoFACodeStore, BannedTokenStoreError},
    utils::constants::{test, DATABASE_URL},
};
use reqwest::Response;
use uuid::Uuid;
use tokio::sync::RwLock;
use std::sync::Arc;
use reqwest::cookie::Jar;
use async_trait::async_trait;
use sqlx::{PgPool, postgres::PgPoolOptions, PgConnection, Connection, Executor};
use sqlx::postgres::PgConnectOptions;
use std::str::FromStr;
use redis;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType,
    pub http_client: reqwest::Client,
    pub db_name: String,
}

impl TestApp {
    pub async fn new() -> Self {
        // Generate unique database name for this test
        let db_name = Uuid::new_v4().to_string();
        
        // Configure PostgreSQL with unique database for each test
        let pg_pool = configure_postgresql(&db_name).await;
        
        // Configure Redis connections for tests
        let redis_conn_banned = configure_redis();
        let redis_conn_2fa = configure_redis();
        
        // Use PostgresUserStore
        let user_store = Arc::new(RwLock::new(Box::new(PostgresUserStore::new(pg_pool)) as Box<dyn UserStore + Send + Sync>));
        
        // Use RedisBannedTokenStore
        let banned_token_store = Arc::new(RwLock::new(Box::new(RedisBannedTokenStore::new(Arc::new(RwLock::new(redis_conn_banned)))) as Box<dyn BannedTokenStore + Send + Sync>));
        
        // Use RedisTwoFACodeStore instead of HashmapTwoFACodeStore
        let two_fa_code_store = Arc::new(RwLock::new(Box::new(RedisTwoFACodeStore::new(Arc::new(RwLock::new(redis_conn_2fa)))) as Box<dyn TwoFACodeStore + Send + Sync>));
        
        let email_client = Arc::new(MockEmailClient);

        let app_state = AppState::new(
            user_store,
            banned_token_store.clone(),
            two_fa_code_store.clone(),
            email_client,
        );

        // Build the application using the test address
        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        // Format the address with the HTTP scheme
        let address = format!("http://{}", app.address);

        // Run the application in a separate async task
        tokio::spawn(async move {
            app.run().await.expect("Failed to run app");
        });

        let cookie_jar = Arc::new(Jar::default());

        // Create an HTTP client
        let http_client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .unwrap();

        // Return a new instance of TestApp
        Self {
            address,
            cookie_jar,
            banned_token_store,
            two_fa_code_store,
            http_client,
            db_name,
        }
    }

    pub async fn get_root(&self) -> Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub fn get_random_email() -> String {
        format!("{}@example.com", Uuid::new_v4())
    }

    pub async fn post_login<Body>(&self, body: &Body) -> Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_login_without_body(&self) -> Response {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_login_malformed(&self) -> Response {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_login_with_body<Body>(&self, body: &Body) -> Response
    where
        Body: serde::Serialize,
    {
        self.post_login(body).await
    }

    pub async fn post_logout(&self) -> Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

// Configure PostgreSQL for tests with unique database per test
async fn configure_postgresql(db_name: &str) -> PgPool {
    let postgresql_conn_url = DATABASE_URL.to_owned();
    configure_database(&postgresql_conn_url, db_name).await;
    let postgresql_conn_url_with_db = format!("{}/{}", postgresql_conn_url, db_name);
    get_postgres_pool(&postgresql_conn_url_with_db)
        .await
        .expect("Failed to create Postgres connection pool!")
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    let connection = PgPoolOptions::new()
        .max_connections(2)  // Réduire le nombre de connexions
        .acquire_timeout(std::time::Duration::from_secs(30))  // Augmenter le timeout
        .connect(db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database.");

    let db_conn_string = format!("{}/{}", db_conn_string, db_name);
    let connection = PgPoolOptions::new()
        .max_connections(2)  // Réduire le nombre de connexions
        .acquire_timeout(std::time::Duration::from_secs(30))  // Augmenter le timeout
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

// Function to configure Redis for tests
fn configure_redis() -> redis::Connection {
    get_redis_client(test::REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}

// Helper function to delete test database (currently not used, but kept for future use)
/*
async fn delete_database(db_name: &str) {
    let postgresql_conn_url: String = DATABASE_URL.to_owned();
    let connection_options = PgConnectOptions::from_str(&postgresql_conn_url)
        .expect("Failed to parse PostgreSQL connection string");
    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    connection
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{}'
                AND pid <> pg_backend_pid();
                "#,
                db_name
            )
            .as_str(),
        )
        .await
        .expect("Failed to drop the database.");

    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}
*/

pub fn get_random_email() -> String {
    TestApp::get_random_email()
}

pub fn assert_status_eq(actual: reqwest::StatusCode, expected: u16) {
    assert_eq!(actual.as_u16(), expected);
}