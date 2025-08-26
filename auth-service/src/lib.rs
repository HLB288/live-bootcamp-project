use axum::{
    http::{Method, StatusCode},
    routing::{get, post},
    Json, Router,
};
use axum::extract::State;
use axum_extra::extract::CookieJar;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir; // AJOUT: pour servir les fichiers statiques

// AJOUT: Imports pour SQLx
use sqlx::{PgPool, postgres::PgPoolOptions};
use redis::{Client, RedisResult};

// Import necessary modules
pub mod domain;
pub mod utils;
pub mod app_state;
pub mod routes;
pub mod services;

// Import types and utilities
use app_state::AppState;
use routes::{login, logout, signup, verify_2fa, verify_token};

pub struct Application {
    pub address: String,
    server: tokio::task::JoinHandle<()>,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let allowed_origins = [
            "http://localhost:8000".parse().unwrap(),
            "http://localhost:8001".parse().unwrap(), // AJOUT: pour l'app-service
            "http://[YOUR_DROPLET_IP]:8000".parse().unwrap(),
        ];

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            // MODIFICATION: Servir les fichiers statiques depuis le dossier assets
            .nest_service("/assets", ServeDir::new("assets"))
            .route("/", get(serve_login_page)) // MODIFICATION: fonction dédiée
            .route("/signup", get(serve_login_page)) // AJOUT: GET pour /signup aussi
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/verify-2fa", post(verify_2fa))
            .route("/logout", post(logout))
            .route("/verify-token", post(verify_token))
            .with_state(app_state)
            .layer(cors);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let actual_address = listener.local_addr()?.to_string();
        
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("Failed to start server");
        });

        Ok(Application {
            address: actual_address,
            server,
        })
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Server running on {}", self.address);
        self.server.await?;
        Ok(())
    }
}

// NOUVELLE FONCTION: Helper function pour créer une pool de connexions PostgreSQL
pub async fn get_postgres_pool(url: &str) -> Result<PgPool, sqlx::Error> {
    // Create a new PostgreSQL connection pool
    PgPoolOptions::new().max_connections(5).connect(url).await
}

// NOUVELLE FONCTION: Servir la page de login depuis le fichier index.html
async fn serve_login_page() -> Result<axum::response::Html<String>, StatusCode> {
    // Lire le fichier index.html depuis le dossier assets
    match tokio::fs::read_to_string("assets/index.html").await {
        Ok(contents) => Ok(axum::response::Html(contents)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub fn get_redis_client(redis_hostname: String) -> RedisResult<Client> {
    let redis_url = format!("redis://{}/", redis_hostname);
    redis::Client::open(redis_url)
}

// AJOUT: Import nécessaire pour la réponse
use axum::response::IntoResponse;