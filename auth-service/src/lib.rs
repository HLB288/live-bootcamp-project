use axum::{
    http::{Method, StatusCode},
    routing::{get, post},
    Json, Router,
};
use axum::extract::State;
use axum_extra::extract::CookieJar;
use tower_http::cors::CorsLayer;

// Import necessary modules
pub mod domain;
pub mod utils;
pub mod app_state;
pub mod routes;
pub mod services; // AJOUT: Déclaration du module services

// Import types and utilities
use app_state::AppState;
use routes::{login, logout, signup, verify_2fa, verify_token};

pub struct Application {
    pub address: String,
    server: tokio::task::JoinHandle<()>, // AJOUT: handle du serveur
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let allowed_origins = [
            "http://localhost:8000".parse().unwrap(),
            "http://[YOUR_DROPLET_IP]:8000".parse().unwrap(),
        ];

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            .route("/", get(|| async { 
                (
                    [("content-type", "text/html")], 
                    "<html><body><h1>Auth Service UI</h1></body></html>"
                )
            })) 
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/verify-2fa", post(verify_2fa))
            .route("/logout", post(logout))
            .route("/verify-token", post(verify_token))
            .with_state(app_state)
            .layer(cors);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let actual_address = listener.local_addr()?.to_string(); // CORRECTION: obtenir l'adresse réelle
        
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("Failed to start server");
        });

        Ok(Application {
            address: actual_address, // CORRECTION: utiliser l'adresse réelle
            server, // AJOUT: stocker le handle
        })
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Server running on {}", self.address);
        self.server.await?; // CORRECTION: attendre le serveur
        Ok(())
    }
}