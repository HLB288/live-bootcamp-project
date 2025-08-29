use axum::{
    http::{Method, StatusCode},
    routing::{get, post},
    Json, Router,
};
use axum::extract::State;
use axum_extra::extract::CookieJar;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use utils::tracing::{make_span_with_request_id, on_request, on_response};
use secrecy::{Secret, ExposeSecret};

use sqlx::{PgPool, postgres::PgPoolOptions};
use redis::{Client, RedisResult};

pub mod domain;
pub mod utils;
pub mod app_state;
pub mod routes;
pub mod services;

use app_state::AppState;
use routes::{signup, login, verify_2fa, logout, verify_token};

pub struct Application {
    pub address: String,
    server: tokio::task::JoinHandle<()>,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let allowed_origins = [
            "http://localhost:8000".parse().unwrap(),
            "http://localhost:8001".parse().unwrap(),
            "http://[YOUR_DROPLET_IP]:8000".parse().unwrap(),
        ];

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            .nest_service("/assets", ServeDir::new("assets"))
            .route("/", get(serve_login_page))
            .route("/signup", get(serve_login_page))
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/verify-2fa", post(verify_2fa))
            .route("/logout", post(logout))
            .route("/verify-token", post(verify_token))
            .with_state(app_state)
            .layer(cors)
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(make_span_with_request_id)
                    .on_request(on_request)
                    .on_response(on_response),
            );

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
        tracing::info!("listening on {}", &self.address);
        self.server.await?;
        Ok(())
    }
}

pub async fn get_postgres_pool(url: &Secret<String>) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new().max_connections(5).connect(url.expose_secret()).await
}

async fn serve_login_page() -> Result<axum::response::Html<String>, StatusCode> {
    match tokio::fs::read_to_string("assets/index.html").await {
        Ok(contents) => Ok(axum::response::Html(contents)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub fn get_redis_client(redis_hostname: String) -> RedisResult<Client> {
    let redis_url = format!("redis://{}/", redis_hostname);
    redis::Client::open(redis_url)
}

use axum::response::IntoResponse;