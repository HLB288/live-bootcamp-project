use axum::{
    http::StatusCode,
    response::{IntoResponse, Response, Html},
    routing::post,
    serve::Serve,
    routing::get,
    Json, Router,
};
use crate::domain::error::AuthAPIError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::{
    routes::{signup, login, logout, verify_2fa, verify_token},
    app_state::AppState,
    services::hashmap_user_store::HashmapUserStore,
};

pub mod routes;
pub mod services;
pub mod app_state;
pub mod domain;

pub struct Application {
    server: Serve<Router, Router>,
    pub address: String,
}

async fn root() -> Html<&'static str> {
    Html("<!DOCTYPE html><html><body><h1>Welcome to the Auth Service</h1></body></html>")
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let router = Router::new()
            .route("/", get(root))
            .route("/signup", post(signup))
            .route("/login", post(login))
            .route("/verify-2fa", post(verify_2fa))
            .route("/logout", post(logout))
            .route("/verify-token", post(verify_token))
            .with_state(app_state);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String, 
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::IncorrectCredentials => (StatusCode::UNAUTHORIZED, "Incorrect credentials"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::UnexpectedError => (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error"),
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}