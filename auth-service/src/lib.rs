use axum::{
    Router,
    routing::post,
    response::IntoResponse,
    serve::Serve,
    http::StatusCode,
};
use std::error::Error;
use tower_http::services::ServeDir;

pub mod routes;
pub struct Application {
    server: Serve<Router, Router>,
    pub address: String,
}

impl Application {
    pub async fn build(_address: &str) -> Result<Self, Box<dyn Error>> {
        let router = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", post(routes::signup))
            .route("/login", post(routes::login))
            .route("/logout", post(routes::logout))
            .route("/verify-2fa", post(routes::verify_2fa))
            .route("/verify-token", post(routes::verify_token));

        let listener = tokio::net::TcpListener::bind("0.0.0.0:3300").await?;
        let address = listener.local_addr()?.to_string();

        let server = axum::serve(listener, router);

        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}








