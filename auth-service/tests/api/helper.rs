use auth_service::Application;
use reqwest::Response;
use uuid::Uuid;
use auth_service::app_state::AppState;
use tokio::sync::RwLock;
use std::sync::Arc;
use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::domain::data_stores::UserStore;
pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        // Create an instance of HashmapUserStore
        let user_store = HashmapUserStore::default();

        // Wrap the user_store in a Box
        let user_store = Box::new(user_store) as Box<dyn UserStore + Send + Sync>;

        // Create an AppState instance with the user_store
        let app_state = AppState::new(user_store);

        // Build the application
        let app = Application::build(app_state, "127.0.0.1:0")
            .await
            .expect("Failed to build app");

        // Format the address with the HTTP scheme
        let address = format!("http://{}", app.address);

        // Run the application in a separate async task
        tokio::spawn(async move {
            app.run().await.expect("Failed to run app");
        });

        // Create an HTTP client
        let http_client = reqwest::Client::new();

        // Return a new instance of TestApp
        TestApp {
            address,
            http_client,
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

    pub async fn post_login(&self) -> Response {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_logout(&self) -> Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_verify_2fa(&self) -> Response {
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_verify_token(&self) -> Response {
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .send()
            .await
            .expect("Failed to send request")
    }
}