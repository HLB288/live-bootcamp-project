use auth_service::{
    Application,
    app_state::AppState,
    services::{hashmap_user_store::HashmapUserStore, hashset_banned_token_store::HashsetBannedTokenStore},
    domain::data_stores::{UserStore, BannedTokenStore, BannedTokenStoreError},
    utils::constants::test,
};
use reqwest::Response;
use uuid::Uuid;
use tokio::sync::RwLock;
use std::sync::Arc;
use reqwest::cookie::Jar;
use async_trait::async_trait;

// AJOUT: Wrapper pour partager la même instance entre l'app et les tests
pub struct TestBannedTokenStoreWrapper {
    inner: Arc<RwLock<HashsetBannedTokenStore>>,
}

#[async_trait]
impl BannedTokenStore for TestBannedTokenStoreWrapper {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        let mut store = self.inner.write().await;
        store.add_token(token).await
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        let store = self.inner.read().await;
        store.contains_token(token).await
    }
}

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub banned_token_store: Arc<RwLock<HashsetBannedTokenStore>>, // CORRECTION: type concret au lieu de trait object
}

impl TestApp {
    pub async fn new() -> Self {
        // Create an instance of HashmapUserStore
        let user_store = HashmapUserStore::default();
        let user_store = Box::new(user_store) as Box<dyn UserStore + Send + Sync>;

        // Create an instance of HashsetBannedTokenStore
        let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::new()));
        let banned_token_store_for_app = banned_token_store.clone(); // CORRECTION: cloner l'Arc, pas le contenu

        // Create an AppState instance with the user_store and banned_token_store
        let app_state = AppState::new(
            user_store, 
            Box::new(TestBannedTokenStoreWrapper {
                inner: banned_token_store_for_app.clone()
            }) as Box<dyn BannedTokenStore + Send + Sync>
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
            .cookie_store(true) // CORRECTION: cookie_store au lieu de cookie_provider
            .build()
            .unwrap();

        // Return a new instance of TestApp
        Self {
            address,
            cookie_jar,
            http_client,
            banned_token_store, // CORRECTION: utiliser la même référence
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

    // AJOUT: fonction utilitaire pour générer des emails aléatoires
    pub fn get_random_email() -> String {
        format!("{}@example.com", Uuid::new_v4())
    }

    // CORRECTION: méthode qui accepte un body
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

    // AJOUT: méthode pour login sans body (pour les tests qui l'attendent)
    pub async fn post_login_without_body(&self) -> Response {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .send() // CORRECTION: pas de JSON = 415 Unsupported Media Type
            .await
            .expect("Failed to send request")
    }

    // AJOUT: méthode pour login avec JSON malformé (pour 422)
    pub async fn post_login_malformed(&self) -> Response {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(&serde_json::json!({})) // MEILLEURE APPROCHE: JSON vide = 422 (comme pour verify_token)
            .send()
            .await
            .expect("Failed to send request")
    }

    // AJOUT: alias pour compatibilité
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

    pub async fn post_verify_2fa(&self) -> Response {
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
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

// AJOUT: fonction libre pour compatibilité
pub fn get_random_email() -> String {
    TestApp::get_random_email()
}

// AJOUT: Helper pour convertir les status codes
pub fn assert_status_eq(actual: reqwest::StatusCode, expected: u16) {
    assert_eq!(actual.as_u16(), expected);
}