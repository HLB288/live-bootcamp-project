use auth_service::{
    Application,
    app_state::{AppState, BannedTokenStoreType, TwoFACodeStoreType}, // AJOUT: types du app_state
    services::{
        hashmap_user_store::HashmapUserStore, 
        hashset_banned_token_store::HashsetBannedTokenStore,
        hashmap_two_fa_code_store::HashmapTwoFACodeStore,
        mock_email_client::MockEmailClient, // AJOUT
    },
    domain::data_stores::{UserStore, BannedTokenStore, TwoFACodeStore, BannedTokenStoreError},
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
    pub banned_token_store: BannedTokenStoreType,
    pub two_fa_code_store: TwoFACodeStoreType, // New!
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let user_store = Arc::new(RwLock::new(Box::new(HashmapUserStore::default()) as Box<dyn UserStore + Send + Sync>));
        let banned_token_store = Arc::new(RwLock::new(Box::new(HashsetBannedTokenStore::default()) as Box<dyn BannedTokenStore + Send + Sync>));
        let two_fa_code_store = Arc::new(RwLock::new(Box::new(HashmapTwoFACodeStore::default()) as Box<dyn TwoFACodeStore + Send + Sync>)); // New!
        let email_client = Arc::new(MockEmailClient); // AJOUT

        let app_state = AppState::new(
            user_store,
            banned_token_store.clone(),
            two_fa_code_store.clone(),
            email_client, // AJOUT
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
            two_fa_code_store, // New!
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
            .send()
            .await
            .expect("Failed to send request")
    }

    // AJOUT: méthode pour login avec JSON malformé (pour 422)
    pub async fn post_login_malformed(&self) -> Response {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(&serde_json::json!({}))
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

    // MODIFICATION: Maintenant accepte un body comme paramètre
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

// AJOUT: fonction libre pour compatibilité
pub fn get_random_email() -> String {
    TestApp::get_random_email()
}

// AJOUT: Helper pour convertir les status codes
pub fn assert_status_eq(actual: reqwest::StatusCode, expected: u16) {
    assert_eq!(actual.as_u16(), expected);
}