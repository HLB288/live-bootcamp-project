use auth_service::Application;
use reqwest::Response;
use uuid::Uuid;
pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        // Construire l'application
        // let app = Application::build("127.0.0.1:0")
        let app = Application::build("206.189.190.136")
            .await
            .expect("Failed to build app");

        // Formater l'adresse avec le schéma HTTP
        let address = format!("http://{}", app.address);

        // Exécuter l'application dans une tâche asynchrone séparée
        tokio::spawn(async move {
            app.run().await.expect("Failed to run app");
        });

        // Créer un client HTTP
        let http_client = reqwest::Client::new();

        // Retourner une nouvelle instance de TestApp
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
            Body:serde::Serialize,
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
