pub mod user;
pub mod error;
pub mod data_stores;
pub mod email_client;

pub use error::*;
pub use user::*;
pub use data_stores::*;
pub use email_client::*;
// AJOUT: Structures et fonctions pour la 2FA
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct LoginAttempt {
    pub email: String,
    pub login_attempt_id: String,
    pub code_2fa: String,
    pub created_at: DateTime<Utc>,
}

impl LoginAttempt {
    pub fn new(email: String, code_2fa: String) -> Self {
        Self {
            email,
            login_attempt_id: Uuid::new_v4().to_string(),
            code_2fa,
            created_at: Utc::now(),
        }
    }
}

// Fonction utilitaire pour générer un code 2FA
pub fn generate_2fa_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(100000..999999)) // Code à 6 chiffres
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(pub String);

impl Email {
    pub fn parse(email: String) -> Result<Self, String> {
        if email.trim().is_empty() {
            return Err("Email cannot be empty".to_string());
        }
        if !email.contains('@') || email.len() < 3 {
            return Err("Invalid email format".to_string());
        }
        Ok(Email(email))
    }
}
impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

pub struct Password(pub String);

