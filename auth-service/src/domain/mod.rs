use std::hash::Hash;
use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, Secret};
use validator::validate_email;

pub mod user;
pub mod error;
pub mod data_stores;
pub mod email_client;

pub use error::*;
pub use user::*;
pub use data_stores::*;
pub use email_client::*;

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

pub fn generate_2fa_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(100000..999999))
}

#[derive(Debug, Clone)]
pub struct Email(pub Secret<String>);

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Eq for Email {}

impl Email {
    pub fn parse(s: Secret<String>) -> Result<Email> {
        if validate_email(s.expose_secret()) {
            Ok(Self(s))
        } else {
            Err(eyre!(format!(
                "{} is not a valid email.",
                s.expose_secret()
            )))
        }
    }
}

impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Password(Secret<String>);

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Password {
    pub fn parse(s: Secret<String>) -> Result<Password> {
        if validate_password(&s) {
            Ok(Self(s))
        } else {
            Err(eyre!("Failed to parse string to a Password type"))
        }
    }
}

fn validate_password(s: &Secret<String>) -> bool {
    s.expose_secret().len() >= 8
}

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

