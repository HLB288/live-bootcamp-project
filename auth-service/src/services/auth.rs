use jsonwebtoken::{decode, DecodingKey, Validation, errors::Error};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::domain::data_stores::BannedTokenStore;
use crate::utils::constants::JWT_SECRET; 
use color_eyre::eyre::{eyre, Context, ContextCompat, Result};
use secrecy::{ExposeSecret, Secret};


// AJOUT: Structure Claims manquante
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub async fn validate_token(
    token: &str,
    banned_token_store: Arc<RwLock<Box<dyn BannedTokenStore + Send + Sync>>>,
) -> Result<(), Error> {
    // Check if the token is banned
    let banned_store = banned_token_store.read().await;
    if banned_store.contains_token(&Secret::new(token.to_string())).await.unwrap_or(false) {
        return Err(Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken));
    }

    // Validate the token using the secret key
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
        &Validation::default(),
    ).map(|_| ())
}