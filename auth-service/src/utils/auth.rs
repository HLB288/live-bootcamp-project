use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::domain::data_stores::BannedTokenStore;
use crate::domain::error::AuthAPIError;
use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};

// Structure pour les claims JWT
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

// Durée de vie du token JWT en secondes
pub const TOKEN_TTL_SECONDS: i64 = 600; // 10 minutes

// Erreur personnalisée pour la génération de token
#[derive(Debug)]
pub enum GenerateTokenError {
    TokenError(jsonwebtoken::errors::Error),
    UnexpectedError,
}

// Génère un cookie d'authentification avec un nouveau token JWT
pub fn generate_auth_cookie(email: &str) -> Result<Cookie<'static>, GenerateTokenError> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

// Crée un cookie avec le token JWT
fn create_auth_cookie(token: String) -> Cookie<'static> {
    Cookie::build((JWT_COOKIE_NAME, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build()
}

// Génère un token JWT
pub fn generate_auth_token(email: &str) -> Result<String, GenerateTokenError> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .ok_or(GenerateTokenError::UnexpectedError)?;

    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(GenerateTokenError::UnexpectedError)?
        .timestamp();

    let exp: usize = exp
        .try_into()
        .map_err(|_| GenerateTokenError::UnexpectedError)?;

    let claims = Claims {
        sub: email.to_owned(),
        exp,
    };

    create_token(&claims).map_err(GenerateTokenError::TokenError)
}

// Valide un token JWT
pub async fn validate_token(
    token: &str,
    banned_token_store: Arc<RwLock<Box<dyn BannedTokenStore + Send + Sync>>>,
) -> Result<(), AuthAPIError> {
    // Vérifie si le token est banni
    let banned_store = banned_token_store.read().await;
    if banned_store.contains_token(token).await.unwrap_or(false) {
        return Err(AuthAPIError::InvalidToken);
    }

    // Valide le token avec la clé secrète
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &Validation::default(),
    ).map(|_| ())
    .map_err(|_| AuthAPIError::InvalidToken)
}

// Crée un token JWT en encodant les claims
pub fn create_token(claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::hashset_banned_token_store::HashsetBannedTokenStore; // CORRECTION: nom correct
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email = "test@example.com";
        let cookie = generate_auth_cookie(email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email = "test@example.com";
        let token = generate_auth_token(email).unwrap();
        let banned_token_store = Arc::new(RwLock::new(Box::new(HashsetBannedTokenStore::default()) as Box<dyn BannedTokenStore + Send + Sync>));
        let result = validate_token(&token, banned_token_store).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_token_with_invalid_token() {
        let token = "invalid_token".to_owned();
        let banned_token_store = Arc::new(RwLock::new(Box::new(HashsetBannedTokenStore::default()) as Box<dyn BannedTokenStore + Send + Sync>));
        let result = validate_token(&token, banned_token_store).await;
        assert!(result.is_err());
    }
}