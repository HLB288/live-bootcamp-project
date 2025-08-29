use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use color_eyre::eyre::{eyre, Context, ContextCompat, Result, WrapErr};
use crate::domain::Email;
use crate::app_state::BannedTokenStoreType;
use super::constants::{JWT_COOKIE_NAME, JWT_SECRET};
use secrecy::{ExposeSecret, Secret};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub const TOKEN_TTL_SECONDS: i64 = 600;

#[tracing::instrument(name = "Generating auth cookie", skip_all)]
pub fn generate_auth_cookie(email: &Email) -> Result<Cookie<'static>> {
    let token = generate_auth_token(email)?;
    Ok(create_auth_cookie(token))
}

fn create_auth_cookie(token: String) -> Cookie<'static> {
    Cookie::build((JWT_COOKIE_NAME, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build()
}

#[tracing::instrument(name = "Generating auth token", skip_all)]
pub fn generate_auth_token(email: &Email) -> Result<String> {
    let delta = chrono::Duration::try_seconds(TOKEN_TTL_SECONDS)
        .wrap_err("failed to create 10 minute time delta")?;

    let exp = Utc::now()
        .checked_add_signed(delta)
        .ok_or(eyre!("failed to add 10 minutes to current time"))?
        .timestamp();

    let exp: usize = exp.try_into().wrap_err(format!(
        "failed to cast exp time to usize. exp time: {}",
        exp
    ))?;

    let sub = email.as_ref().expose_secret().to_owned();
    let claims = Claims { sub, exp };

    create_token(&claims)
}
#[tracing::instrument(name = "Validating token", skip_all)]
pub async fn validate_token(
    token: &str,
    banned_token_store: BannedTokenStoreType,
) -> Result<Claims> {
    match banned_token_store.read().await.contains_token(&Secret::new(token.to_string())).await {
        Ok(value) => {
            if value {
                return Err(eyre!("token is banned"));
            }
        }
        Err(e) => return Err(e.into()),
    }

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .wrap_err("failed to decode token")
}
#[tracing::instrument(name = "Creating token", skip_all)]
fn create_token(claims: &Claims) -> Result<String> {
    encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.expose_secret().as_bytes()),
    )
    .wrap_err("failed to create token")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::hashset_banned_token_store::HashsetBannedTokenStore;
    use crate::domain::{Email, data_stores::BannedTokenStore};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use secrecy::Secret;

    #[tokio::test]
    async fn test_generate_auth_cookie() {
        let email_str = "test@example.com";
        let email = Email::parse(Secret::new(email_str.to_string())).unwrap();
        let cookie = generate_auth_cookie(&email).unwrap();
        assert_eq!(cookie.name(), JWT_COOKIE_NAME);
        assert_eq!(cookie.value().split('.').count(), 3);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[tokio::test]
    async fn test_validate_token_with_valid_token() {
        let email_str = "test@example.com";
        let email = Email::parse(Secret::new(email_str.to_string())).unwrap();
        let token = generate_auth_token(&email).unwrap();
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