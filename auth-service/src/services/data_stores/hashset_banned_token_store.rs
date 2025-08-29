use std::collections::HashSet;
use async_trait::async_trait;
use secrecy::{Secret, ExposeSecret};
use color_eyre::eyre::eyre;
use crate::domain::data_stores::{BannedTokenStore, BannedTokenStoreError};

#[derive(Clone)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

impl HashsetBannedTokenStore {
    pub fn new() -> Self {
        HashsetBannedTokenStore {
            tokens: HashSet::new(),
        }
    }
}

impl Default for HashsetBannedTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        if !self.tokens.insert(token.expose_secret().clone()) {
            return Err(BannedTokenStoreError::UnexpectedError(eyre!("Token already exists").into()));
        }
        Ok(())
    }

    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_and_contains_token() {
        let mut store = HashsetBannedTokenStore::new();
        let token = Secret::new("some_token".to_string());

        assert!(store.add_token(token.clone()).await.is_ok());
        assert!(store.contains_token(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_add_duplicate_token() {
        let mut store = HashsetBannedTokenStore::new();
        let token = Secret::new("some_token".to_string());

        assert!(store.add_token(token.clone()).await.is_ok());
        assert!(store.add_token(token).await.is_err());
    }

    #[tokio::test]
    async fn test_contains_non_existent_token() {
        let store = HashsetBannedTokenStore::new();
        let token = Secret::new("non_existent_token".to_string());

        assert!(!store.contains_token(&token).await.unwrap());
    }
}