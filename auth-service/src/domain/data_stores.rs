use crate::domain::user::User;
use async_trait::async_trait;
use std::error::Error;
use std::fmt;

// Define a custom error type for BannedTokenStore operations
#[derive(Debug)]
pub enum BannedTokenStoreError {
    TokenAlreadyExists,
    TokenNotFound,
    UnexpectedError,
}

impl fmt::Display for BannedTokenStoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BannedTokenStoreError::TokenAlreadyExists => write!(f, "Token already exists in the store"),
            BannedTokenStoreError::TokenNotFound => write!(f, "Token not found in the store"),
            BannedTokenStoreError::UnexpectedError => write!(f, "An unexpected error occurred"),
        }
    }
}

impl Error for BannedTokenStoreError {}

// Define the BannedTokenStore trait
#[async_trait]
pub trait BannedTokenStore: Send + Sync {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>; // CORRECTION: add_token au lieu de add
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &str) -> Result<User, UserStoreError>; // CORRECTION: retourne User clonée
    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError>;
}