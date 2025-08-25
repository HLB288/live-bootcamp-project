use crate::domain::user::User;
use async_trait::async_trait;
use std::error::Error;
use std::fmt;
use crate::domain::{LoginAttempt, Email}; // AJOUT: Email


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
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

// Erreurs pour LoginAttemptStore
#[derive(Debug)]
pub enum LoginAttemptError {
    LoginAttemptNotFound,
    InvalidCode,
    CodeExpired,
    UnexpectedError,
}

impl fmt::Display for LoginAttemptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LoginAttemptError::LoginAttemptNotFound => write!(f, "Login attempt not found"),
            LoginAttemptError::InvalidCode => write!(f, "Invalid 2FA code"),
            LoginAttemptError::CodeExpired => write!(f, "2FA code has expired"),
            LoginAttemptError::UnexpectedError => write!(f, "An unexpected error occurred"),
        }
    }
}

impl Error for LoginAttemptError {}

// Trait LoginAttemptStore
#[async_trait]
pub trait LoginAttemptStore: Send + Sync {
    async fn add_login_attempt(&mut self, login_attempt: LoginAttempt) -> Result<(), LoginAttemptError>;
    async fn get_login_attempt(&self, login_attempt_id: &str) -> Result<LoginAttempt, LoginAttemptError>;
    async fn remove_login_attempt(&mut self, login_attempt_id: &str) -> Result<(), LoginAttemptError>;
}

// AJOUT: This trait represents the interface all concrete 2FA code stores should implement
#[async_trait]
pub trait TwoFACodeStore: Send + Sync {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    LoginAttemptIdNotFound,
    UnexpectedError,
}

impl fmt::Display for TwoFACodeStoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TwoFACodeStoreError::LoginAttemptIdNotFound => write!(f, "Login attempt ID not found"),
            TwoFACodeStoreError::UnexpectedError => write!(f, "An unexpected error occurred"),
        }
    }
}

impl Error for TwoFACodeStoreError {}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self, String> {
        // Use the `parse_str` function from the `uuid` crate to ensure `id` is a valid UUID
        match uuid::Uuid::parse_str(&id) {
            Ok(_) => Ok(Self(id)),
            Err(_) => Err("Invalid UUID format".to_string()),
        }
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        // Use the `uuid` crate to generate a random version 4 UUID
        Self(uuid::Uuid::new_v4().to_string())
    }
}

// Implement AsRef<str> for LoginAttemptId
impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(String);

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self, String> {
        // Ensure `code` is a valid 6-digit code
        if code.len() != 6 {
            return Err("2FA code must be exactly 6 characters long".to_string());
        }
        
        if !code.chars().all(|c| c.is_ascii_digit()) {
            return Err("2FA code must contain only digits".to_string());
        }
        
        Ok(Self(code))
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        // Use the `rand` crate to generate a random 2FA code.
        // The code should be 6 digits (ex: 834629)
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let code = format!("{:06}", rng.gen_range(0..1000000));
        Self(code)
    }
}

// Implement AsRef<str> for TwoFACode
impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        &self.0
    }
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
    async fn get_user(&self, email: &str) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError>;
}