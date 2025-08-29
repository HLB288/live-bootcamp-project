use std::collections::HashMap;
use secrecy::{Secret, ExposeSecret};
use crate::domain::user::User;
use crate::domain::data_stores::{UserStoreError, UserStore};
use crate::domain::{Email, Password};

pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl Default for HashmapUserStore {
    fn default() -> Self {
        Self { users: HashMap::new() }
    }
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(user.email.as_ref().expose_secret()) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(user.email.as_ref().expose_secret().clone(), user);
            Ok(())
        }
    }

    async fn get_user(&self, email: &str) -> Result<User, UserStoreError> { 
        self.users.get(email).cloned().ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) if user.password.as_ref().expose_secret() == password => Ok(()),
            Some(_) => Err(UserStoreError::InvalidCredentials),
            None => Err(UserStoreError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::Secret;

    fn create_test_user(email: &str, password: &str) -> User {
        User {
            email: Email::parse(Secret::new(email.to_string())).unwrap(),
            password: Password::parse(Secret::new(password.to_string())).unwrap(),
            requires_2fa: false,
        }
    }

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = create_test_user("test@example.com", "password123");
        assert!(store.add_user(user).await.is_ok());
        assert_eq!(store.users.len(), 1);
    }

    #[tokio::test]
    async fn test_add_existing_user() {
        let mut store = HashmapUserStore::default();
        let user = create_test_user("test@example.com", "password123");
        assert!(store.add_user(user).await.is_ok());
        let result = store.add_user(create_test_user("test@example.com", "password456")).await;
        assert!(matches!(result, Err(UserStoreError::UserAlreadyExists)));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = create_test_user("test@example.com", "password123");
        store.add_user(user).await.unwrap();
        assert!(store.get_user("test@example.com").await.is_ok());
    }

    #[tokio::test]
    async fn test_get_nonexistent_user() {
        let store = HashmapUserStore::default();
        let result = store.get_user("nonexistent@example.com").await;
        assert!(matches!(result, Err(UserStoreError::UserNotFound)));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = create_test_user("test@example.com", "password123");
        store.add_user(user).await.unwrap();
        assert!(store.validate_user("test@example.com", "password123").await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_user_invalid_credentials() {
        let mut store = HashmapUserStore::default();
        let user = create_test_user("test@example.com", "password123");
        store.add_user(user).await.unwrap();
        let result = store.validate_user("test@example.com", "wrongpassword").await;
        assert!(matches!(result, Err(UserStoreError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_validate_nonexistent_user() {
        let store = HashmapUserStore::default();
        let result = store.validate_user("nonexistent@example.com", "password123").await;
        assert!(matches!(result, Err(UserStoreError::UserNotFound)));
    }
}