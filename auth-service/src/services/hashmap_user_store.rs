use std::collecetion::HashMap;
use crate::domain::User;

#[derive(Debug, PaialEq)]
pub enum UserStoreError {
    UserAlreadyExists, 
    UserNotFound, 
    InvalidCredential, 
    UnexpectedError,
}

#[derive(Default)]
pub struct HashmapUserState {
    users: HashMap<String, User>,
}


impl HashmapUserStore {
    pub fn add_user(&mut self, user: USer) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            Err(UserStoreError::UserAlreadyExists)
        } else {
            self.users.insert(user.email.clone(), user);
            Ok(())
        }
    }
    pub fn get_user(&self, email: &str) -> Result<&User, UserStoreError> {
        self.users.get(email).ok_or(UserStoreErrorr::UserNotFound)
    }
    pub fn validate_user(&self, email:&str, password: &str) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) if user.password == password => Ok(()), 
            Some(_) => Err(UserStoreError::InvalidCredentials),
            None => Err(UserStoreError::UserNotFound),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_user(email: &str, password: &str) -> User {
        User {
            email: email.to_string(),
            password: password.to_string(),
        }
    }

    #[test]
    fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = create_test_user("test@example.com", "password123");

        assert!(store.add_user(user).is_ok());
        assert_eq!(store.users.len(), 1);
    }

    #[test]
    fn test_add_existing_user() {
        let mut store = HashmapUserStore::default();
        let user = create_test_user("test@example.com", "password123");

        assert!(store.add_user(user).is_ok());
        let result = store.add_user(create_test_user("test@example.com", "password456"));
        assert!(matches!(result, Err(UserStoreError::UserAlreadyExists)));
    }

    #[test]
    fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = create_test_user("test@example.com", "password123");

        store.add_user(user).unwrap();
        assert!(store.get_user("test@example.com").is_ok());
    }

    #[test]
    fn test_get_nonexistent_user() {
        let store = HashmapUserStore::default();
        let result = store.get_user("nonexistent@example.com");
        assert!(matches!(result, Err(UserStoreError::UserNotFound)));
    }

    #[test]
    fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = create_test_user("test@example.com", "password123");

        store.add_user(user).unwrap();
        assert!(store.validate_user("test@example.com", "password123").is_ok());
    }

    #[test]
    fn test_validate_user_invalid_credentials() {
        let mut store = HashmapUserStore::default();
        let user = create_test_user("test@example.com", "password123");

        store.add_user(user).unwrap();
        let result = store.validate_user("test@example.com", "wrongpassword");
        assert!(matches!(result, Err(UserStoreError::InvalidCredentials)));
    }

    #[test]
    fn test_validate_nonexistent_user() {
        let store = HashmapUserStore::default();
        let result = store.validate_user("nonexistent@example.com", "password123");
        assert!(matches!(result, Err(UserStoreError::UserNotFound)));
    }
}


