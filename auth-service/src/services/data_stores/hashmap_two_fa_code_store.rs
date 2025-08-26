use std::collections::HashMap;
use async_trait::async_trait;
use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

impl HashmapTwoFACodeStore {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
        }
    }
}

#[async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email, (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        match self.codes.remove(email) {
            Some(_) => Ok(()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        match self.codes.get(email) {
            Some((login_attempt_id, code)) => {
                Ok((login_attempt_id.clone(), code.clone()))
            }
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_and_get_code() {
        let mut store = HashmapTwoFACodeStore::new();
        let email = Email("test@example.com".to_string());
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        
        // Test add_code
        assert!(store.add_code(email.clone(), login_attempt_id.clone(), code.clone()).await.is_ok());
        
        // Test get_code
        let result = store.get_code(&email).await;
        assert!(result.is_ok());
        
        let (retrieved_id, retrieved_code) = result.unwrap();
        assert_eq!(retrieved_id, login_attempt_id);
        assert_eq!(retrieved_code, code);
    }

    #[tokio::test]
    async fn test_get_nonexistent_code() {
        let store = HashmapTwoFACodeStore::new();
        let email = Email("nonexistent@example.com".to_string());
        
        let result = store.get_code(&email).await;
        assert!(matches!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound)));
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut store = HashmapTwoFACodeStore::new();
        let email = Email("test@example.com".to_string());
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();
        
        // Add code first
        store.add_code(email.clone(), login_attempt_id, code).await.unwrap();
        
        // Test remove_code
        assert!(store.remove_code(&email).await.is_ok());
        
        // Verify code is removed
        let result = store.get_code(&email).await;
        assert!(matches!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound)));
    }

    #[tokio::test]
    async fn test_remove_nonexistent_code() {
        let mut store = HashmapTwoFACodeStore::new();
        let email = Email("nonexistent@example.com".to_string());
        
        let result = store.remove_code(&email).await;
        assert!(matches!(result, Err(TwoFACodeStoreError::LoginAttemptIdNotFound)));
    }

    #[tokio::test]
    async fn test_overwrite_existing_code() {
        let mut store = HashmapTwoFACodeStore::new();
        let email = Email("test@example.com".to_string());
        let login_attempt_id1 = LoginAttemptId::default();
        let login_attempt_id2 = LoginAttemptId::default();
        let code1 = TwoFACode::parse("123456".to_string()).unwrap();
        let code2 = TwoFACode::parse("654321".to_string()).unwrap();
        
        // Add first code
        store.add_code(email.clone(), login_attempt_id1, code1).await.unwrap();
        
        // Add second code (should overwrite)
        store.add_code(email.clone(), login_attempt_id2.clone(), code2.clone()).await.unwrap();
        
        // Verify second code is stored
        let (retrieved_id, retrieved_code) = store.get_code(&email).await.unwrap();
        assert_eq!(retrieved_id, login_attempt_id2);
        assert_eq!(retrieved_code, code2);
    }
}