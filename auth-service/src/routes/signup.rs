use axum::{extract::State, Json};
use axum::http::StatusCode;
use serde::Deserialize;
use crate::app_state::AppState;
use crate::domain::error::AuthAPIError;
use crate::domain::user::User;

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool, // AJOUT: champ manquant
}

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<StatusCode, AuthAPIError> {
    // Validation basique des entrées
    if request.email.is_empty() || !request.email.contains('@') {
        return Err(AuthAPIError::InvalidCredentials);
    }
    
    if request.password.len() < 8 {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let mut user_store = state.user_store.write().await;
    let user = User::new(request.email, request.password, request.requires_2fa);
    
    user_store.add_user(user).await.map_err(|e| match e {
        crate::domain::data_stores::UserStoreError::UserAlreadyExists => AuthAPIError::UserAlreadyExists,
        _ => AuthAPIError::UnexpectedError,
    })?;
    
    Ok(StatusCode::CREATED) 
}