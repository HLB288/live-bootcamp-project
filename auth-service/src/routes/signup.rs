use axum::{extract::State, Json};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use secrecy::{Secret, ExposeSecret};
use color_eyre::eyre::eyre;
use crate::app_state::AppState;
use crate::domain::error::AuthAPIError;
use crate::domain::{user::User, Email, Password};

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: Secret<String>,
    pub password: Secret<String>,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[tracing::instrument(name = "Signup", skip_all, err(Debug))]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = Email::parse(request.email)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;
    
    let password = Password::parse(request.password)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let mut user_store = state.user_store.write().await;
    let user = User::new(email, password, request.requires_2fa);
    
    if let Err(e) = user_store.add_user(user).await {
        return Err(match e {
            crate::domain::data_stores::UserStoreError::UserAlreadyExists => AuthAPIError::UserAlreadyExists,
            _ => AuthAPIError::UnexpectedError(eyre!("User store error: {}", e).into()),
        });
    }
    
    Ok(StatusCode::CREATED)
}