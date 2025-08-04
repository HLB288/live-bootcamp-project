use axum::{extract::State,    
    http::StatusCode,    
    response::IntoResponse,    
    Json};
use serde::{Deserialize, Serialize};
use crate::{    app_state::AppState,};
use crate::AuthAPIError;
use crate::domain::user::User;
use crate::domain::data_stores::UserStore;
use futures_util::TryFutureExt;

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
}

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = request.email;
    let password = request.password;

    // Validation des entrées
    if email.is_empty() || !email.contains('@') {
        return Err(AuthAPIError::InvalidCredentials);
    }

    if password.len() < 8 {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    // Vérification de l'existence de l'email
    if user_store.get_user(&user.email).await.is_ok() {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    // Ajout de l'utilisateur
    user_store.add_user(user).await.map_err(|_| AuthAPIError::UnexpectedError)?;

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}
