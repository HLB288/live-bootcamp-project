use axum::{extract::State, Json};
use axum::http::StatusCode;
use serde::Deserialize;
use crate::app_state::AppState;
use crate::domain::error::AuthAPIError;
use crate::utils::auth::validate_token; // Import de la fonction de validation

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<StatusCode, AuthAPIError> {
    // Utilisation de la fonction de validation complète du token
    validate_token(&request.token, state.banned_token_store.clone()).await
        .map_err(|_| AuthAPIError::InvalidToken)?;
    
    Ok(StatusCode::OK)
}