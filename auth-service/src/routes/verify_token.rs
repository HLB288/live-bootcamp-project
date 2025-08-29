use axum::{extract::State, Json};
use axum::http::StatusCode;
use serde::Deserialize;
use crate::app_state::AppState;
use crate::domain::error::AuthAPIError;
use crate::utils::auth::validate_token;

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

#[tracing::instrument(name = "Verify token", skip_all)]
pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<StatusCode, AuthAPIError> {
    validate_token(&request.token, state.banned_token_store.clone()).await
        .map_err(|_| AuthAPIError::InvalidToken)?;
    
    Ok(StatusCode::OK)
}