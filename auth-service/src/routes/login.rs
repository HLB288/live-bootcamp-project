use axum::{extract::State, Json};
use axum::http::StatusCode;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use crate::app_state::AppState;
use crate::domain::error::AuthAPIError;
use crate::utils::auth::generate_auth_cookie;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(CookieJar, StatusCode), AuthAPIError> {
    // AMÉLIORATION: Validation plus stricte des entrées
    if request.email.trim().is_empty() || request.password.trim().is_empty() {
        return Err(AuthAPIError::InvalidCredentials);
    }
    
    if !request.email.contains('@') || request.email.len() < 3 {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let user_store = state.user_store.read().await;
    user_store.validate_user(&request.email, &request.password)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    let auth_cookie = generate_auth_cookie(&request.email)
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    let updated_jar = jar.add(auth_cookie);
    Ok((updated_jar, StatusCode::OK))
}