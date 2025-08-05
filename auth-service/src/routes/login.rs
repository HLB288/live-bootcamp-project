use axum::{
    http::StatusCode,
    response::IntoResponse,
    Json, extract::State,
};
use serde::Deserialize;
use crate::domain::error::AuthAPIError;
use crate::app_state::AppState;
// pub async fn login() -> impl IntoResponse {
//     StatusCode::OK
// }

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let user_store = &state.user_store.read().await;

    // Validate user credentials and handle the Result
    user_store.validate_user(&request.email, &request.password)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    // Get the user and handle the Result
    let _user = user_store.get_user(&request.email)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    Ok(StatusCode::OK)
}