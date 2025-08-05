use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;


// Déclaration des modules
pub mod domain;
pub mod utils;
pub mod app_state;
pub mod routes;

// Imports des types nécessaires
use domain::error::AuthAPIError;
use utils::auth::generate_auth_cookie;
use app_state::AppState;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let user_store = &state.user_store.read().await;

    // Validate user credentials and handle the Result
    user_store.validate_user(&request.email, &request.password)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    // Get the user and handle the Result
    let user = user_store.get_user(&request.email)
        .await
        .map_err(|_| AuthAPIError::IncorrectCredentials)?;

    // Generate the authentication cookie
    let auth_cookie = generate_auth_cookie(&user.email)
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    // Add the cookie to the CookieJar
    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok(StatusCode::OK))
}
