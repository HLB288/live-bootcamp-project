use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, data_stores::{LoginAttemptId, TwoFACode}},
    utils::auth::generate_auth_cookie,
};

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}

pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    // Validate the email
    let email = Email::parse(request.email)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    // Validate the login attempt ID (must be a valid UUID)
    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    // Validate the 2FA code (must be 6 digits)
    let two_fa_code = TwoFACode::parse(request.two_fa_code)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    // Get the stored code from the 2FA code store
    let code_tuple = {
        let two_fa_code_store = state.two_fa_code_store.read().await;
        two_fa_code_store.get_code(&email).await
            .map_err(|_| AuthAPIError::IncorrectCredentials)?
    }; // Read lock is released here

    let (stored_login_attempt_id, stored_two_fa_code) = code_tuple;

    // Validate that the credentials match
    if login_attempt_id.as_ref() != stored_login_attempt_id.as_ref() {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    if two_fa_code.as_ref() != stored_two_fa_code.as_ref() {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    // IMPORTANT: Remove the 2FA code from the store after successful authentication
    // This prevents the same code from being used twice
    {
        let mut two_fa_code_store = state.two_fa_code_store.write().await;
        two_fa_code_store.remove_code(&email).await
            .map_err(|_| AuthAPIError::UnexpectedError)?;
    } // Write lock is released here

    // Generate auth cookie
    let auth_cookie = generate_auth_cookie(email.as_ref())
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    let updated_jar = jar.add(auth_cookie);

    Ok((updated_jar, StatusCode::OK.into_response()))
}