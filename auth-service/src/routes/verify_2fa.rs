use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use secrecy::{Secret, ExposeSecret};
use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, data_stores::{LoginAttemptId, TwoFACode}},
    utils::auth::generate_auth_cookie,
};
use color_eyre::eyre::eyre;

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}

#[tracing::instrument(name = "Verify 2FA", skip_all)]
pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError> {
    let email = Email::parse(Secret::new(request.email))
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let two_fa_code = TwoFACode::parse(request.two_fa_code)
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let code_tuple = {
        let two_fa_code_store = state.two_fa_code_store.read().await;
        two_fa_code_store.get_code(&email).await
            .map_err(|_| AuthAPIError::IncorrectCredentials)?
    };

    let (stored_login_attempt_id, stored_two_fa_code) = code_tuple;

    if login_attempt_id.as_ref().expose_secret() != stored_login_attempt_id.as_ref().expose_secret() {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    if two_fa_code.as_ref().expose_secret() != stored_two_fa_code.as_ref().expose_secret() {
        return Err(AuthAPIError::IncorrectCredentials);
    }

    {
        let mut two_fa_code_store = state.two_fa_code_store.write().await;
        two_fa_code_store.remove_code(&email).await
            .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;
    }

    let auth_cookie = generate_auth_cookie(&email)
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;
    let updated_jar = jar.add(auth_cookie);

    Ok((updated_jar, StatusCode::OK.into_response()))
}