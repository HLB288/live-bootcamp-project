use axum::{extract::State, http::StatusCode};
use axum_extra::extract::CookieJar;
use secrecy::Secret;
use crate::app_state::AppState;
use crate::domain::error::AuthAPIError;
use crate::utils::constants::JWT_COOKIE_NAME;
use crate::utils::auth::validate_token;

#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), AuthAPIError> {
    let cookie = jar.get(JWT_COOKIE_NAME).ok_or(AuthAPIError::MissingToken)?;
    let token = cookie.value().to_string();

    validate_token(&token, state.banned_token_store.clone()).await
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;

    let mut banned_store = state.banned_token_store.write().await;
    banned_store.add_token(Secret::new(token)).await
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;
    drop(banned_store);

    let updated_jar = jar.remove(JWT_COOKIE_NAME);
    Ok((updated_jar, StatusCode::OK))
}