use axum::{extract::State, http::StatusCode};
use axum_extra::extract::CookieJar;
use crate::app_state::AppState;
use crate::domain::error::AuthAPIError;
use crate::utils::constants::JWT_COOKIE_NAME;
use crate::utils::auth::validate_token; // AJOUT: import pour valider le token

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), AuthAPIError> {
    let cookie = jar.get(JWT_COOKIE_NAME).ok_or(AuthAPIError::MissingToken)?;
    let token = cookie.value().to_string();

    // IMPORTANT: Valider le token AVANT de le bannir
    // Cela retournera InvalidToken si le token est déjà banni ou invalide
    validate_token(&token, state.banned_token_store.clone()).await?;

    // Seulement si le token est valide, le bannir
    let mut banned_store = state.banned_token_store.write().await;
    banned_store.add_token(token).await.map_err(|_| AuthAPIError::UnexpectedError)?;
    drop(banned_store); // Libérer le lock explicitement

    let updated_jar = jar.remove(JWT_COOKIE_NAME);
    Ok((updated_jar, StatusCode::OK))
}