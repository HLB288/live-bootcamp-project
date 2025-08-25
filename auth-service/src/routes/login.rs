use axum::{extract::State, Json};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use crate::{
    app_state::AppState,
    domain::{error::AuthAPIError, Email, data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore}},
    utils::auth::generate_auth_cookie,
};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

// The login route can return 2 possible success responses.
// This enum models each response!
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Validation des entrées
    if request.email.trim().is_empty() || request.password.trim().is_empty() {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    }
    
    if !request.email.contains('@') || request.email.len() < 3 {
        return (jar, Err(AuthAPIError::InvalidCredentials));
    }

    let email = request.email.as_str();

    // Valider les credentials
    let user_store = state.user_store.read().await;
    if let Err(_) = user_store.validate_user(email, &request.password).await {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    // Récupérer l'utilisateur
    let user = match user_store.get_user(email).await {
        Ok(user) => user,
        Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
    };

    drop(user_store); // Libérer le lock

    // Handle request based on user's 2FA configuration
    match user.require_2fa {
        // We are now passing `&user.email` and `&state` to `handle_2fa`
        true => handle_2fa(&Email(user.email), &state, jar).await,
        false => handle_no_2fa(&Email(user.email), jar).await,
    }
}

async fn handle_2fa(
    email: &Email,
    state: &AppState,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    // First, we must generate a new random login attempt ID and 2FA code
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    // Store the ID and code in our 2FA code store. Return `AuthAPIError::UnexpectedError` if the operation fails
    {
        let mut two_fa_store = state.two_fa_code_store.write().await;
        if let Err(_) = two_fa_store.add_code(email.clone(), login_attempt_id.clone(), two_fa_code.clone()).await {
            return (jar, Err(AuthAPIError::UnexpectedError));
        }
    } // Lock is released here

    // AJOUT: send 2FA code via the email client. Return `AuthAPIError::UnexpectedError` if the operation fails.
    let email_subject = "Your 2FA Code";
    let email_content = format!("Your 2FA verification code is: {}", two_fa_code.as_ref());
    
    if let Err(_) = state.email_client.send_email(email, email_subject, &email_content).await {
        return (jar, Err(AuthAPIError::UnexpectedError));
    }

    let response = Json(LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().to_owned(), // CORRECTION: as_ref().to_owned()
    }));

    (jar, Ok((StatusCode::PARTIAL_CONTENT, response)))
}

// New!
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> (
    CookieJar,
    Result<(StatusCode, Json<LoginResponse>), AuthAPIError>,
) {
    let auth_cookie = match generate_auth_cookie(&email.0) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    };

    let updated_jar = jar.add(auth_cookie);
    (
        updated_jar,
        Ok((StatusCode::OK, Json(LoginResponse::RegularAuth))),
    )
}